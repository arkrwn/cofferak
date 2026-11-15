#![cfg(feature = "gcp-kms")]
//! Integration tests for the Cloud KMS `HostSeal` backend, run against a
//! fake metadata server + Cloud KMS on a loopback port. No network and no
//! real Google service is involved.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cofferak_core::seal::{GcpKmsConfig, GcpKmsSeal, HostSeal, SealedBlob};

const KEY_NAME: &str = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1";
const OTHER_KEY_NAME: &str = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k2";
const MARKER: &str = "cofferak-gcp-kms-seal-v1";

/// What the fake server saw and how it should behave.
#[derive(Default)]
struct State {
    token_requests: usize,
    encrypt_calls: usize,
    decrypt_calls: usize,
    last_authorization: Option<String>,
    metadata_down: bool,
    decrypt_returns_31_bytes: bool,
}

struct FakeGoogle {
    port: u16,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

const PERMISSION_DENIED: &str =
    r#"{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}"#;
const DECRYPT_FAILED: &str = r#"{"error":{"code":400,"message":"Decryption failed: the ciphertext is invalid.","status":"INVALID_ARGUMENT"}}"#;

fn decode_field(json: &serde_json::Value, field: &str) -> Option<Vec<u8>> {
    B64.decode(json.get(field)?.as_str()?).ok()
}

fn handle(stream: &mut TcpStream, key_name: &str, state: &Mutex<State>) {
    let Some(request) = read_request(stream) else {
        return;
    };
    let token_path = "/computeMetadata/v1/instance/service-accounts/default/token";
    if request.method == "GET" && request.path == token_path {
        if request.header("Metadata-Flavor") != Some("Google") {
            respond(
                stream,
                403,
                "Forbidden",
                "Missing Metadata-Flavor:Google header.",
            );
            return;
        }
        let down = {
            let mut s = state.lock().unwrap();
            s.token_requests += 1;
            s.metadata_down
        };
        if down {
            respond(stream, 500, "Internal Server Error", "metadata is down");
        } else {
            respond(
                stream,
                200,
                "OK",
                r#"{"access_token":"fake-token","expires_in":3600,"token_type":"Bearer"}"#,
            );
        }
        return;
    }

    let prefix = "/v1/";
    let Some(rest) = request.path.strip_prefix(prefix) else {
        respond(stream, 404, "Not Found", "{}");
        return;
    };
    let Some((name, method)) = rest.rsplit_once(':') else {
        respond(stream, 404, "Not Found", "{}");
        return;
    };
    if request.method != "POST" || (method != "encrypt" && method != "decrypt") {
        respond(stream, 404, "Not Found", "{}");
        return;
    }
    let authorization = request.header("Authorization").map(str::to_string);
    let decrypt_31 = {
        let mut s = state.lock().unwrap();
        if method == "encrypt" {
            s.encrypt_calls += 1;
        } else {
            s.decrypt_calls += 1;
        }
        s.last_authorization = authorization.clone();
        s.decrypt_returns_31_bytes
    };
    if authorization.as_deref() != Some("Bearer fake-token") {
        respond(
            stream,
            401,
            "Unauthorized",
            r#"{"error":{"code":401,"message":"Request had invalid authentication credentials.","status":"UNAUTHENTICATED"}}"#,
        );
        return;
    }
    if name != key_name {
        respond(stream, 403, "Forbidden", PERMISSION_DENIED);
        return;
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        respond(stream, 400, "Bad Request", DECRYPT_FAILED);
        return;
    };
    let aad = decode_field(&json, "additionalAuthenticatedData").unwrap_or_default();
    if method == "encrypt" {
        let plaintext = decode_field(&json, "plaintext").unwrap_or_default();
        let mut raw = b"FAKE".to_vec();
        raw.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        raw.extend_from_slice(&aad);
        raw.extend(plaintext.iter().map(|b| b ^ 0xA5));
        let body = serde_json::json!({"name": key_name, "ciphertext": B64.encode(raw)});
        respond(stream, 200, "OK", &body.to_string());
        return;
    }

    // decrypt
    let raw = decode_field(&json, "ciphertext").unwrap_or_default();
    let parsed = raw.strip_prefix(b"FAKE").and_then(|r| {
        let len = u32::from_be_bytes(r.get(..4)?.try_into().ok()?) as usize;
        let embedded_aad = r.get(4..4 + len)?;
        let data = r.get(4 + len..)?;
        (embedded_aad == aad.as_slice()).then(|| data.iter().map(|b| b ^ 0xA5).collect::<Vec<u8>>())
    });
    match parsed {
        Some(mut plaintext) => {
            if decrypt_31 {
                plaintext.truncate(31);
            }
            let body = serde_json::json!({"plaintext": B64.encode(plaintext)});
            respond(stream, 200, "OK", &body.to_string());
        }
        None => respond(stream, 400, "Bad Request", DECRYPT_FAILED),
    }
}

impl FakeGoogle {
    /// A fake that accepts requests for `key_name` only.
    fn start(key_name: &str) -> FakeGoogle {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (state, stop, key_name) = (state.clone(), stop.clone(), key_name.to_string());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(mut stream) = stream {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                        handle(&mut stream, &key_name, &state);
                    }
                }
            })
        };
        FakeGoogle {
            port,
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn seal_for(&self, key_name: &str, host_id: &str) -> GcpKmsSeal {
        GcpKmsSeal {
            config: GcpKmsConfig {
                key_name: key_name.into(),
                endpoint: format!("http://127.0.0.1:{}", self.port),
                metadata_host: format!("127.0.0.1:{}", self.port),
                allow_gcloud: false,
            },
            host_id: host_id.into(),
        }
    }

    fn seal(&self, host_id: &str) -> GcpKmsSeal {
        self.seal_for(KEY_NAME, host_id)
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }
}

impl Drop for FakeGoogle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it notices the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    key
}

fn error_text<T: std::fmt::Debug>(result: Result<T, cofferak_core::seal::SealError>) -> String {
    let err = result.expect_err("expected an error");
    err.to_string()
}

#[test]
fn sealing_then_unsealing_returns_the_same_key_and_the_blob_hides_it() {
    let fake = FakeGoogle::start(KEY_NAME);
    let seal = fake.seal("pod-a");
    let key = test_key();

    let blob = seal.seal(&key).expect("seal should succeed");
    assert_eq!(seal.unseal(&blob).expect("unseal should succeed"), key);

    assert!(
        !blob.0.windows(key.len()).any(|w| w == key),
        "the blob must not contain the raw key bytes"
    );
    let text = String::from_utf8(blob.0.clone()).expect("blob is text");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(MARKER));
    assert_eq!(lines.next(), Some(KEY_NAME));
    fake.with_state(|s| {
        assert_eq!(s.last_authorization.as_deref(), Some("Bearer fake-token"));
        assert_eq!(s.encrypt_calls, 1);
        assert_eq!(s.decrypt_calls, 1);
    });
}

#[test]
fn a_blob_sealed_for_one_host_does_not_unseal_as_another_host() {
    let fake = FakeGoogle::start(KEY_NAME);
    let blob = fake.seal("pod-a").seal(&test_key()).unwrap();

    let result = fake.seal("pod-b").unseal(&blob);
    let message = error_text(result);
    assert!(message.contains("400"), "unexpected message: {message}");
}

#[test]
fn unsealing_with_a_different_key_name_fails_naming_both_keys_without_calling_kms() {
    let fake = FakeGoogle::start(KEY_NAME);
    let blob = fake.seal("pod-a").seal(&test_key()).unwrap();
    let decrypts_before = fake.with_state(|s| s.decrypt_calls);

    let message = error_text(fake.seal_for(OTHER_KEY_NAME, "pod-a").unseal(&blob));

    assert!(message.contains(KEY_NAME), "unexpected message: {message}");
    assert!(
        message.contains(OTHER_KEY_NAME),
        "unexpected message: {message}"
    );
    assert_eq!(fake.with_state(|s| s.decrypt_calls), decrypts_before);
}

#[test]
fn a_tampered_ciphertext_does_not_unseal() {
    let fake = FakeGoogle::start(KEY_NAME);
    let seal = fake.seal("pod-a");
    let blob = seal.seal(&test_key()).unwrap();

    let text = String::from_utf8(blob.0).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut ciphertext = lines[2].clone().into_bytes();
    // Flip a character inside the base64 text (after the FAKE prefix and
    // length header, within the aad), keeping it valid base64.
    ciphertext[10] = if ciphertext[10] == b'A' { b'B' } else { b'A' };
    lines[2] = String::from_utf8(ciphertext).unwrap();
    let tampered = SealedBlob(format!("{}\n", lines.join("\n")).into_bytes());

    assert!(seal.unseal(&tampered).is_err());
}

#[test]
fn blobs_from_other_backends_or_with_a_wrong_shape_do_not_unseal() {
    let fake = FakeGoogle::start(KEY_NAME);
    let seal = fake.seal("pod-a");
    let blob = seal.seal(&test_key()).unwrap();

    for foreign in [
        b"cofferak-file-seal-v1".to_vec(),
        Vec::new(),
        vec![0xff, 0xfe, 0xfd, 0x00, 0x80],
    ] {
        assert!(seal.unseal(&SealedBlob(foreign)).is_err());
    }

    let mut with_extra_line = blob.0.clone();
    with_extra_line.extend_from_slice(b"extra\n");
    assert!(seal.unseal(&SealedBlob(with_extra_line)).is_err());
}

#[test]
fn a_kms_permission_error_is_reported_with_its_status_and_reason() {
    // The server only knows another key, so KMS answers 403 for ours.
    let fake = FakeGoogle::start(OTHER_KEY_NAME);

    let message = error_text(fake.seal("pod-a").seal(&test_key()));

    assert!(message.contains("403"), "unexpected message: {message}");
    assert!(
        message.contains("Permission denied"),
        "unexpected message: {message}"
    );
}

#[test]
fn sealing_without_a_google_identity_fails_before_reaching_kms() {
    let fake = FakeGoogle::start(KEY_NAME);
    fake.with_state(|s| s.metadata_down = true);

    let message = error_text(fake.seal("pod-a").seal(&test_key()));

    assert!(
        message.contains("metadata server"),
        "unexpected message: {message}"
    );
    fake.with_state(|s| {
        assert_eq!(s.token_requests, 1);
        assert_eq!(s.encrypt_calls, 0);
    });
}

#[test]
fn a_decrypt_answer_of_31_bytes_is_rejected_as_not_a_32_byte_key() {
    let fake = FakeGoogle::start(KEY_NAME);
    let seal = fake.seal("pod-a");
    let blob = seal.seal(&test_key()).unwrap();
    fake.with_state(|s| s.decrypt_returns_31_bytes = true);

    let message = error_text(seal.unseal(&blob));

    assert!(
        message.contains("expected 32"),
        "unexpected message: {message}"
    );
}

fn config(key_name: &str, endpoint: &str) -> GcpKmsConfig {
    GcpKmsConfig {
        key_name: key_name.into(),
        endpoint: endpoint.into(),
        metadata_host: "metadata.google.internal".into(),
        allow_gcloud: false,
    }
}

#[test]
fn config_validation_rejects_anything_but_a_crypto_key_name_and_a_safe_endpoint() {
    let good_endpoint = "https://cloudkms.googleapis.com";
    for bad_key in [
        "k1",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k?x=1",
        "projects/../locations/l/keyRings/r/cryptoKeys/k",
        "",
    ] {
        assert!(
            config(bad_key, good_endpoint).validate().is_err(),
            "key name {bad_key:?} should be rejected"
        );
    }

    for bad_endpoint in [
        "http://kms.example.com",
        "ftp://x",
        "http://127.0.0.1.evil.com:80",
    ] {
        assert!(
            config(KEY_NAME, bad_endpoint).validate().is_err(),
            "endpoint {bad_endpoint:?} should be rejected"
        );
    }

    for good_endpoint in [
        "https://cloudkms.googleapis.com",
        "https://private.example.com/",
        "http://127.0.0.1:9999",
        "http://localhost:9999",
    ] {
        assert!(
            config(KEY_NAME, good_endpoint).validate().is_ok(),
            "endpoint {good_endpoint:?} should be accepted"
        );
    }
}
