//! Protocol version 2 sessions (ADR 0019) over a real socket pair, served
//! by the same connection handler the Unix listener uses: handshake,
//! authenticate once, many requests on one connection, batch reads, base64
//! values, and the rules that must not weaken compared with version 1.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::{encrypt_entry, generate_root_keypair, wrap_dek_for_host, Aad};
use cofferak_core::format::VaultFile;
use cofferakd::audit::AuditLog;
use cofferakd::daemon::{token_key, Daemon};
use serde_json::{json, Value};

const SECRET: [u8; 32] = [0x42; 32];
const DEK: [u8; 32] = [0x7A; 32];
const HOST_KEY: [u8; 32] = [0x11; 32];
const HOST_ID: &str = "host-a";

struct Fixture {
    dir: PathBuf,
    vault_path: PathBuf,
    daemon: Arc<Mutex<Daemon>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn service_token() -> AccessToken {
    AccessToken {
        service_id: "svc".to_string(),
        prefixes: vec!["app".to_string()],
        permission: Permission::ReadWrite,
        secret: SECRET,
    }
}

/// A persistent daemon over a real vault file with one enrolled service.
fn fixture(tag: &str) -> Fixture {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cofferakd-session-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let vault_path = dir.join("vault.cofferak");
    let (root_pubkey, _) = generate_root_keypair().unwrap();
    let mut vault = VaultFile::new(root_pubkey);
    vault.hosts.insert(
        HOST_ID.to_string(),
        wrap_dek_for_host(&DEK, HOST_ID, &HOST_KEY),
    );
    vault.services.insert(
        "svc".to_string(),
        encrypt_entry(
            &DEK,
            &Aad::service_token("svc"),
            &bincode::serialize(&service_token()).unwrap(),
        ),
    );
    vault.save(&vault_path).unwrap();

    let host_wrap = vault.hosts[HOST_ID].clone();
    let mut tokens = BTreeMap::new();
    tokens.insert(token_key(&SECRET), service_token());
    let audit = AuditLog::open(&dir.join("audit.jsonl")).unwrap();
    let daemon = Daemon::new(DEK, vault, tokens, audit).with_persistence(
        vault_path.clone(),
        HOST_ID.to_string(),
        host_wrap,
        0,
    );
    Fixture {
        dir,
        vault_path,
        daemon: Arc::new(Mutex::new(daemon)),
    }
}

/// One client connection to the daemon's real connection handler.
struct Conn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Conn {
    fn open(f: &Fixture) -> Conn {
        let (server, client) = UnixStream::pair().unwrap();
        let daemon = Arc::clone(&f.daemon);
        std::thread::spawn(move || cofferakd::server::handle_connection(server, daemon));
        Conn {
            reader: BufReader::new(client.try_clone().unwrap()),
            writer: client,
        }
    }

    /// Send one request line, `None` if the daemon closed the connection.
    fn try_call(&mut self, request: Value) -> Option<Value> {
        let mut line = serde_json::to_vec(&request).unwrap();
        line.push(b'\n');
        self.writer.write_all(&line).ok()?;
        let mut response = String::new();
        match self.reader.read_line(&mut response) {
            Ok(n) if n > 0 => Some(serde_json::from_str(&response).unwrap()),
            _ => None,
        }
    }

    fn call(&mut self, request: Value) -> Value {
        self.try_call(request)
            .expect("daemon closed the connection")
    }

    /// Open a version 2 session authenticated as `svc`.
    fn session(f: &Fixture) -> Conn {
        let mut c = Conn::open(f);
        assert_eq!(
            c.call(json!({"Hello": {"version": 2}}))["Hello"]["version"],
            2
        );
        assert_eq!(
            c.call(json!({"Auth": {"method": "token", "credential": token_key(&SECRET)}})),
            json!({"Authed": {"service": "svc"}})
        );
        c
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn hello_reports_the_version_and_features() {
    let f = fixture("hello");
    let mut c = Conn::open(&f);
    let hello = c.call(json!({"Hello": {"version": 2}}));
    assert_eq!(hello["Hello"]["version"], 2);
    let features: Vec<&str> = hello["Hello"]["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(features.contains(&"session"));
    assert!(features.contains(&"batch"));
    assert!(features.contains(&"base64"));
}

#[test]
fn a_newer_client_is_answered_with_the_version_the_daemon_speaks() {
    let f = fixture("newer");
    let mut c = Conn::open(&f);
    assert_eq!(
        c.call(json!({"Hello": {"version": 9}}))["Hello"]["version"],
        2
    );
}

#[test]
fn hello_for_an_unknown_old_version_is_refused() {
    let f = fixture("old");
    let mut c = Conn::open(&f);
    assert_eq!(
        c.call(json!({"Hello": {"version": 1}})),
        json!({"Err": "unsupported protocol version"})
    );
}

#[test]
fn one_session_serves_many_requests_with_base64_values() {
    let f = fixture("many");
    let mut c = Conn::session(&f);
    // Every byte value, so an encoding slip can't hide.
    let binary: Vec<u8> = (0..=255).collect();
    assert_eq!(
        c.call(json!({"Set": {"path": "app/BIN", "value": b64(&binary)}})),
        json!("Ok")
    );
    for i in 0..50 {
        let path = format!("app/K{i}");
        let value = format!("value-{i}");
        assert_eq!(
            c.call(json!({"Set": {"path": path, "value": b64(value.as_bytes())}})),
            json!("Ok")
        );
        assert_eq!(
            c.call(json!({"Get": {"path": path}})),
            json!({"Value": b64(value.as_bytes())})
        );
    }
    assert_eq!(
        c.call(json!({"Get": {"path": "app/BIN"}})),
        json!({"Value": b64(&binary)})
    );
    assert_eq!(c.call(json!("Ping")), json!("Ok"));
    let listed = c.call(json!({"List": {"prefix": "app"}}));
    assert_eq!(listed["Listed"].as_array().unwrap().len(), 51);
    assert_eq!(c.call(json!({"Rm": {"path": "app/BIN"}})), json!("Ok"));
    assert_eq!(
        c.call(json!({"Get": {"path": "app/BIN"}})),
        json!("NotFound")
    );
}

#[test]
fn session_writes_are_on_disk() {
    let f = fixture("durable");
    let mut c = Conn::session(&f);
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}})),
        json!("Ok")
    );
    let disk = VaultFile::load(&f.vault_path).unwrap();
    assert!(disk.entries.contains_key("app/K"));
}

#[test]
fn get_many_reports_each_path_on_its_own() {
    let f = fixture("batch");
    let mut c = Conn::session(&f);
    c.call(json!({"Set": {"path": "app/A", "value": b64(b"a")}}));
    c.call(json!({"Set": {"path": "app/B", "value": b64(b"b")}}));
    let reply = c.call(json!({"GetMany": {"paths": ["app/A", "other/X", "app/MISSING", "app/B"]}}));
    assert_eq!(
        reply,
        json!({"Values": [
            {"path": "app/A", "value": b64(b"a")},
            {"path": "other/X", "error": "denied"},
            {"path": "app/MISSING", "error": "not_found"},
            {"path": "app/B", "value": b64(b"b")},
        ]})
    );
}

#[test]
fn get_many_refuses_too_many_paths_and_too_many_bytes() {
    let f = fixture("batch-limits");
    let mut c = Conn::session(&f);
    let paths: Vec<String> = (0..257).map(|i| format!("app/K{i}")).collect();
    let reply = c.call(json!({"GetMany": {"paths": paths}}));
    assert!(reply["Err"].as_str().unwrap().contains("too many paths"));

    // Five values of 1 MiB are over the 4 MiB a batch may carry.
    let big = b64(&vec![7u8; 1024 * 1024]);
    let paths: Vec<String> = (0..5).map(|i| format!("app/BIG{i}")).collect();
    for p in &paths {
        assert_eq!(
            c.call(json!({"Set": {"path": p, "value": big}})),
            json!("Ok")
        );
    }
    let reply = c.call(json!({"GetMany": {"paths": paths}}));
    assert!(reply["Err"].as_str().unwrap().contains("exceed"));
    // The session is still usable afterwards.
    assert_eq!(c.call(json!("Ping")), json!("Ok"));
}

#[test]
fn requests_before_authentication_are_refused() {
    let f = fixture("unauth");
    let mut c = Conn::open(&f);
    c.call(json!({"Hello": {"version": 2}}));
    for request in [
        json!({"Get": {"path": "app/K"}}),
        json!({"GetMany": {"paths": ["app/K"]}}),
        json!({"Set": {"path": "app/K", "value": b64(b"v")}}),
        json!({"Rm": {"path": "app/K"}}),
        json!({"List": {"prefix": "app"}}),
    ] {
        assert_eq!(c.call(request), json!({"Err": "authenticate first"}));
    }
}

#[test]
fn a_wrong_credential_is_denied_and_the_connection_closed_after_three() {
    let f = fixture("bruteforce");
    let mut c = Conn::open(&f);
    c.call(json!({"Hello": {"version": 2}}));
    let wrong = json!({"Auth": {"method": "token", "credential": "f".repeat(64)}});
    assert_eq!(c.call(wrong.clone()), json!("Denied"));
    assert_eq!(c.call(wrong.clone()), json!("Denied"));
    assert_eq!(c.call(wrong.clone()), json!("Denied"));
    assert!(
        c.try_call(wrong).is_none(),
        "the connection must be closed after three wrong credentials"
    );
}

#[test]
fn an_unknown_authentication_method_is_refused() {
    let f = fixture("method");
    let mut c = Conn::open(&f);
    c.call(json!({"Hello": {"version": 2}}));
    let reply = c.call(json!({"Auth": {"method": "magic", "credential": "x"}}));
    assert!(reply["Err"]
        .as_str()
        .unwrap()
        .contains("unsupported authentication method"));
}

#[test]
fn the_session_keeps_the_access_rules_of_its_service() {
    let f = fixture("acl");
    let mut c = Conn::session(&f);
    assert_eq!(c.call(json!({"Get": {"path": "other/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"Set": {"path": "other/K", "value": b64(b"v")}})),
        json!("Denied")
    );
    assert_eq!(
        c.call(json!({"Get": {"path": "app/../other/K"}})),
        json!("Denied")
    );
}

#[test]
fn a_value_that_is_not_base64_is_refused_and_nothing_is_written() {
    let f = fixture("badb64");
    let mut c = Conn::session(&f);
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": "not base64!"}})),
        json!({"Err": "value is not valid base64"})
    );
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("NotFound"));
}

#[test]
fn an_open_session_loses_access_when_its_service_is_removed() {
    let f = fixture("revoke");
    let mut c = Conn::session(&f);
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}})),
        json!("Ok")
    );

    // Remove the service the way the CLI does, while the session is open.
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.services.remove("svc");
    disk.seal(&DEK);
    disk.save(&f.vault_path).unwrap();

    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K"]}})),
        json!({"Values": [{"path": "app/K", "error": "denied"}]})
    );
}

#[test]
fn version_1_requests_still_work_on_the_same_listener() {
    let f = fixture("v1");
    let mut c = Conn::open(&f);
    let token = token_key(&SECRET);
    assert_eq!(
        c.call(json!({"Set": {"token": token, "path": "app/K", "value": [118, 49]}})),
        json!("Ok")
    );
    assert_eq!(
        c.call(json!({"Get": {"token": token, "path": "app/K"}})),
        json!({"Value": [118, 49]})
    );
    // A version 2 session reads what version 1 wrote.
    let mut s = Conn::session(&f);
    assert_eq!(
        s.call(json!({"Get": {"path": "app/K"}})),
        json!({"Value": b64(b"v1")})
    );
}

#[test]
fn version_1_requests_are_not_accepted_inside_a_session() {
    let f = fixture("mixed");
    let mut c = Conn::session(&f);
    let reply = c.call(json!({"Get": {"token": token_key(&SECRET), "path": "app/K"}}));
    // Unknown fields are ignored, so this is a plain session Get.
    assert_eq!(reply, json!("NotFound"));
    assert_eq!(
        c.call(json!({"Hello": {"version": 2}})),
        json!({"Err": "session is already open"})
    );
}

#[test]
fn authentication_is_written_to_the_audit_log_without_the_credential() {
    let f = fixture("audit");
    let mut c = Conn::open(&f);
    c.call(json!({"Hello": {"version": 2}}));
    c.call(json!({"Auth": {"method": "token", "credential": "f".repeat(64)}}));
    c.call(json!({"Auth": {"method": "token", "credential": token_key(&SECRET)}}));
    let log = std::fs::read_to_string(f.dir.join("audit.jsonl")).unwrap();
    assert!(log.contains("\"auth\""));
    assert!(log.contains("unknown"));
    assert!(log.contains("svc"));
    assert!(!log.contains(&token_key(&SECRET)));
    assert!(!log.contains(&"f".repeat(64)));
}

#[test]
fn with_certificate_binding_a_session_needs_its_own_services_certificate() {
    // The TLS listener passes the client certificate's names (ADR 0017).
    let f = fixture("certbind");
    let auth =
        serde_json::to_vec(&json!({"Auth": {"method": "token", "credential": token_key(&SECRET)}}))
            .unwrap();
    let reply = |session: &mut cofferakd::session::Session, line: &[u8], names: &[String]| {
        let r = session.handle_line(line, &f.daemon, Some(names));
        serde_json::from_slice::<Value>(&r.bytes).unwrap()
    };

    let other = vec!["some-other-service".to_string()];
    let mut session = cofferakd::session::Session::new();
    reply(&mut session, br#"{"Hello":{"version":2}}"#, &other);
    assert_eq!(reply(&mut session, &auth, &other), json!("Denied"));
    assert!(!session.is_authenticated());

    let own = vec!["svc".to_string()];
    let mut session = cofferakd::session::Session::new();
    reply(&mut session, br#"{"Hello":{"version":2}}"#, &own);
    assert_eq!(
        reply(&mut session, &auth, &own),
        json!({"Authed": {"service": "svc"}})
    );
    assert_eq!(
        reply(&mut session, br#"{"Get":{"path":"app/K"}}"#, &own),
        json!("NotFound")
    );
    // The certificate is checked on every request, not only at Auth.
    assert_eq!(
        reply(&mut session, br#"{"Get":{"path":"app/K"}}"#, &other),
        json!("Denied")
    );
}
