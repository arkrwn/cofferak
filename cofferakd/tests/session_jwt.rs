//! Workload identity sessions (ADR 0022): a protocol version 2 session that
//! authenticates with a signed JWT instead of a service token. Real ES256
//! tokens are minted here with aws-lc-rs and verified by the daemon against
//! a JWKS stored encrypted in a real vault file, over the same connection
//! handler the Unix listener uses.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::{
    decrypt_entry, encrypt_entry, generate_root_keypair, wrap_dek_for_host, Aad,
};
use cofferak_core::format::VaultFile;
use cofferak_core::workload::{Binding, Issuer, JwtAlg, WorkloadConfig};
use cofferakd::audit::AuditLog;
use cofferakd::daemon::{token_key, Daemon};
use cofferakd::session::{Session, SessionLimits};
use serde_json::{json, Value};

const SECRET: [u8; 32] = [0x42; 32];
const DEK: [u8; 32] = [0x7A; 32];
const HOST_KEY: [u8; 32] = [0x11; 32];
const HOST_ID: &str = "host-a";
const ISS: &str = "https://issuer.test";
const AUD: &str = "cofferak";
const SUB: &str = "system:serviceaccount:ns:app1";
const ISSUER_NAME: &str = "idp";
const BINDING_NAME: &str = "app-main";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

// ---------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------

/// An ES256 signing key and the JWKS that publishes its public half.
struct Signer {
    pair: EcdsaKeyPair,
    jwks: String,
}

impl Signer {
    fn new() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        assert_eq!(point[0], 0x04);
        let half = (point.len() - 1) / 2;
        let jwks = json!({"keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": "k1",
            "alg": "ES256",
            "use": "sig",
            "x": B64URL.encode(&point[1..1 + half]),
            "y": B64URL.encode(&point[1 + half..]),
        }]})
        .to_string();
        Signer { pair, jwks }
    }

    /// A token with `claims`, signed with this key.
    fn mint(&self, claims: &Value) -> String {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": "k1"});
        let input = format!(
            "{}.{}",
            B64URL.encode(serde_json::to_vec(&header).unwrap()),
            B64URL.encode(serde_json::to_vec(claims).unwrap())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", B64URL.encode(sig.as_ref()))
    }
}

fn claims(sub: &str, exp: i64) -> Value {
    json!({"iss": ISS, "aud": AUD, "sub": sub, "iat": now(), "exp": exp})
}

/// A good token for the bound subject, valid for an hour.
fn good_token(signer: &Signer) -> String {
    signer.mint(&claims(SUB, now() + 3600))
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

struct Fixture {
    dir: PathBuf,
    vault_path: PathBuf,
    daemon: Arc<Mutex<Daemon>>,
    signer: Signer,
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

fn config_for(signer: &Signer) -> WorkloadConfig {
    let mut config = WorkloadConfig::default();
    config.issuers.insert(
        ISSUER_NAME.to_string(),
        Issuer {
            issuer: ISS.to_string(),
            audience: AUD.to_string(),
            algorithms: vec![JwtAlg::Es256],
            jwks: signer.jwks.clone(),
            leeway_secs: 30,
            max_ttl_secs: 86_400,
        },
    );
    config.bindings.insert(
        BINDING_NAME.to_string(),
        Binding {
            issuer: ISSUER_NAME.to_string(),
            subject: SUB.to_string(),
            service: "svc".to_string(),
        },
    );
    config
}

/// A persistent daemon over a real vault file with one enrolled service and
/// the workload configuration.
fn fixture(tag: &str) -> Fixture {
    fixture_with(tag, |signer| {
        bincode::serialize(&config_for(signer)).unwrap()
    })
}

/// Same, with the plaintext stored under the workload AAD chosen by `plain`.
fn fixture_with(tag: &str, plain: impl FnOnce(&Signer) -> Vec<u8>) -> Fixture {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cofferakd-jwt-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let vault_path = dir.join("vault.cofferak");
    let signer = Signer::new();
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
    vault.workload = Some(encrypt_entry(&DEK, &Aad::workload(), &plain(&signer)));
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
        signer,
    }
}

/// Edit the workload configuration in the vault file while the daemon runs,
/// the way the CLI does: load, decrypt, change, re-encrypt, seal, save.
fn edit_workload(f: &Fixture, edit: impl FnOnce(&mut WorkloadConfig)) {
    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    let entry = disk.workload.clone().unwrap();
    let bytes = decrypt_entry(&DEK, &Aad::workload(), &entry).unwrap();
    let mut config: WorkloadConfig = bincode::deserialize(&bytes).unwrap();
    edit(&mut config);
    disk.workload = Some(encrypt_entry(
        &DEK,
        &Aad::workload(),
        &bincode::serialize(&config).unwrap(),
    ));
    disk.seal(&DEK);
    disk.save(&f.vault_path).unwrap();
}

fn audit_lines(f: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(f.dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn audit_text(f: &Fixture) -> String {
    std::fs::read_to_string(f.dir.join("audit.jsonl")).unwrap()
}

/// The `result` of every `auth` line, in order.
fn auth_results(f: &Fixture) -> Vec<String> {
    audit_lines(f)
        .iter()
        .filter(|l| l["action"] == "auth")
        .map(|l| l["result"].as_str().unwrap().to_string())
        .collect()
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

    /// A version 2 connection that has said Hello, not yet authenticated.
    fn hello(f: &Fixture) -> Conn {
        let mut c = Conn::open(f);
        assert_eq!(
            c.call(json!({"Hello": {"version": 2}}))["Hello"]["version"],
            2
        );
        c
    }

    fn auth_jwt(&mut self, token: &str) -> Value {
        self.call(json!({"Auth": {"method": "jwt", "credential": token}}))
    }

    /// A session authenticated with `token` as a workload.
    fn jwt_session(f: &Fixture, token: &str) -> Conn {
        let mut c = Conn::hello(f);
        assert_eq!(c.auth_jwt(token), json!({"Authed": {"service": "svc"}}));
        c
    }

    /// A session authenticated with the service's own token.
    fn token_session(f: &Fixture) -> Conn {
        let mut c = Conn::hello(f);
        assert_eq!(
            c.call(json!({"Auth": {"method": "token", "credential": token_key(&SECRET)}})),
            json!({"Authed": {"service": "svc"}})
        );
        c
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn a_valid_token_opens_a_session_that_keeps_to_the_services_prefix() {
    let f = fixture("basic");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));

    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"v1")}})),
        json!("Ok")
    );
    assert_eq!(
        c.call(json!({"Set": {"path": "app/L", "value": b64(b"v2")}})),
        json!("Ok")
    );
    assert_eq!(
        c.call(json!({"Get": {"path": "app/K"}})),
        json!({"Value": b64(b"v1")})
    );
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K", "other/X", "app/MISSING", "app/L"]}})),
        json!({"Values": [
            {"path": "app/K", "value": b64(b"v1")},
            {"path": "other/X", "error": "denied"},
            {"path": "app/MISSING", "error": "not_found"},
            {"path": "app/L", "value": b64(b"v2")},
        ]})
    );
    assert_eq!(
        c.call(json!({"List": {"prefix": "app"}})),
        json!({"Listed": ["app/K", "app/L"]})
    );
    assert_eq!(c.call(json!({"Rm": {"path": "app/K"}})), json!("Ok"));
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("NotFound"));

    // The session is on disk like any other write.
    let disk = VaultFile::load(&f.vault_path).unwrap();
    assert!(disk.entries.contains_key("app/L"));
    assert!(!disk.entries.contains_key("app/K"));

    // Everything outside `app` is denied, for every operation.
    for path in ["other/K", "appx/K", "app/../other/K", "x"] {
        assert_eq!(c.call(json!({"Get": {"path": path}})), json!("Denied"));
        assert_eq!(
            c.call(json!({"Set": {"path": path, "value": b64(b"v")}})),
            json!("Denied")
        );
        assert_eq!(c.call(json!({"Rm": {"path": path}})), json!("Denied"));
        assert_eq!(
            c.call(json!({"GetMany": {"paths": [path]}})),
            json!({"Values": [{"path": path, "error": "denied"}]})
        );
    }
    assert_eq!(
        c.call(json!({"List": {"prefix": "other"}})),
        json!("Denied")
    );
    assert_eq!(c.call(json!({"List": {"prefix": "appx"}})), json!("Denied"));
}

#[test]
fn tokens_that_must_not_pass_are_denied_and_audited_with_the_reason() {
    let f = fixture("denied");
    let other_key = Signer::new();
    let exp = now() + 3600;

    let mut wrong_aud = claims(SUB, exp);
    wrong_aud["aud"] = json!("someone-else");
    let mut unknown_issuer = claims(SUB, exp);
    unknown_issuer["iss"] = json!("https://elsewhere.test");

    // A genuine token for an unbound subject with the payload of a bound
    // one swapped in: the signature no longer matches the payload.
    let genuine = f
        .signer
        .mint(&claims("system:serviceaccount:ns:intruder", exp));
    let parts: Vec<&str> = genuine.split('.').collect();
    let forged_payload = B64URL.encode(serde_json::to_vec(&claims(SUB, exp)).unwrap());
    let tampered = format!("{}.{forged_payload}.{}", parts[0], parts[2]);

    // `alg: none`, with the payload of a bound subject and no signature.
    let none = format!(
        "{}.{}.",
        B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#),
        B64URL.encode(serde_json::to_vec(&claims(SUB, exp)).unwrap())
    );

    let cases: Vec<(&str, String, Option<&str>)> = vec![
        (
            "wrong audience",
            f.signer.mint(&wrong_aud),
            Some("denied: wrong audience"),
        ),
        (
            "expired",
            f.signer.mint(&claims(SUB, now() - 600)),
            Some("denied: token expired"),
        ),
        (
            "other key",
            other_key.mint(&claims(SUB, exp)),
            Some("denied: bad signature"),
        ),
        (
            "unbound subject",
            f.signer
                .mint(&claims("system:serviceaccount:ns:other", exp)),
            Some("denied: subject is not bound"),
        ),
        (
            "unknown issuer",
            f.signer.mint(&unknown_issuer),
            Some("denied: unknown issuer"),
        ),
        ("tampered payload", tampered, Some("denied: bad signature")),
        ("alg none", none, None),
    ];

    for (name, token, _) in &cases {
        let mut c = Conn::hello(&f);
        assert_eq!(c.auth_jwt(token), json!("Denied"), "{name}");
        assert_eq!(
            c.call(json!({"Get": {"path": "app/K"}})),
            json!({"Err": "authenticate first"}),
            "{name}: a denied token must not open a session"
        );
    }

    let results = auth_results(&f);
    assert_eq!(results.len(), cases.len());
    for ((name, _, reason), result) in cases.iter().zip(&results) {
        match reason {
            Some(reason) => assert_eq!(result, reason, "{name}"),
            None => assert!(result.starts_with("denied: "), "{name}: {result}"),
        }
    }
    for line in audit_lines(&f).iter().filter(|l| l["action"] == "auth") {
        assert_eq!(line["service_id"], "unknown");
    }

    // Neither a token nor any part of one is written to the audit log.
    let log = audit_text(&f);
    for (name, token, _) in &cases {
        assert!(!log.contains(token.as_str()), "{name}");
        for part in token.split('.').filter(|p| p.len() > 8) {
            assert!(!log.contains(part), "{name}: a token part is in the log");
        }
    }
}

#[test]
fn three_denied_logins_close_the_connection() {
    let f = fixture("brute");
    let mut wrong_aud = claims(SUB, now() + 3600);
    wrong_aud["aud"] = json!("someone-else");
    let bad = f.signer.mint(&wrong_aud);

    let mut c = Conn::hello(&f);
    for _ in 0..3 {
        assert_eq!(c.auth_jwt(&bad), json!("Denied"));
    }
    assert!(
        c.try_call(json!({"Auth": {"method": "jwt", "credential": good_token(&f.signer)}}))
            .is_none(),
        "the connection must be closed after three denied logins"
    );
    assert_eq!(
        auth_results(&f),
        vec!["denied: wrong audience"; 3],
        "the good token on the closed connection was never evaluated"
    );
}

#[test]
fn a_successful_login_and_the_requests_after_it_are_audited_as_the_bound_service() {
    let f = fixture("audit-ok");
    let token = good_token(&f.signer);
    let mut c = Conn::jwt_session(&f, &token);
    c.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}}));
    c.call(json!({"Get": {"path": "app/K"}}));
    c.call(json!({"Get": {"path": "other/K"}}));

    let lines = audit_lines(&f);
    let auth: Vec<&Value> = lines.iter().filter(|l| l["action"] == "auth").collect();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0]["service_id"], "svc");
    assert_eq!(
        auth[0]["result"],
        format!("ok: jwt issuer {ISSUER_NAME} subject {SUB}")
    );

    let find = |action: &str, path: &str| -> &Value {
        lines
            .iter()
            .find(|l| l["action"] == action && l["path"] == path)
            .unwrap_or_else(|| panic!("no audit line for {action} {path}"))
    };
    assert_eq!(find("set", "app/K")["service_id"], "svc");
    assert_eq!(find("set", "app/K")["result"], "ok");
    assert_eq!(find("get", "app/K")["service_id"], "svc");
    assert_eq!(find("get", "app/K")["result"], "ok");
    assert_eq!(find("get", "other/K")["service_id"], "svc");
    assert_eq!(find("get", "other/K")["result"], "denied");

    let log = audit_text(&f);
    assert!(!log.contains(&token));
    assert!(!log.contains(token.rsplit('.').next().unwrap()));
}

#[test]
fn removing_the_binding_ends_access_of_a_session_that_is_already_open() {
    let f = fixture("unbind");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}})),
        json!("Ok")
    );

    edit_workload(&f, |config| {
        config.bindings.remove(BINDING_NAME);
    });

    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K"]}})),
        json!({"Values": [{"path": "app/K", "error": "denied"}]})
    );
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"w")}})),
        json!("Denied")
    );
    assert_eq!(c.call(json!({"List": {"prefix": "app"}})), json!("Denied"));
    assert_eq!(c.call(json!({"Rm": {"path": "app/K"}})), json!("Denied"));

    // And a new login with the same token is refused too.
    let mut c2 = Conn::hello(&f);
    assert_eq!(c2.auth_jwt(&good_token(&f.signer)), json!("Denied"));
    assert_eq!(
        auth_results(&f).last().unwrap(),
        "denied: subject is not bound"
    );
}

#[test]
fn removing_the_issuer_ends_access_of_a_session_that_is_already_open() {
    let f = fixture("unissue");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("NotFound"));

    edit_workload(&f, |config| {
        config.issuers.remove(ISSUER_NAME);
    });

    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K"]}})),
        json!({"Values": [{"path": "app/K", "error": "denied"}]})
    );

    // The same with the bindings removed along with the issuer.
    let f = fixture("unissue2");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    edit_workload(&f, |config| {
        config.issuers.clear();
        config.bindings.clear();
    });
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
}

#[test]
fn removing_the_service_ends_access_of_a_session_that_is_already_open() {
    let f = fixture("unservice");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    assert_eq!(
        c.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}})),
        json!("Ok")
    );

    let mut disk = VaultFile::load(&f.vault_path).unwrap();
    disk.services.remove("svc");
    disk.seal(&DEK);
    disk.save(&f.vault_path).unwrap();

    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K"]}})),
        json!({"Values": [{"path": "app/K", "error": "denied"}]})
    );

    // A new login for the still-bound subject is refused as well.
    let mut c2 = Conn::hello(&f);
    assert_eq!(c2.auth_jwt(&good_token(&f.signer)), json!("Denied"));
    assert_eq!(
        auth_results(&f).last().unwrap(),
        "denied: bound service 'svc' is not enrolled"
    );
}

#[test]
fn a_binding_removed_and_added_again_for_another_service_does_not_carry_old_sessions_over() {
    let f = fixture("rebind");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("NotFound"));

    edit_workload(&f, |config| {
        config.bindings.remove(BINDING_NAME);
    });
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));

    edit_workload(&f, |config| {
        config.bindings.insert(
            BINDING_NAME.to_string(),
            Binding {
                issuer: ISSUER_NAME.to_string(),
                subject: SUB.to_string(),
                service: "another-service".to_string(),
            },
        );
    });
    // The session was authenticated as `svc`, the binding now names another
    // service: denied, not silently moved to the new one.
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
    assert_eq!(
        c.call(json!({"GetMany": {"paths": ["app/K"]}})),
        json!({"Values": [{"path": "app/K", "error": "denied"}]})
    );
}

#[test]
fn a_binding_changed_in_place_to_another_service_does_not_carry_the_session_over() {
    let f = fixture("rebind-inplace");
    let mut c = Conn::jwt_session(&f, &good_token(&f.signer));
    edit_workload(&f, |config| {
        config.bindings.get_mut(BINDING_NAME).unwrap().service = "another-service".to_string();
    });
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("Denied"));
}

#[test]
fn a_session_ends_when_its_token_expires() {
    let f = fixture("expiry");
    let exp = now() + 2;
    let mut c = Conn::jwt_session(&f, &f.signer.mint(&claims(SUB, exp)));
    assert_eq!(c.call(json!({"Get": {"path": "app/K"}})), json!("NotFound"));

    std::thread::sleep(Duration::from_secs(4));
    // Closed by the daemon without an answer: the read ends at EOF.
    assert!(
        c.try_call(json!({"Get": {"path": "app/K"}})).is_none(),
        "a session must be closed when its identity token has expired"
    );
}

#[test]
fn a_request_after_the_token_expired_closes_the_session_without_a_reply() {
    let f = fixture("expiry-line");
    let exp = now() + 2;
    let token = f.signer.mint(&claims(SUB, exp));
    let mut session = Session::new();

    let hello = session.handle_line(br#"{"Hello":{"version":2}}"#, &f.daemon, None);
    assert!(!hello.close);
    let auth =
        serde_json::to_vec(&json!({"Auth": {"method": "jwt", "credential": token}})).unwrap();
    let reply = session.handle_line(&auth, &f.daemon, None);
    assert!(!reply.close);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
        json!({"Authed": {"service": "svc"}})
    );
    assert!(session.is_authenticated());
    assert_eq!(session.identity_expires_at(), Some(exp));

    let get = br#"{"Get":{"path":"app/K"}}"#;
    let reply = session.handle_line(get, &f.daemon, None);
    assert!(!reply.close);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.bytes).unwrap(),
        json!("NotFound")
    );

    while now() < exp {
        std::thread::sleep(Duration::from_millis(100));
    }
    for line in [
        &get[..],
        br#"{"GetMany":{"paths":["app/K"]}}"#,
        br#"{"List":{"prefix":"app"}}"#,
    ] {
        let reply = session.handle_line(line, &f.daemon, None);
        assert!(reply.close, "expired session must be closed");
        assert!(reply.bytes.is_empty(), "and nothing is sent back");
    }
}

#[test]
fn the_session_lifetime_is_cut_to_the_time_the_token_has_left() {
    let limits = SessionLimits {
        idle: Duration::from_secs(300),
        lifetime: Duration::from_secs(3600),
    };
    assert_eq!(limits.lifetime_for(None), Duration::from_secs(3600));
    let short = limits.lifetime_for(Some(now() + 10));
    assert!(short <= Duration::from_secs(10), "{short:?}");
    assert!(short >= Duration::from_secs(8), "{short:?}");
    // A token that outlives the maximum lifetime does not extend it.
    assert_eq!(
        limits.lifetime_for(Some(now() + 86_400)),
        Duration::from_secs(3600)
    );
    // An expired one leaves nothing.
    assert_eq!(limits.lifetime_for(Some(now() - 5)), Duration::ZERO);
}

#[test]
fn certificate_binding_applies_to_identity_sessions() {
    let f = fixture("cert");
    let token = good_token(&f.signer);
    let auth =
        serde_json::to_vec(&json!({"Auth": {"method": "jwt", "credential": token}})).unwrap();
    let reply = |session: &mut Session, line: &[u8], names: &[String]| {
        let r = session.handle_line(line, &f.daemon, Some(names));
        serde_json::from_slice::<Value>(&r.bytes).unwrap()
    };

    let other = vec!["other".to_string()];
    let mut session = Session::new();
    reply(&mut session, br#"{"Hello":{"version":2}}"#, &other);
    assert_eq!(reply(&mut session, &auth, &other), json!("Denied"));
    assert!(!session.is_authenticated());
    assert_eq!(
        auth_results(&f).last().unwrap(),
        "denied: certificate is not for this service"
    );

    let own = vec!["svc".to_string()];
    let mut session = Session::new();
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
    assert_eq!(
        reply(
            &mut session,
            br#"{"Set":{"path":"app/K","value":"dg=="}}"#,
            &other
        ),
        json!("Denied")
    );
    // Back with the right certificate the session still works.
    assert_eq!(
        reply(&mut session, br#"{"Get":{"path":"app/K"}}"#, &own),
        json!("NotFound")
    );
}

#[test]
fn a_damaged_workload_configuration_accepts_no_identity_but_service_tokens_still_work() {
    // Valid encryption of bytes that are not a configuration.
    let garbage = fixture_with("garbage", |_| b"garbage".to_vec());
    // Decodes, but does not validate: the binding names an unknown issuer.
    let invalid = fixture_with("invalid", |signer| {
        let mut config = config_for(signer);
        config.bindings.get_mut(BINDING_NAME).unwrap().issuer = "no-such-issuer".to_string();
        bincode::serialize(&config).unwrap()
    });
    // The same configuration with a second binding to an unknown issuer.
    let partly = fixture_with("partly", |signer| {
        let mut config = config_for(signer);
        config.bindings.insert(
            "stray".to_string(),
            Binding {
                issuer: "no-such-issuer".to_string(),
                subject: "x".to_string(),
                service: "svc".to_string(),
            },
        );
        bincode::serialize(&config).unwrap()
    });

    for f in [&garbage, &invalid, &partly] {
        let mut c = Conn::hello(f);
        assert_eq!(c.auth_jwt(&good_token(&f.signer)), json!("Denied"));
        assert_eq!(
            auth_results(f).last().unwrap(),
            "denied: unknown issuer",
            "no issuer is configured, so no token is accepted"
        );

        let mut s = Conn::token_session(f);
        assert_eq!(
            s.call(json!({"Set": {"path": "app/K", "value": b64(b"v")}})),
            json!("Ok")
        );
        assert_eq!(
            s.call(json!({"Get": {"path": "app/K"}})),
            json!({"Value": b64(b"v")})
        );
    }
}

#[test]
fn identity_and_service_token_sessions_see_the_same_data() {
    let f = fixture("shared");
    let mut by_token = Conn::token_session(&f);
    let mut by_jwt = Conn::jwt_session(&f, &good_token(&f.signer));

    assert_eq!(
        by_token.call(json!({"Set": {"path": "app/FROM_TOKEN", "value": b64(b"t")}})),
        json!("Ok")
    );
    assert_eq!(
        by_jwt.call(json!({"Get": {"path": "app/FROM_TOKEN"}})),
        json!({"Value": b64(b"t")})
    );
    assert_eq!(
        by_jwt.call(json!({"Set": {"path": "app/FROM_JWT", "value": b64(b"j")}})),
        json!("Ok")
    );
    assert_eq!(
        by_token.call(json!({"Get": {"path": "app/FROM_JWT"}})),
        json!({"Value": b64(b"j")})
    );
    assert_eq!(
        by_token.call(json!({"List": {"prefix": "app"}})),
        by_jwt.call(json!({"List": {"prefix": "app"}}))
    );

    // Version 1 still works on the same daemon and sees both.
    let mut v1 = Conn::open(&f);
    let token = token_key(&SECRET);
    assert_eq!(
        v1.call(json!({"Get": {"token": token, "path": "app/FROM_JWT"}})),
        json!({"Value": [106]})
    );
    assert_eq!(
        v1.call(json!({"Set": {"token": token, "path": "app/FROM_V1", "value": [49]}})),
        json!("Ok")
    );
    assert_eq!(
        by_jwt.call(json!({"Get": {"path": "app/FROM_V1"}})),
        json!({"Value": b64(b"1")})
    );
}

#[test]
fn unsupported_methods_and_jwt_before_hello_are_refused() {
    let f = fixture("methods");
    let mut c = Conn::hello(&f);
    let reply = c.call(json!({"Auth": {"method": "magic", "credential": "x"}}));
    assert!(reply["Err"]
        .as_str()
        .unwrap()
        .contains("unsupported authentication method"));
    // The refusal does not count as a login and the session stays usable.
    assert_eq!(
        c.auth_jwt(&good_token(&f.signer)),
        json!({"Authed": {"service": "svc"}})
    );

    // `jwt` in version 1 framing, before Hello.
    let mut v1 = Conn::open(&f);
    assert_eq!(
        v1.call(json!({"Auth": {"method": "jwt", "credential": good_token(&f.signer)}})),
        json!({"Err": "malformed request"})
    );
    // And nothing was authenticated by it.
    assert_eq!(
        auth_results(&f),
        vec![format!("ok: jwt issuer {ISSUER_NAME} subject {SUB}")]
    );
}
