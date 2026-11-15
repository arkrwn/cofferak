//! Workload identity smoke test (ADR 0022): sessions authenticated with a
//! JWT, run against a real `cofferakd` by `scripts/workload-check.sh rust`
//! (see the contract in that script's header).
//!
//! Usage: `COFFERAK_SOCKET=.. COFFERAK_JWT_DIR=.. COFFERAK_JWT_EXPIRES_IN=..
//! COFFERAK_REVOKE_CMD=.. smoke_jwt <allowed-prefix> <denied-path>`

use cofferak_sdk::{Client, SdkError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn main() {
    let socket = env("COFFERAK_SOCKET");
    let dir = PathBuf::from(env("COFFERAK_JWT_DIR"));
    let expires_in: u64 = env("COFFERAK_JWT_EXPIRES_IN")
        .parse()
        .expect("COFFERAK_JWT_EXPIRES_IN must be a number of seconds");
    let revoke_cmd = env("COFFERAK_REVOKE_CMD");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let prefix = args.first().expect("allowed path prefix argument").clone();
    let denied_path = args.get(1).expect("denied path argument").clone();

    let client = Client::connect(&socket);

    // a. a good token acts as the bound service
    let mut s = client
        .session_jwt_file(dir.join("good.jwt"))
        .expect("opening a session with good.jwt");
    assert_eq!(s.service(), "app1");
    let binary: Vec<u8> = (0..=255).collect();
    let a = format!("{prefix}/jwt");
    let b = format!("{prefix}/jwt-other");
    s.set(&a, &binary).expect("set binary");
    s.set(&b, b"second").expect("set");
    assert_eq!(s.get(&a).expect("get"), binary, "binary must round-trip");
    let many = s
        .get_many(&[a.clone(), b.clone(), format!("{prefix}/jwt-missing")])
        .expect("get_many");
    assert_eq!(many.len(), 2, "a missing path is left out");
    assert_eq!(many[&a], binary);
    assert_eq!(many[&b], b"second");
    let all = s.get_all(&prefix).expect("get_all");
    assert_eq!(all.get(&a), Some(&binary));
    assert!(s.list(&prefix).expect("list").contains(&a));
    assert!(matches!(s.get(&denied_path), Err(SdkError::Denied)));
    assert!(matches!(
        s.get_many(std::slice::from_ref(&denied_path)),
        Err(SdkError::Denied)
    ));
    s.ping().expect("ping");
    s.close();

    // b. every bad token is denied at open
    for name in ["wrong-aud", "unbound", "expired", "wrong-key"] {
        match client.session_jwt_file(dir.join(format!("{name}.jwt"))) {
            Err(SdkError::Denied) => {}
            Err(e) => panic!("{name}.jwt: expected Denied, got error {e}"),
            Ok(_) => panic!("{name}.jwt: expected Denied, got a session"),
        }
    }

    // c. reconnect with a fresh token file after the first token expired
    let current = dir.join("current.jwt");
    let mut s = client
        .session_jwt_file(&current)
        .expect("opening a session with current.jwt");
    let opened = Instant::now();
    s.get(&a).expect("read with the first token");
    replace_atomically(&current, &dir.join("long.jwt"));
    let wake = opened + Duration::from_secs(expires_in) + Duration::from_millis(1500);
    std::thread::sleep(wake.saturating_duration_since(Instant::now()));
    assert_eq!(
        s.get(&a).expect("read after the token expired (reconnect)"),
        binary
    );

    // e. a provider closure works too, and its errors come back as they are
    let good = dir.join("good.jwt");
    let mut p = client
        .session_jwt(move || Ok(std::fs::read_to_string(&good)?.trim().to_string()))
        .expect("opening a session with a provider");
    assert_eq!(p.service(), "app1");
    assert_eq!(p.get(&a).expect("get via provider"), binary);
    // a provider error comes back as it is, never as Denied
    let failing = client.session_jwt(|| Err(SdkError::Protocol("no token".to_string())));
    assert!(matches!(failing, Err(SdkError::Protocol(m)) if m == "no token"));

    // d. revocation: removing the binding denies the next request
    let mut s = client
        .session_jwt_file(dir.join("good.jwt"))
        .expect("opening a session with good.jwt");
    s.get(&a).expect("read before revocation");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&revoke_cmd)
        .status()
        .expect("running COFFERAK_REVOKE_CMD");
    assert!(status.success(), "COFFERAK_REVOKE_CMD failed: {status}");
    assert!(
        matches!(s.get(&a), Err(SdkError::Denied)),
        "a read after the binding was removed must be denied"
    );

    println!("rust SDK JWT smoke test passed");
}

/// Replace `target` with the content of `source` in one step, the way the
/// kubelet rotates a projected token.
fn replace_atomically(target: &Path, source: &Path) {
    let content = std::fs::read(source).expect("reading the new token");
    let tmp = target.with_extension("jwt.tmp");
    std::fs::write(&tmp, content).expect("writing the temporary token file");
    std::fs::rename(&tmp, target).expect("replacing the token file");
}
