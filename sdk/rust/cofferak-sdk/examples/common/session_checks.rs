//! Session (protocol version 2) checks shared by the `smoke` and
//! `smoke_tls` examples, so both transports prove the same behaviour
//! against a real `cofferakd`.

use cofferak_sdk::{Client, SdkError};

pub fn session_checks(client: &Client, token: &str, allowed_path: &str, denied_path: &str) {
    let base = format!("{allowed_path}-session");
    let a = format!("{base}/A");
    let b = format!("{base}/B");
    let binary: Vec<u8> = (0..=255).collect();

    let mut s = client.session(token).expect("opening a session");
    assert!(
        !s.service().is_empty(),
        "the session must report its service id"
    );
    s.ping().expect("ping");
    s.set(&a, b"alpha").expect("set");
    s.set(&b, &binary).expect("set binary");
    assert_eq!(s.get(&b).expect("get"), binary, "binary must round-trip");

    let many = s
        .get_many(&[a.clone(), b.clone(), format!("{base}/MISSING")])
        .expect("get_many");
    assert_eq!(many.len(), 2, "a missing path is left out");
    assert_eq!(many[&a], b"alpha");
    assert_eq!(many[&b], binary);
    assert_eq!(s.get_all(&base).expect("get_all"), many);
    let mut listed = s.list(&base).expect("list");
    listed.sort();
    assert_eq!(listed, vec![a.clone(), b.clone()]);

    assert!(matches!(s.get(denied_path), Err(SdkError::Denied)));
    assert!(matches!(
        s.get_many(&[denied_path.to_string()]),
        Err(SdkError::Denied)
    ));

    // With $COFFERAK_SMOKE_IDLE_SECS the daemon closes idle sessions after
    // that many seconds: wait it out, the next call must reconnect.
    if let Ok(idle) = std::env::var("COFFERAK_SMOKE_IDLE_SECS") {
        let secs: f64 = idle.parse().expect("COFFERAK_SMOKE_IDLE_SECS is a number");
        std::thread::sleep(std::time::Duration::from_secs_f64(secs + 1.0));
    }
    assert_eq!(s.get(&a).expect("session must reconnect"), b"alpha");
    // A closed session reconnects when used again.
    s.close();
    s.rm(&a).expect("rm");
    s.rm(&b).expect("rm");
    assert!(matches!(s.get(&a), Err(SdkError::NotFound)));

    assert!(
        matches!(client.session(&"0".repeat(64)), Err(SdkError::Denied)),
        "an unknown token must be denied"
    );
}
