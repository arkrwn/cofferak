//! Session time limits (ADR 0019). In its own test binary because the
//! limits are read from the environment once per process.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::generate_root_keypair;
use cofferak_core::format::VaultFile;
use cofferakd::audit::AuditLog;
use cofferakd::daemon::{token_key, Daemon};

const SECRET: [u8; 32] = [0x42; 32];

fn call(writer: &mut UnixStream, reader: &mut BufReader<UnixStream>, line: &str) -> String {
    writer.write_all(line.as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let mut out = String::new();
    reader.read_line(&mut out).unwrap();
    out.trim().to_string()
}

#[test]
fn an_idle_session_is_closed_and_a_busy_one_ends_at_its_lifetime() {
    std::env::set_var("COFFERAK_SESSION_IDLE_SECS", "1");
    std::env::set_var("COFFERAK_SESSION_MAX_SECS", "3");

    let (root_pubkey, _) = generate_root_keypair().unwrap();
    let mut tokens = BTreeMap::new();
    tokens.insert(
        token_key(&SECRET),
        AccessToken {
            service_id: "svc".to_string(),
            prefixes: vec!["app".to_string()],
            permission: Permission::ReadWrite,
            secret: SECRET,
        },
    );
    let audit_path = std::env::temp_dir().join(format!(
        "cofferakd-session-idle-{}.jsonl",
        std::process::id()
    ));
    let daemon = Arc::new(Mutex::new(Daemon::new(
        [0x7A; 32],
        VaultFile::new(root_pubkey),
        tokens,
        AuditLog::open(&audit_path).unwrap(),
    )));
    let open = || {
        let (server, client) = UnixStream::pair().unwrap();
        let d = Arc::clone(&daemon);
        std::thread::spawn(move || cofferakd::server::handle_connection(server, d));
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut writer = client;
        call(&mut writer, &mut reader, r#"{"Hello":{"version":2}}"#);
        let auth = format!(
            r#"{{"Auth":{{"method":"token","credential":"{}"}}}}"#,
            token_key(&SECRET)
        );
        assert!(call(&mut writer, &mut reader, &auth).contains("Authed"));
        (writer, reader)
    };

    // Idle: no request for longer than the idle limit.
    let (mut writer, mut reader) = open();
    let start = Instant::now();
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "an idle session must be closed by the daemon");
    assert!(start.elapsed() >= Duration::from_millis(900));
    assert!(start.elapsed() < Duration::from_secs(3));
    let _ = writer.write_all(b"\"Ping\"\n");

    // Busy: requests keep coming, the lifetime limit still ends it.
    let (mut writer, mut reader) = open();
    let start = Instant::now();
    let mut closed = false;
    while start.elapsed() < Duration::from_secs(8) {
        if writer.write_all(b"\"Ping\"\n").is_err() {
            closed = true;
            break;
        }
        let mut out = String::new();
        if reader.read_line(&mut out).unwrap_or(0) == 0 {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(closed, "a session must end at its maximum lifetime");
    assert!(start.elapsed() >= Duration::from_millis(2500));

    let _ = std::fs::remove_file(&audit_path);
}
