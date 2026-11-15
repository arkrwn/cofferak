//! Tests for `commands/workload.rs` (ADR 0022): trusted identity providers
//! and workload bindings stored encrypted in the vault, driven with a fake
//! host seal, plus one test of the real binary.

#[allow(dead_code)]
#[path = "../src/client.rs"]
mod client;
#[allow(dead_code)]
#[path = "../src/commands/enroll.rs"]
mod enroll;
#[allow(dead_code)]
#[path = "../src/commands/init.rs"]
mod init;
#[allow(dead_code)]
#[path = "../src/commands/integrity.rs"]
mod integrity;
#[allow(dead_code)]
#[path = "../src/presence.rs"]
mod presence;
use cofferakd::protocol;
#[allow(dead_code)]
#[path = "../src/commands/secrets.rs"]
mod secrets;
#[allow(dead_code)]
#[path = "../src/commands/transfer.rs"]
mod transfer;
#[allow(dead_code)]
#[path = "../src/commands/workload.rs"]
mod workload;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferak_core::acl::Permission;
use cofferak_core::crypto::{decrypt_entry, unwrap_dek_for_host, Aad};
use cofferak_core::format::{read_anchor, VaultFile};
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};
use cofferak_core::workload::{JwtAlg, WorkloadConfig};

use enroll::run_enroll_service_with_seal;
use init::{run_init_host_with_seal, run_init_root, CliError};
use secrets::run_rotate_dek;
use workload::{run_change_with_seal, run_list_with_seal, Change, Outcome};

const HOST: &str = "host-a";
const ISS: &str = "https://oidc.plaintext-probe-issuer.example/cluster";
const AUD: &str = "plaintext-probe-audience";
const SUB: &str = "system:serviceaccount:plaintext-probe-ns:api";

struct FakeHostSeal {
    tag: u8,
}

impl HostSeal for FakeHostSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let mut out = Vec::with_capacity(33);
        out.push(self.tag);
        out.extend(key.iter().map(|b| b ^ 0xAA));
        Ok(SealedBlob(out))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0.len() != 33 || blob.0[0] != self.tag {
            return Err(SealError::Invalid("fake seal: tag mismatch".to_string()));
        }
        let mut key = [0u8; 32];
        for (i, b) in blob.0[1..].iter().enumerate() {
            key[i] = b ^ 0xAA;
        }
        Ok(key)
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cofferak-cli-workload-test-{}-{nanos}-{n}-{tag}",
        std::process::id()
    ))
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..=chunk.len() {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn ec_jwks(kid: &str) -> String {
    let x = b64url(&[7u8; 32]);
    let y = b64url(&[9u8; 32]);
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","use":"sig","x":"{x}","y":"{y}"}}]}}"#
    )
}

fn rsa_jwks(kid: &str, n_len: usize) -> String {
    let mut n = vec![0x5Au8; n_len];
    n[0] = 0xC0;
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"{}","e":"AQAB"}}]}}"#,
        b64url(&n)
    )
}

fn add_issuer(name: &str, iss: &str, jwks: String) -> Change {
    Change::AddIssuer {
        name: name.to_string(),
        issuer: iss.to_string(),
        audience: AUD.to_string(),
        algorithms: vec![JwtAlg::Es256],
        jwks,
        leeway_secs: 30,
        max_ttl_secs: 3600,
        replace: false,
    }
}

fn bind(name: &str, issuer: &str, subject: &str, service: &str) -> Change {
    Change::Bind {
        name: name.to_string(),
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        service: service.to_string(),
    }
}

fn setup(tag: &str) -> (PathBuf, FakeHostSeal) {
    let dir = temp_dir(tag);
    run_init_root(&dir).expect("init --root");
    let seal = FakeHostSeal { tag: 0x5A };
    run_init_host_with_seal(&dir, HOST, &seal).expect("init host");
    (dir, seal)
}

fn enroll(dir: &Path, seal: &FakeHostSeal, service: &str) {
    run_enroll_service_with_seal(
        dir,
        HOST,
        seal,
        service,
        vec!["app".to_string()],
        Permission::Read,
    )
    .expect("enroll service");
}

fn change(dir: &Path, seal: &FakeHostSeal, c: Change) -> Result<Outcome, CliError> {
    run_change_with_seal(dir, HOST, seal, c)
}

fn list(dir: &Path, seal: &FakeHostSeal) -> WorkloadConfig {
    run_list_with_seal(dir, HOST, seal).expect("list")
}

fn generation(dir: &Path) -> u64 {
    VaultFile::load(&dir.join("vault.cofferak"))
        .unwrap()
        .generation
}

fn vault_bytes(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("vault.cofferak")).unwrap()
}

fn err_text(r: Result<Outcome, CliError>) -> String {
    r.expect_err("should have been refused").to_string()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn add_issuer_stores_the_issuer_bumps_generation_updates_anchor_and_hides_plaintext() {
    let (dir, seal) = setup("add");
    assert!(list(&dir, &seal).is_empty());
    let g0 = generation(&dir);

    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();
    let g1 = generation(&dir);
    assert_eq!(g1, g0 + 1);

    let config = list(&dir, &seal);
    let issuer = &config.issuers["k8s"];
    assert_eq!(issuer.issuer, ISS);
    assert_eq!(issuer.audience, AUD);
    assert_eq!(issuer.algorithms, vec![JwtAlg::Es256]);
    assert_eq!(issuer.leeway_secs, 30);
    assert_eq!(issuer.max_ttl_secs, 3600);

    enroll(&dir, &seal, "svc");
    let g2 = generation(&dir);
    assert_eq!(g2, g1 + 1);
    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();
    assert_eq!(generation(&dir), g2 + 1);

    // The anchor follows, so the daemon's rollback check passes.
    let (vault, dek) = transfer::open_vault(&dir, HOST, &seal).expect("integrity check passes");
    assert_eq!(
        read_anchor(&dir, HOST, &dek).unwrap(),
        Some(vault.generation)
    );

    let bytes = vault_bytes(&dir);
    for secret in [ISS, AUD, SUB, "oidc.plaintext-probe-issuer", "k1"] {
        assert!(
            !contains(&bytes, secret),
            "{secret} must not be readable in vault.cofferak"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn add_issuer_refuses_bad_input_and_replace_overwrites() {
    let (dir, seal) = setup("add-bad");
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();
    let before = vault_bytes(&dir);

    // An existing name without replace.
    let msg = err_text(change(
        &dir,
        &seal,
        add_issuer("k8s", "https://other.example", ec_jwks("k2")),
    ));
    assert!(msg.contains("already exists"), "{msg}");
    assert_eq!(
        vault_bytes(&dir),
        before,
        "refusal must not touch the vault"
    );

    let mut cases: Vec<(&str, Change)> = Vec::new();
    cases.push((
        "not json",
        add_issuer("n1", "https://a.example", "not json at all".to_string()),
    ));
    cases.push((
        "no key",
        add_issuer("n2", "https://b.example", r#"{"keys":[]}"#.to_string()),
    ));
    // An RSA key where only ES256 is allowed.
    cases.push((
        "no key fits",
        add_issuer("n3", "https://c.example", rsa_jwks("r", 256)),
    ));
    let mut short = add_issuer("n4", "https://d.example", rsa_jwks("r", 128));
    if let Change::AddIssuer { algorithms, .. } = &mut short {
        *algorithms = vec![JwtAlg::Rs256];
    }
    cases.push(("short rsa modulus", short));
    for (label, tweak) in [
        ("empty audience", 0),
        ("no algorithms", 1),
        ("leeway above 300", 2),
        ("max_ttl 0", 3),
    ] {
        let mut c = add_issuer("n5", "https://e.example", ec_jwks("k"));
        if let Change::AddIssuer {
            audience,
            algorithms,
            leeway_secs,
            max_ttl_secs,
            ..
        } = &mut c
        {
            match tweak {
                0 => audience.clear(),
                1 => algorithms.clear(),
                2 => *leeway_secs = 301,
                _ => *max_ttl_secs = 0,
            }
        }
        cases.push((label, c));
    }
    // Two issuers with the same iss.
    cases.push(("same iss", add_issuer("dup", ISS, ec_jwks("k3"))));

    for (label, c) in cases {
        let r = change(&dir, &seal, c);
        assert!(r.is_err(), "{label} must be refused");
        assert_eq!(vault_bytes(&dir), before, "{label} must not write");
    }

    // With replace the issuer is replaced.
    let mut c = add_issuer("k8s", "https://new.example", ec_jwks("k9"));
    if let Change::AddIssuer { replace, .. } = &mut c {
        *replace = true;
    }
    change(&dir, &seal, c).unwrap();
    let config = list(&dir, &seal);
    assert_eq!(config.issuers.len(), 1);
    assert_eq!(config.issuers["k8s"].issuer, "https://new.example");
    assert!(config.issuers["k8s"].jwks.contains("k9"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_jwks_swaps_keys_and_keeps_bindings() {
    let (dir, seal) = setup("update");
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("old"))).unwrap();
    enroll(&dir, &seal, "svc");
    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();

    change(
        &dir,
        &seal,
        Change::UpdateJwks {
            name: "k8s".into(),
            jwks: ec_jwks("new"),
        },
    )
    .unwrap();
    let config = list(&dir, &seal);
    assert!(config.issuers["k8s"].jwks.contains("new"));
    assert!(!config.issuers["k8s"].jwks.contains("old"));
    assert_eq!(config.bindings["b1"].subject, SUB);

    let before = vault_bytes(&dir);
    let msg = err_text(change(
        &dir,
        &seal,
        Change::UpdateJwks {
            name: "nope".into(),
            jwks: ec_jwks("x"),
        },
    ));
    assert!(msg.contains("no issuer named nope"), "{msg}");
    // A JWKS that cannot work is refused too, and nothing is written.
    assert!(change(
        &dir,
        &seal,
        Change::UpdateJwks {
            name: "k8s".into(),
            jwks: "{}".into(),
        },
    )
    .is_err());
    assert_eq!(vault_bytes(&dir), before);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn bind_and_unbind_enforce_their_preconditions() {
    let (dir, seal) = setup("bind");
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();

    // Service not enrolled.
    let msg = err_text(change(&dir, &seal, bind("b1", "k8s", SUB, "svc")));
    assert!(msg.contains("enroll-service"), "{msg}");

    enroll(&dir, &seal, "svc");
    enroll(&dir, &seal, "svc2");

    // Unknown issuer.
    assert!(change(&dir, &seal, bind("b1", "ghost", SUB, "svc")).is_err());

    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();
    let before = vault_bytes(&dir);
    // Second binding for the same (issuer, subject).
    assert!(change(&dir, &seal, bind("b2", "k8s", SUB, "svc2")).is_err());
    // Duplicate binding name.
    let msg = err_text(change(&dir, &seal, bind("b1", "k8s", "other-sub", "svc2")));
    assert!(msg.contains("already exists"), "{msg}");
    assert_eq!(vault_bytes(&dir), before);

    change(&dir, &seal, Change::Unbind { name: "b1".into() }).unwrap();
    assert!(list(&dir, &seal).bindings.is_empty());
    // The subject is free again.
    change(&dir, &seal, bind("b2", "k8s", SUB, "svc2")).unwrap();

    let before = vault_bytes(&dir);
    let msg = err_text(change(&dir, &seal, Change::Unbind { name: "zzz".into() }));
    assert!(msg.contains("no binding named zzz"), "{msg}");
    assert_eq!(vault_bytes(&dir), before);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rm_issuer_drops_its_bindings_and_reports_them() {
    let (dir, seal) = setup("rm");
    change(&dir, &seal, add_issuer("one", ISS, ec_jwks("k1"))).unwrap();
    change(
        &dir,
        &seal,
        add_issuer("two", "https://two.example", ec_jwks("k2")),
    )
    .unwrap();
    enroll(&dir, &seal, "svc");
    change(&dir, &seal, bind("a", "one", "s1", "svc")).unwrap();
    change(&dir, &seal, bind("b", "one", "s2", "svc")).unwrap();
    change(&dir, &seal, bind("c", "two", "s1", "svc")).unwrap();

    let outcome = change(&dir, &seal, Change::RmIssuer { name: "one".into() }).unwrap();
    let mut dropped = outcome.dropped_bindings.clone();
    dropped.sort();
    assert_eq!(dropped, vec!["a".to_string(), "b".to_string()]);

    let config = list(&dir, &seal);
    assert!(!config.issuers.contains_key("one"));
    assert!(config.issuers.contains_key("two"));
    assert_eq!(config.bindings.keys().collect::<Vec<_>>(), vec!["c"]);

    let before = vault_bytes(&dir);
    assert!(change(&dir, &seal, Change::RmIssuer { name: "one".into() }).is_err());
    assert_eq!(vault_bytes(&dir), before);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_configuration_survives_rotate_dek() {
    let (dir, seal) = setup("rotate");
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();
    enroll(&dir, &seal, "svc");
    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();
    let before = list(&dir, &seal);

    let (_, old_dek) = transfer::open_vault(&dir, HOST, &seal).unwrap();
    let old_dek = *old_dek;

    let hosts: Vec<(String, Box<dyn HostSeal>)> =
        vec![(HOST.to_string(), Box::new(FakeHostSeal { tag: 0x5A }))];
    run_rotate_dek(&dir, &hosts).expect("rotate-dek");

    let vault = VaultFile::load(&dir.join("vault.cofferak")).unwrap();
    let sealed = std::fs::read(dir.join("hosts/host-a.seal")).unwrap();
    let host_key = seal.unseal(&SealedBlob(sealed)).unwrap();
    let new_dek = unwrap_dek_for_host(&vault.hosts[HOST], HOST, &host_key).unwrap();
    assert_ne!(new_dek, old_dek);

    let entry = vault.workload.as_ref().expect("workload entry kept");
    let plain = decrypt_entry(&new_dek, &Aad::workload(), entry).expect("decrypts under new DEK");
    let decoded: WorkloadConfig = bincode::deserialize(&plain).unwrap();
    assert_eq!(decoded, before);
    assert!(decrypt_entry(&old_dek, &Aad::workload(), entry).is_err());

    assert_eq!(list(&dir, &seal), before);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn re_enrolling_a_service_still_works_and_keeps_its_binding() {
    let (dir, seal) = setup("reenroll");
    let first = run_enroll_service_with_seal(
        &dir,
        HOST,
        &seal,
        "svc",
        vec!["app".into()],
        Permission::Read,
    )
    .unwrap();
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();
    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();
    let before = list(&dir, &seal);

    let second = run_enroll_service_with_seal(
        &dir,
        HOST,
        &seal,
        "svc",
        vec!["app".into(), "more".into()],
        Permission::ReadWrite,
    )
    .expect("re-enrolling an existing service id works");
    assert_eq!(second.service_id, "svc");
    assert_eq!(second.permission, Permission::ReadWrite);
    assert_ne!(first.secret, second.secret);

    assert_eq!(list(&dir, &seal), before);
    assert!(list(&dir, &seal).bindings.contains_key("b1"));
    // The binding still resolves to a service that exists.
    change(&dir, &seal, bind("b2", "k8s", "another", "svc")).unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_vault_edited_outside_cofferak_fails_every_workload_change_and_writes_nothing() {
    let (dir, seal) = setup("tamper");
    change(&dir, &seal, add_issuer("k8s", ISS, ec_jwks("k1"))).unwrap();
    enroll(&dir, &seal, "svc");
    change(&dir, &seal, bind("b1", "k8s", SUB, "svc")).unwrap();

    let path = dir.join("vault.cofferak");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    let meta_before = std::fs::read(dir.join("meta.json")).unwrap();

    let changes = vec![
        add_issuer("new", "https://new.example", ec_jwks("n")),
        Change::UpdateJwks {
            name: "k8s".into(),
            jwks: ec_jwks("n"),
        },
        Change::RmIssuer { name: "k8s".into() },
        bind("b2", "k8s", "other", "svc"),
        Change::Unbind { name: "b1".into() },
    ];
    for c in changes {
        let label = format!("{c:?}");
        assert!(change(&dir, &seal, c).is_err(), "{label} must fail");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{label} wrote");
    }
    assert!(run_list_with_seal(&dir, HOST, &seal).is_err());
    assert_eq!(std::fs::read(dir.join("meta.json")).unwrap(), meta_before);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_binary_manages_issuers_bindings_and_identity_only_services() {
    use std::process::Command;

    let dir = temp_dir("binary");
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("host.key");
    let data = dir.join("data");
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_cofferak"))
            .args(args)
            .arg("--data-dir")
            .arg(&data)
            .env("COFFERAK_SEAL", "file")
            .env("COFFERAK_HOST_KEY_FILE", &key_file)
            .env("COFFERAK_NO_USER_PRESENCE", "1")
            .env_remove("COFFERAK_HOST_ID")
            .output()
            .expect("run cofferak");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "cofferak {args:?} failed: {stdout}{stderr}"
        );
        stdout
    };
    let has_hex64 = |text: &str| {
        text.lines().any(|l| {
            let l = l.trim();
            l.len() == 64 && l.bytes().all(|b| b.is_ascii_hexdigit())
        })
    };

    run(&["init", "--root"]);
    run(&["init", "--host", "bin-host"]);

    let jwks = dir.join("jwks.json");
    std::fs::write(&jwks, ec_jwks("bin-key")).unwrap();
    let jwks = jwks.to_string_lossy().into_owned();

    let shown = run(&[
        "enroll-service",
        "svc-shown",
        "--paths",
        "app",
        "--perm",
        "ro",
    ]);
    assert!(has_hex64(&shown), "a plain enroll-service prints the token");
    let hidden = run(&[
        "enroll-service",
        "svc-hidden",
        "--paths",
        "app",
        "--perm",
        "ro",
        "--identity-only",
    ]);
    assert!(!has_hex64(&hidden), "identity-only must not print a token");

    run(&[
        "workload",
        "add-issuer",
        "k8s",
        "--iss",
        ISS,
        "--audience",
        AUD,
        "--jwks",
        &jwks,
        "--alg",
        "ES256",
    ]);
    run(&[
        "workload",
        "bind",
        "payments",
        "--issuer",
        "k8s",
        "--subject",
        SUB,
        "--service",
        "svc-hidden",
    ]);
    let listing = run(&["workload", "list"]);
    for want in [ISS, AUD, SUB, "k8s", "payments", "svc-hidden", "bin-key"] {
        assert!(listing.contains(want), "list lacks {want}: {listing}");
    }
    std::fs::remove_dir_all(&dir).ok();
}
