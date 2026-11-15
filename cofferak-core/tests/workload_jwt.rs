//! Integration tests for `cofferak_core::workload`: workload identity
//! tokens (JWTs) verified offline against configured issuers and bound to
//! services. Real signed tokens are minted here with aws-lc-rs, the same
//! crypto library the code under test verifies with, and checked through the
//! public API only.

use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
    RSA_PKCS1_SHA256,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use cofferak_core::workload::{
    Binding, Issuer, JwtAlg, Principal, Reject, Verified, WorkloadConfig, MAX_JWKS_BYTES,
    MAX_TOKEN_BYTES,
};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

const ISS: &str = "https://issuer.test";
const AUD: &str = "cofferak";
const SUB: &str = "system:serviceaccount:ns:sa";

// ---------------------------------------------------------------------
// Minting helpers
// ---------------------------------------------------------------------

enum Signer {
    Ec(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

struct TestKey {
    kid: String,
    alg: JwtAlg,
    signer: Signer,
    jwk: Value,
    /// The public key as the library hands it out (EC point or RSA DER).
    public: Vec<u8>,
}

fn b64(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

fn ec_key(kid: &str, p384: bool) -> TestKey {
    let (signing, alg, crv) = if p384 {
        (&ECDSA_P384_SHA384_FIXED_SIGNING, JwtAlg::Es384, "P-384")
    } else {
        (&ECDSA_P256_SHA256_FIXED_SIGNING, JwtAlg::Es256, "P-256")
    };
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref()).unwrap();
    let point = key.public_key().as_ref().to_vec();
    assert_eq!(point[0], 0x04);
    let half = (point.len() - 1) / 2;
    let jwk = json!({
        "kty": "EC",
        "crv": crv,
        "kid": kid,
        "x": b64(&point[1..1 + half]),
        "y": b64(&point[1 + half..]),
    });
    TestKey {
        kid: kid.into(),
        alg,
        signer: Signer::Ec(key),
        jwk,
        public: point,
    }
}

fn es256(kid: &str) -> TestKey {
    ec_key(kid, false)
}

fn es384(kid: &str) -> TestKey {
    ec_key(kid, true)
}

/// Read one DER INTEGER at `pos`, return its value bytes and the next position.
fn der_integer(buf: &[u8], pos: usize) -> (&[u8], usize) {
    assert_eq!(buf[pos], 0x02, "expected a DER INTEGER");
    let (len, start) = der_len(buf, pos + 1);
    (&buf[start..start + len], start + len)
}

fn der_len(buf: &[u8], pos: usize) -> (usize, usize) {
    let first = buf[pos];
    if first < 0x80 {
        (first as usize, pos + 1)
    } else {
        let count = (first & 0x7f) as usize;
        let len = buf[pos + 1..pos + 1 + count]
            .iter()
            .fold(0usize, |a, b| (a << 8) | *b as usize);
        (len, pos + 1 + count)
    }
}

/// Parse a DER RSAPublicKey into (n, e), `n` without its leading zero byte.
fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(der[0], 0x30, "expected a DER SEQUENCE");
    let (_, body) = der_len(der, 1);
    let (n, next) = der_integer(der, body);
    let (e, _) = der_integer(der, next);
    let n: Vec<u8> = n.iter().copied().skip_while(|b| *b == 0).collect();
    (n, e.to_vec())
}

fn rsa_key(kid: &str) -> TestKey {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let der = key.public_key().as_ref().to_vec();
    let (n, e) = rsa_components(&der);
    let jwk = json!({
        "kty": "RSA",
        "kid": kid,
        "n": b64(&n),
        "e": b64(&e),
    });
    TestKey {
        kid: kid.into(),
        alg: JwtAlg::Rs256,
        signer: Signer::Rsa(key),
        jwk,
        public: der,
    }
}

fn sign(signer: &Signer, input: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    match signer {
        Signer::Ec(key) => key.sign(&rng, input).unwrap().as_ref().to_vec(),
        Signer::Rsa(key) => {
            let mut sig = vec![0u8; key.public_modulus_len()];
            key.sign(&RSA_PKCS1_SHA256, &rng, input, &mut sig).unwrap();
            sig
        }
    }
}

/// `b64(header).b64(claims).b64(signature)`, signed over the first two parts.
fn mint(header: &Value, claims: &Value, signer: &Signer) -> String {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig = sign(signer, input.as_bytes());
    format!("{input}.{}", b64(&sig))
}

fn assemble(header: &Value, claims: &Value, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes()),
        b64(signature)
    )
}

fn header_for(key: &TestKey) -> Value {
    json!({"alg": key.alg.name(), "typ": "JWT", "kid": key.kid})
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims_for(iss: &str, sub: &str) -> Value {
    let t = now();
    json!({"iss": iss, "aud": AUD, "sub": sub, "iat": t, "exp": t + 3600})
}

fn good_claims() -> Value {
    claims_for(ISS, SUB)
}

fn claims_with(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Value {
    let mut c = good_claims();
    edit(c.as_object_mut().unwrap());
    c
}

fn token(key: &TestKey) -> String {
    mint(&header_for(key), &good_claims(), &key.signer)
}

fn token_with(key: &TestKey, claims: &Value) -> String {
    mint(&header_for(key), claims, &key.signer)
}

fn jwks_of(jwks: &[Value]) -> String {
    json!({ "keys": jwks }).to_string()
}

fn issuer_for(iss: &str, algorithms: Vec<JwtAlg>, keys: &[&TestKey]) -> Issuer {
    let jwks: Vec<Value> = keys.iter().map(|k| k.jwk.clone()).collect();
    Issuer {
        issuer: iss.into(),
        audience: AUD.into(),
        algorithms,
        jwks: jwks_of(&jwks),
        leeway_secs: 30,
        max_ttl_secs: 86_400,
    }
}

fn issuer(algorithms: Vec<JwtAlg>, keys: &[&TestKey]) -> Issuer {
    issuer_for(ISS, algorithms, keys)
}

/// An ES256-only issuer holding one key: the baseline for most tests.
fn simple() -> (Issuer, TestKey) {
    let key = es256("k1");
    (issuer(vec![JwtAlg::Es256], &[&key]), key)
}

/// Change one character in the middle of one dot-separated part.
fn tamper(token: &str, part: usize) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    let mut chars: Vec<char> = parts[part].chars().collect();
    let i = chars.len() / 2;
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    parts[part] = chars.into_iter().collect();
    parts.join(".")
}

fn assert_rejected_as(result: Result<Verified, Reject>, allowed: &[Reject]) {
    match result {
        Ok(v) => panic!("token was accepted: {v:?}"),
        Err(r) => assert!(
            allowed.contains(&r),
            "rejected as {r:?}, expected one of {allowed:?}"
        ),
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    OsRng.fill_bytes(&mut b);
    b[0] |= 0x80;
    b
}

// ---------------------------------------------------------------------
// 1. Valid tokens
// ---------------------------------------------------------------------

#[test]
fn accepts_a_valid_es256_token_and_returns_subject_and_exp() {
    let (iss, key) = simple();
    let claims = good_claims();
    let exp = claims["exp"].as_i64().unwrap();
    let v = iss.verify(&token_with(&key, &claims)).unwrap();
    assert_eq!(v.subject, SUB);
    assert_eq!(v.expires_at, exp);
}

#[test]
fn accepts_a_valid_es384_token_and_returns_subject_and_exp() {
    let key = es384("k384");
    let iss = issuer(vec![JwtAlg::Es384], &[&key]);
    let claims = good_claims();
    let exp = claims["exp"].as_i64().unwrap();
    let v = iss.verify(&token_with(&key, &claims)).unwrap();
    assert_eq!(v.subject, SUB);
    assert_eq!(v.expires_at, exp);
}

#[test]
fn accepts_a_valid_rs256_token_and_returns_subject_and_exp() {
    let key = rsa_key("rsa1");
    let iss = issuer(vec![JwtAlg::Rs256], &[&key]);
    let claims = good_claims();
    let exp = claims["exp"].as_i64().unwrap();
    let v = iss.verify(&token_with(&key, &claims)).unwrap();
    assert_eq!(v.subject, SUB);
    assert_eq!(v.expires_at, exp);
}

#[test]
fn a_generated_rsa_key_passes_issuer_validation() {
    let key = rsa_key("rsa1");
    assert_eq!(issuer(vec![JwtAlg::Rs256], &[&key]).validate(), Ok(()));
}

// ---------------------------------------------------------------------
// 2. Time claims
// ---------------------------------------------------------------------

#[test]
fn rejects_an_expired_token() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("exp".into(), json!(t - 120));
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::Expired));
}

#[test]
fn accepts_a_token_expired_by_less_than_the_leeway() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("exp".into(), json!(t - 10));
    });
    assert!(iss.verify(&token_with(&key, &c)).is_ok());
}

#[test]
fn rejects_a_token_without_exp() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.remove("exp");
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::MissingClaim));
}

#[test]
fn rejects_a_token_whose_nbf_is_in_the_future_beyond_the_leeway() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("nbf".into(), json!(t + 120));
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::NotYetValid));
}

#[test]
fn accepts_a_token_whose_nbf_is_in_the_future_within_the_leeway() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("nbf".into(), json!(t + 10));
    });
    assert!(iss.verify(&token_with(&key, &c)).is_ok());
}

#[test]
fn rejects_a_token_valid_for_longer_than_max_ttl() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("exp".into(), json!(t + 2 * 86_400));
    });
    assert_eq!(
        iss.verify(&token_with(&key, &c)),
        Err(Reject::ValidForTooLong)
    );
}

#[test]
fn accepts_a_token_valid_for_exactly_max_ttl() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("exp".into(), json!(t + 86_400));
    });
    assert!(iss.verify(&token_with(&key, &c)).is_ok());
}

#[test]
fn rejects_exp_just_beyond_max_ttl_plus_leeway() {
    let (iss, key) = simple();
    let t = now();
    let c = claims_with(|c| {
        c.insert("exp".into(), json!(t + 86_400 + 30 + 60));
    });
    assert_eq!(
        iss.verify(&token_with(&key, &c)),
        Err(Reject::ValidForTooLong)
    );
}

// ---------------------------------------------------------------------
// 3. Audience, issuer, subject
// ---------------------------------------------------------------------

#[test]
fn rejects_a_token_with_the_wrong_audience() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("aud".into(), json!("someone-else"));
    });
    assert_eq!(
        iss.verify(&token_with(&key, &c)),
        Err(Reject::WrongAudience)
    );
}

#[test]
fn accepts_an_audience_array_that_contains_the_right_one() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("aud".into(), json!(["other", AUD]));
    });
    assert!(iss.verify(&token_with(&key, &c)).is_ok());
}

#[test]
fn rejects_an_audience_array_without_the_right_one() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("aud".into(), json!(["other", "another"]));
    });
    assert_eq!(
        iss.verify(&token_with(&key, &c)),
        Err(Reject::WrongAudience)
    );
}

#[test]
fn rejects_an_audience_that_only_contains_the_right_one_as_a_substring() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("aud".into(), json!("cofferak-staging"));
    });
    assert_eq!(
        iss.verify(&token_with(&key, &c)),
        Err(Reject::WrongAudience)
    );
}

#[test]
fn rejects_a_token_without_an_audience() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.remove("aud");
    });
    assert_rejected_as(
        iss.verify(&token_with(&key, &c)),
        &[Reject::MissingClaim, Reject::WrongAudience],
    );
}

#[test]
fn rejects_a_token_with_the_wrong_issuer() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("iss".into(), json!("https://evil.test"));
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::WrongIssuer));
}

#[test]
fn rejects_a_token_without_a_subject() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.remove("sub");
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::MissingClaim));
}

#[test]
fn rejects_a_token_with_an_empty_subject() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("sub".into(), json!(""));
    });
    assert_eq!(iss.verify(&token_with(&key, &c)), Err(Reject::MissingClaim));
}

#[test]
fn rejects_a_token_whose_subject_is_not_a_string() {
    let (iss, key) = simple();
    let c = claims_with(|c| {
        c.insert("sub".into(), json!(42));
    });
    assert_rejected_as(
        iss.verify(&token_with(&key, &c)),
        &[Reject::MissingClaim, Reject::Malformed],
    );
}

// ---------------------------------------------------------------------
// 4. Algorithm attacks
// ---------------------------------------------------------------------

#[test]
fn rejects_alg_none_with_an_empty_signature() {
    let (iss, key) = simple();
    let header = json!({"alg": "none", "typ": "JWT", "kid": key.kid});
    let t = assemble(&header, &good_claims(), b"");
    assert_rejected_as(
        iss.verify(&t),
        &[Reject::AlgorithmNotAllowed, Reject::Malformed],
    );
}

#[test]
fn rejects_alg_none_spelled_in_other_cases() {
    let (iss, key) = simple();
    for name in ["None", "NONE", "nOnE"] {
        let header = json!({"alg": name, "typ": "JWT", "kid": key.kid});
        let t = assemble(&header, &good_claims(), b"");
        assert_rejected_as(
            iss.verify(&t),
            &[Reject::AlgorithmNotAllowed, Reject::Malformed],
        );
    }
}

fn hs256_token(key: &TestKey, secret: &[u8]) -> String {
    let header = json!({"alg": "HS256", "typ": "JWT", "kid": key.kid});
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(good_claims().to_string().as_bytes())
    );
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), input.as_bytes());
    format!("{input}.{}", b64(mac.as_ref()))
}

#[test]
fn rejects_hs256_signed_with_the_rsa_public_key_as_secret() {
    let key = rsa_key("rsa1");
    let iss = issuer(vec![JwtAlg::Rs256], &[&key]);
    let (n, _) = rsa_components(&key.public);
    // Positive control: the real RS256 token is accepted.
    assert!(iss.verify(&token(&key)).is_ok());
    for secret in [n, key.public.clone()] {
        assert_eq!(
            iss.verify(&hs256_token(&key, &secret)),
            Err(Reject::AlgorithmNotAllowed)
        );
    }
}

#[test]
fn rejects_hs256_signed_with_the_ec_public_key_as_secret() {
    let (iss, key) = simple();
    assert!(iss.verify(&token(&key)).is_ok());
    assert_eq!(
        iss.verify(&hs256_token(&key, &key.public)),
        Err(Reject::AlgorithmNotAllowed)
    );
}

#[test]
fn rejects_a_validly_signed_es384_token_when_only_es256_is_allowed() {
    let k256 = es256("k256");
    let k384 = es384("k384");
    let only_256 = issuer(vec![JwtAlg::Es256], &[&k256, &k384]);
    let both = issuer(vec![JwtAlg::Es256, JwtAlg::Es384], &[&k256, &k384]);
    let t = token(&k384);
    assert_eq!(only_256.verify(&t), Err(Reject::AlgorithmNotAllowed));
    assert!(both.verify(&t).is_ok());
}

#[test]
fn rejects_ps256_and_eddsa_headers() {
    let (iss, key) = simple();
    for name in ["PS256", "EdDSA", "HS384", "RS512", "ES512"] {
        let header = json!({"alg": name, "typ": "JWT", "kid": key.kid});
        let t = mint(&header, &good_claims(), &key.signer);
        assert_rejected_as(
            iss.verify(&t),
            &[Reject::AlgorithmNotAllowed, Reject::Malformed],
        );
    }
    for name in ["PS256", "EdDSA"] {
        let header = json!({"alg": name, "typ": "JWT", "kid": key.kid});
        let t = mint(&header, &good_claims(), &key.signer);
        assert_eq!(iss.verify(&t), Err(Reject::AlgorithmNotAllowed));
    }
}

// ---------------------------------------------------------------------
// 5. Key selection
// ---------------------------------------------------------------------

#[test]
fn rejects_a_token_signed_by_a_different_key_with_the_same_kid() {
    let (iss, key) = simple();
    let other = es256("k1");
    assert!(iss.verify(&token(&key)).is_ok());
    assert_eq!(iss.verify(&token(&other)), Err(Reject::BadSignature));
}

#[test]
fn rejects_an_unknown_kid() {
    let (iss, key) = simple();
    let mut header = header_for(&key);
    header["kid"] = json!("nope");
    let t = mint(&header, &good_claims(), &key.signer);
    assert_eq!(iss.verify(&t), Err(Reject::UnknownKey));
}

#[test]
fn rejects_a_token_without_kid_when_two_keys_fit() {
    let a = es256("a");
    let b = es256("b");
    let iss = issuer(vec![JwtAlg::Es256], &[&a, &b]);
    let header = json!({"alg": "ES256", "typ": "JWT"});
    let t = mint(&header, &good_claims(), &a.signer);
    assert_eq!(iss.verify(&t), Err(Reject::UnknownKey));
    // Control: with a kid the same key is found.
    assert!(iss.verify(&token(&a)).is_ok());
}

#[test]
fn accepts_a_token_without_kid_when_exactly_one_key_fits() {
    let (iss, key) = simple();
    let header = json!({"alg": "ES256", "typ": "JWT"});
    let t = mint(&header, &good_claims(), &key.signer);
    assert!(iss.verify(&t).is_ok());
}

#[test]
fn accepts_a_token_without_kid_when_the_other_key_does_not_fit_the_algorithm() {
    let ec = es256("e");
    let rsa = rsa_key("r");
    let iss = issuer(vec![JwtAlg::Es256, JwtAlg::Rs256], &[&ec, &rsa]);
    let header = json!({"alg": "ES256", "typ": "JWT"});
    let t = mint(&header, &good_claims(), &ec.signer);
    assert!(iss.verify(&t).is_ok());
}

#[test]
fn ignores_a_jwk_whose_use_is_enc() {
    let key = es256("k1");
    let t = token(&key);
    let mut sig_jwk = key.jwk.clone();
    sig_jwk["use"] = json!("sig");
    let mut enc_jwk = key.jwk.clone();
    enc_jwk["use"] = json!("enc");
    let mut iss = issuer(vec![JwtAlg::Es256], &[&key]);
    iss.jwks = jwks_of(&[sig_jwk]);
    assert!(iss.verify(&t).is_ok());
    iss.jwks = jwks_of(&[enc_jwk]);
    assert_eq!(iss.verify(&t), Err(Reject::UnknownKey));
}

#[test]
fn ignores_a_jwk_whose_alg_differs_from_the_header_alg() {
    let key = es256("k1");
    let t = token(&key);
    let mut same = key.jwk.clone();
    same["alg"] = json!("ES256");
    let mut other = key.jwk.clone();
    other["alg"] = json!("ES384");
    let mut iss = issuer(vec![JwtAlg::Es256, JwtAlg::Es384], &[&key]);
    iss.jwks = jwks_of(&[same]);
    assert!(iss.verify(&t).is_ok());
    iss.jwks = jwks_of(&[other]);
    assert_eq!(iss.verify(&t), Err(Reject::UnknownKey));
}

#[test]
fn rejects_an_es256_token_against_a_p384_key_with_the_same_kid() {
    let signer = es256("k1");
    let p384 = es384("k1");
    let iss = issuer(vec![JwtAlg::Es256, JwtAlg::Es384], &[&p384]);
    assert_eq!(iss.verify(&token(&signer)), Err(Reject::UnknownKey));
    // Control: the P-384 key does verify an ES384 token.
    assert!(iss.verify(&token(&p384)).is_ok());
}

#[test]
fn picks_the_right_key_by_kid_in_a_mixed_rsa_and_ec_jwks() {
    let rsa = rsa_key("r1");
    let ec = es256("e1");
    let iss = issuer(vec![JwtAlg::Rs256, JwtAlg::Es256], &[&rsa, &ec]);
    assert!(iss.verify(&token(&rsa)).is_ok());
    assert!(iss.verify(&token(&ec)).is_ok());
    // An RS256 token naming the EC key's kid must not verify.
    let mut header = header_for(&rsa);
    header["kid"] = json!("e1");
    let t = mint(&header, &good_claims(), &rsa.signer);
    assert_eq!(iss.verify(&t), Err(Reject::UnknownKey));
}

// ---------------------------------------------------------------------
// 6. Integrity
// ---------------------------------------------------------------------

#[test]
fn rejects_a_token_with_one_payload_character_changed() {
    let (iss, key) = simple();
    let t = token(&key);
    assert!(iss.verify(&t).is_ok());
    assert_rejected_as(
        iss.verify(&tamper(&t, 1)),
        &[Reject::BadSignature, Reject::Malformed],
    );
}

#[test]
fn rejects_a_token_with_one_signature_character_changed() {
    let (iss, key) = simple();
    let t = token(&key);
    assert_eq!(iss.verify(&tamper(&t, 2)), Err(Reject::BadSignature));
}

#[test]
fn rejects_a_token_with_one_header_character_changed() {
    let (iss, key) = simple();
    let t = token(&key);
    assert_rejected_as(
        iss.verify(&tamper(&t, 0)),
        &[
            Reject::BadSignature,
            Reject::Malformed,
            Reject::UnknownKey,
            Reject::AlgorithmNotAllowed,
        ],
    );
}

#[test]
fn rejects_a_payload_swapped_into_another_valid_tokens_body() {
    let (iss, key) = simple();
    let low = token_with(&key, &claims_for(ISS, "low-privilege"));
    let high = token_with(&key, &claims_for(ISS, "high-privilege"));
    assert!(iss.verify(&low).is_ok());
    assert!(iss.verify(&high).is_ok());
    let low_parts: Vec<&str> = low.split('.').collect();
    let high_parts: Vec<&str> = high.split('.').collect();
    let spliced = format!("{}.{}.{}", low_parts[0], high_parts[1], low_parts[2]);
    assert_eq!(iss.verify(&spliced), Err(Reject::BadSignature));
}

#[test]
fn rejects_an_rs256_token_with_the_signature_changed() {
    let key = rsa_key("r1");
    let iss = issuer(vec![JwtAlg::Rs256], &[&key]);
    let t = token(&key);
    assert!(iss.verify(&t).is_ok());
    assert_eq!(iss.verify(&tamper(&t, 2)), Err(Reject::BadSignature));
}

// ---------------------------------------------------------------------
// 7. Format limits
// ---------------------------------------------------------------------

#[test]
fn rejects_a_token_over_16_kib() {
    let (iss, key) = simple();
    let big = claims_with(|c| {
        c.insert("pad".into(), json!("x".repeat(MAX_TOKEN_BYTES)));
    });
    let t = token_with(&key, &big);
    assert!(t.len() > MAX_TOKEN_BYTES);
    assert_eq!(iss.verify(&t), Err(Reject::TooLarge));
    assert_eq!(
        iss.verify(&"a".repeat(MAX_TOKEN_BYTES + 1)),
        Err(Reject::TooLarge)
    );
}

#[test]
fn accepts_a_token_just_under_16_kib() {
    let (iss, key) = simple();
    let base = token_with(&key, &good_claims()).len();
    // Base64 expands by 4/3, leave room for the signature and the padding.
    let pad = (MAX_TOKEN_BYTES - base) * 3 / 4 - 64;
    let c = claims_with(|c| {
        c.insert("pad".into(), json!("x".repeat(pad)));
    });
    let t = token_with(&key, &c);
    assert!(t.len() <= MAX_TOKEN_BYTES, "len {}", t.len());
    assert!(t.len() > MAX_TOKEN_BYTES - 256, "len {}", t.len());
    assert!(iss.verify(&t).is_ok());
}

#[test]
fn rejects_tokens_without_exactly_three_parts() {
    let (iss, key) = simple();
    let t = token(&key);
    let parts: Vec<&str> = t.split('.').collect();
    let two = format!("{}.{}", parts[0], parts[1]);
    let four = format!("{t}.extra");
    for bad in [two.as_str(), four.as_str(), "", "a.b.c", "abc", "..", "."] {
        assert_eq!(iss.verify(bad), Err(Reject::Malformed), "token {bad:?}");
    }
}

#[test]
fn rejects_a_header_that_is_base64_but_not_json() {
    let (iss, key) = simple();
    let input = format!(
        "{}.{}",
        b64(b"this is not json"),
        b64(good_claims().to_string().as_bytes())
    );
    let sig = sign(&key.signer, input.as_bytes());
    let t = format!("{input}.{}", b64(&sig));
    assert_eq!(iss.verify(&t), Err(Reject::Malformed));
}

#[test]
fn rejects_a_payload_that_is_base64_but_not_json() {
    let (iss, key) = simple();
    // Correctly signed, so only the payload format is wrong.
    let input = format!(
        "{}.{}",
        b64(header_for(&key).to_string().as_bytes()),
        b64(b"this is not json")
    );
    let sig = sign(&key.signer, input.as_bytes());
    let t = format!("{input}.{}", b64(&sig));
    assert_eq!(iss.verify(&t), Err(Reject::Malformed));
}

#[test]
fn rejects_a_payload_that_is_json_but_not_an_object() {
    let (iss, key) = simple();
    let input = format!(
        "{}.{}",
        b64(header_for(&key).to_string().as_bytes()),
        b64(b"[1,2,3]")
    );
    let sig = sign(&key.signer, input.as_bytes());
    let t = format!("{input}.{}", b64(&sig));
    assert_rejected_as(iss.verify(&t), &[Reject::Malformed, Reject::MissingClaim]);
}

// ---------------------------------------------------------------------
// 8. Headers that must be ignored or refused
// ---------------------------------------------------------------------

#[test]
fn ignores_jku_x5u_and_an_embedded_jwk_for_a_token_signed_by_the_configured_key() {
    let (iss, key) = simple();
    let attacker = es256("k1");
    let mut header = header_for(&key);
    header["jku"] = json!("http://evil.example/jwks");
    header["x5u"] = json!("http://evil.example/cert");
    header["jwk"] = attacker.jwk.clone();
    let t = mint(&header, &good_claims(), &key.signer);
    assert!(iss.verify(&t).is_ok());
}

#[test]
fn rejects_a_token_signed_by_the_attacker_key_embedded_in_its_header() {
    let (iss, key) = simple();
    let attacker = es256("k1");
    let mut header = header_for(&key);
    header["jku"] = json!("http://evil.example/jwks");
    header["x5u"] = json!("http://evil.example/cert");
    header["jwk"] = attacker.jwk.clone();
    let t = mint(&header, &good_claims(), &attacker.signer);
    assert_eq!(iss.verify(&t), Err(Reject::BadSignature));
}

#[test]
fn rejects_an_embedded_attacker_key_even_without_a_kid() {
    let (iss, _key) = simple();
    let attacker = es256("evil");
    let header = json!({"alg": "ES256", "typ": "JWT", "jwk": attacker.jwk});
    let t = mint(&header, &good_claims(), &attacker.signer);
    assert_eq!(iss.verify(&t), Err(Reject::BadSignature));
}

#[test]
fn rejects_a_header_with_crit_listing_a_registered_claim() {
    let (iss, key) = simple();
    let mut header = header_for(&key);
    header["crit"] = json!(["exp"]);
    let t = mint(&header, &good_claims(), &key.signer);
    // Refused for the header itself, before any key is looked at.
    assert_eq!(iss.verify(&t), Err(Reject::Malformed));
}

#[test]
fn rejects_a_header_with_an_unknown_crit_entry() {
    let (iss, key) = simple();
    let mut header = header_for(&key);
    header["crit"] = json!(["x-unknown-extension"]);
    header["x-unknown-extension"] = json!(true);
    let t = mint(&header, &good_claims(), &key.signer);
    // Refused for the header itself, before any key is looked at.
    assert_eq!(iss.verify(&t), Err(Reject::Malformed));
}

// ---------------------------------------------------------------------
// 9. Issuer::validate
// ---------------------------------------------------------------------

fn rsa_jwk(kid: &str, n: &[u8], e: &[u8]) -> Value {
    json!({"kty": "RSA", "kid": kid, "n": b64(n), "e": b64(e)})
}

fn rsa_issuer_with(n: &[u8], e: &[u8]) -> Issuer {
    Issuer {
        issuer: ISS.into(),
        audience: AUD.into(),
        algorithms: vec![JwtAlg::Rs256],
        jwks: jwks_of(&[rsa_jwk("r", n, e)]),
        leeway_secs: 30,
        max_ttl_secs: 86_400,
    }
}

#[test]
fn validate_accepts_a_good_issuer() {
    let (iss, _) = simple();
    assert_eq!(iss.validate(), Ok(()));
}

#[test]
fn validate_rejects_an_empty_issuer() {
    let (mut iss, _) = simple();
    iss.issuer = String::new();
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_an_empty_audience() {
    let (mut iss, _) = simple();
    iss.audience = String::new();
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_no_algorithms() {
    let (mut iss, _) = simple();
    iss.algorithms = vec![];
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_zero_max_ttl() {
    let (mut iss, _) = simple();
    iss.max_ttl_secs = 0;
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_leeway_over_300_seconds_and_accepts_300() {
    let (mut iss, _) = simple();
    iss.leeway_secs = 300;
    assert_eq!(iss.validate(), Ok(()));
    iss.leeway_secs = 301;
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_jwks_that_is_not_json() {
    let (mut iss, _) = simple();
    iss.jwks = "{ this is not json".into();
    assert!(iss.validate().is_err());
    iss.jwks = "[]".into();
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_jwks_without_a_key_that_fits_an_allowed_algorithm() {
    let ec = es256("e");
    let mut iss = issuer(vec![JwtAlg::Es256], &[&ec]);
    assert_eq!(iss.validate(), Ok(()));
    iss.algorithms = vec![JwtAlg::Rs256];
    assert!(iss.validate().is_err());
    iss.algorithms = vec![JwtAlg::Es384];
    assert!(iss.validate().is_err());
    iss.jwks = jwks_of(&[]);
    iss.algorithms = vec![JwtAlg::Es256];
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_jwks_whose_only_fitting_key_is_for_encryption() {
    let mut ec = es256("e");
    ec.jwk["use"] = json!("enc");
    let iss = issuer(vec![JwtAlg::Es256], &[&ec]);
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_an_rsa_key_with_a_1024_bit_modulus() {
    let n = random_bytes(128);
    assert!(rsa_issuer_with(&n, &[1, 0, 1]).validate().is_err());
    // Control: 2048 bits is fine.
    let n = random_bytes(256);
    assert_eq!(rsa_issuer_with(&n, &[1, 0, 1]).validate(), Ok(()));
}

#[test]
fn validate_rejects_an_rsa_modulus_over_8192_bits() {
    let n = random_bytes(1025);
    assert!(rsa_issuer_with(&n, &[1, 0, 1]).validate().is_err());
    let n = random_bytes(1024);
    assert_eq!(rsa_issuer_with(&n, &[1, 0, 1]).validate(), Ok(()));
}

#[test]
fn validate_rejects_an_rsa_exponent_of_2_pow_32_or_larger() {
    let n = random_bytes(256);
    assert!(rsa_issuer_with(&n, &[1, 0, 0, 0, 0]).validate().is_err());
    assert!(rsa_issuer_with(&n, &[0xff; 8]).validate().is_err());
}

#[test]
fn validate_rejects_an_even_rsa_exponent() {
    let n = random_bytes(256);
    assert!(rsa_issuer_with(&n, &[1, 0, 0]).validate().is_err());
    assert!(rsa_issuer_with(&n, &[4]).validate().is_err());
}

#[test]
fn validate_rejects_rsa_exponents_one_and_zero_and_empty() {
    let n = random_bytes(256);
    assert!(rsa_issuer_with(&n, &[1]).validate().is_err());
    assert!(rsa_issuer_with(&n, &[0]).validate().is_err());
    assert!(rsa_issuer_with(&n, &[]).validate().is_err());
}

#[test]
fn validate_accepts_rsa_exponents_3_and_65537() {
    let n = random_bytes(256);
    assert_eq!(rsa_issuer_with(&n, &[3]).validate(), Ok(()));
    assert_eq!(rsa_issuer_with(&n, &[1, 0, 1]).validate(), Ok(()));
}

#[test]
fn validate_rejects_an_ec_key_with_a_wrong_size_x() {
    let good = es256("e");
    let mut bad = good.jwk.clone();
    bad["x"] = json!(b64(&random_bytes(31)));
    let mut iss = issuer(vec![JwtAlg::Es256], &[&good]);
    assert_eq!(iss.validate(), Ok(()));
    iss.jwks = jwks_of(&[bad]);
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_an_ec_key_with_a_wrong_size_y_or_unknown_curve() {
    let good = es256("e");
    let mut short_y = good.jwk.clone();
    short_y["y"] = json!(b64(&random_bytes(48)));
    let mut bad_curve = good.jwk.clone();
    bad_curve["crv"] = json!("P-521");
    let mut iss = issuer(vec![JwtAlg::Es256], &[&good]);
    iss.jwks = jwks_of(&[short_y]);
    assert!(iss.validate().is_err());
    iss.jwks = jwks_of(&[bad_curve]);
    assert!(iss.validate().is_err());
}

#[test]
fn validate_rejects_a_jwks_over_256_kib() {
    let (mut iss, _) = simple();
    let base_len = iss.jwks.len();
    iss.jwks.push_str(&" ".repeat(MAX_JWKS_BYTES));
    assert!(iss.jwks.len() > MAX_JWKS_BYTES);
    assert!(base_len < MAX_JWKS_BYTES);
    assert!(iss.validate().is_err());
}

// ---------------------------------------------------------------------
// 10. WorkloadConfig
// ---------------------------------------------------------------------

const ISS_A: &str = "https://a.test";
const ISS_B: &str = "https://b.test";

struct World {
    config: WorkloadConfig,
    key_a: TestKey,
    key_b: TestKey,
}

fn bind(issuer: &str, subject: &str, service: &str) -> Binding {
    Binding {
        issuer: issuer.into(),
        subject: subject.into(),
        service: service.into(),
    }
}

fn world() -> World {
    let key_a = es256("ka");
    let key_b = es384("kb");
    let mut config = WorkloadConfig::default();
    config.issuers.insert(
        "a".into(),
        issuer_for(ISS_A, vec![JwtAlg::Es256], &[&key_a]),
    );
    config.issuers.insert(
        "b".into(),
        issuer_for(ISS_B, vec![JwtAlg::Es384], &[&key_b]),
    );
    config
        .bindings
        .insert("pay-a".into(), bind("a", SUB, "payments"));
    config
        .bindings
        .insert("web-b".into(), bind("b", "repo:acme/app", "web"));
    World {
        config,
        key_a,
        key_b,
    }
}

fn token_a(w: &World, sub: &str) -> String {
    token_with(&w.key_a, &claims_for(ISS_A, sub))
}

fn token_b(w: &World, sub: &str) -> String {
    token_with(&w.key_b, &claims_for(ISS_B, sub))
}

#[test]
fn workload_config_validates() {
    assert_eq!(world().config.validate(), Ok(()));
}

#[test]
fn authenticate_finds_the_right_issuer_among_two() {
    let w = world();
    let claims = claims_for(ISS_A, SUB);
    let exp = claims["exp"].as_i64().unwrap();
    let p = w
        .config
        .authenticate(&token_with(&w.key_a, &claims))
        .unwrap();
    assert_eq!(
        p,
        Principal {
            service: "payments".into(),
            subject: SUB.into(),
            issuer: "a".into(),
            binding: "pay-a".into(),
            expires_at: exp,
        }
    );

    let p = w
        .config
        .authenticate(&token_b(&w, "repo:acme/app"))
        .unwrap();
    assert_eq!(p.service, "web");
    assert_eq!(p.issuer, "b");
    assert_eq!(p.binding, "web-b");
    assert_eq!(p.subject, "repo:acme/app");
}

#[test]
fn authenticate_rejects_a_token_from_an_unconfigured_issuer() {
    let w = world();
    let stranger = es256("ks");
    let t = token_with(&stranger, &claims_for("https://stranger.test", SUB));
    assert_eq!(w.config.authenticate(&t), Err(Reject::UnknownIssuer));
}

#[test]
fn authenticate_rejects_a_verified_token_whose_subject_is_not_bound() {
    let w = world();
    assert_eq!(
        w.config
            .authenticate(&token_a(&w, "system:serviceaccount:other:thing")),
        Err(Reject::NoBinding)
    );
}

#[test]
fn authenticate_does_not_trust_a_token_naming_a_known_issuer_but_signed_by_another_key() {
    let w = world();
    let attacker = es256("ka");
    let t = token_with(&attacker, &claims_for(ISS_A, SUB));
    assert_eq!(w.config.authenticate(&t), Err(Reject::BadSignature));
}

#[test]
fn binding_matches_the_subject_exactly() {
    let w = world();
    assert!(w.config.authenticate(&token_a(&w, SUB)).is_ok());
    for sub in [
        "system:serviceaccount:ns:sa2",
        "system:serviceaccount:ns:s",
        "System:ServiceAccount:ns:sa",
        "SYSTEM:SERVICEACCOUNT:NS:SA",
        "system:serviceaccount:ns:sa ",
        " system:serviceaccount:ns:sa",
        "system:serviceaccount:ns:sa*",
        "system:serviceaccount:ns:sa\n",
        "system:serviceaccount:ns:",
        "system:serviceaccount:ns",
    ] {
        assert_eq!(
            w.config.authenticate(&token_a(&w, sub)),
            Err(Reject::NoBinding),
            "subject {sub:?}"
        );
    }
}

#[test]
fn a_binding_with_a_wildcard_character_is_only_a_literal() {
    let mut w = world();
    w.config.bindings.insert(
        "star".into(),
        bind("a", "system:serviceaccount:ns:team-*", "star"),
    );
    assert_eq!(w.config.validate(), Ok(()));
    for sub in [
        "system:serviceaccount:ns:team-",
        "system:serviceaccount:ns:team-x",
        "system:serviceaccount:ns:team-*x",
    ] {
        assert_eq!(
            w.config.authenticate(&token_a(&w, sub)),
            Err(Reject::NoBinding),
            "subject {sub:?}"
        );
    }
    let p = w
        .config
        .authenticate(&token_a(&w, "system:serviceaccount:ns:team-*"))
        .unwrap();
    assert_eq!(p.service, "star");
}

#[test]
fn a_subject_bound_under_one_issuer_is_not_honoured_for_another() {
    let w = world();
    // Control: issuer a's own token with this subject is accepted.
    assert!(w.config.authenticate(&token_a(&w, SUB)).is_ok());
    // The same subject from issuer b is not bound.
    assert_eq!(
        w.config.authenticate(&token_b(&w, SUB)),
        Err(Reject::NoBinding)
    );
    // And the other way around.
    assert!(w.config.authenticate(&token_b(&w, "repo:acme/app")).is_ok());
    assert_eq!(
        w.config.authenticate(&token_a(&w, "repo:acme/app")),
        Err(Reject::NoBinding)
    );
}

#[test]
fn binding_for_looks_up_by_issuer_name_and_exact_subject() {
    let w = world();
    let (name, b) = w.config.binding_for("a", SUB).unwrap();
    assert_eq!(name, "pay-a");
    assert_eq!(b.service, "payments");
    assert!(w.config.binding_for("b", SUB).is_none());
    assert!(w
        .config
        .binding_for("a", "system:serviceaccount:ns:SA")
        .is_none());
    assert!(w.config.binding_for("A", SUB).is_none());
}

#[test]
fn config_validate_rejects_two_issuers_with_the_same_iss() {
    let mut w = world();
    let key = es256("kc");
    w.config
        .issuers
        .insert("c".into(), issuer_for(ISS_A, vec![JwtAlg::Es256], &[&key]));
    assert!(w.config.validate().is_err());
}

#[test]
fn config_validate_rejects_a_binding_naming_an_unknown_issuer() {
    let mut w = world();
    w.config
        .bindings
        .insert("ghost".into(), bind("nope", "someone", "svc"));
    assert!(w.config.validate().is_err());
}

#[test]
fn config_validate_rejects_the_same_issuer_and_subject_bound_twice() {
    let mut w = world();
    w.config
        .bindings
        .insert("pay-a-again".into(), bind("a", SUB, "other-service"));
    assert!(w.config.validate().is_err());
}

#[test]
fn config_validate_allows_the_same_subject_under_different_issuers() {
    let mut w = world();
    w.config
        .bindings
        .insert("pay-b".into(), bind("b", SUB, "payments"));
    assert_eq!(w.config.validate(), Ok(()));
}

#[test]
fn config_validate_rejects_an_empty_subject() {
    let mut w = world();
    w.config
        .bindings
        .insert("empty".into(), bind("a", "", "svc"));
    assert!(w.config.validate().is_err());
}

#[test]
fn config_validate_rejects_an_invalid_issuer() {
    let mut w = world();
    w.config.issuers.get_mut("a").unwrap().audience = String::new();
    assert!(w.config.validate().is_err());
}

#[test]
fn config_round_trips_through_bincode_unchanged() {
    let w = world();
    let bytes = bincode::serialize(&w.config).unwrap();
    let back: WorkloadConfig = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back, w.config);
    assert_eq!(back.validate(), Ok(()));
    // The restored config still authenticates.
    assert!(back.authenticate(&token_a(&w, SUB)).is_ok());
}

// ---------------------------------------------------------------------
// 11. The iss claim when picking an issuer
// ---------------------------------------------------------------------

#[test]
fn authenticate_rejects_a_token_whose_iss_is_not_a_string() {
    let w = world();
    for bad in [
        json!(123),
        json!(["https://a.test"]),
        json!(null),
        json!({"a": 1}),
    ] {
        let c = claims_with(|c| {
            c.insert("iss".into(), bad.clone());
        });
        assert_eq!(
            w.config.authenticate(&token_with(&w.key_a, &c)),
            Err(Reject::Malformed),
            "iss {bad}"
        );
    }
}

#[test]
fn authenticate_rejects_a_token_without_an_iss_claim() {
    let w = world();
    let c = claims_with(|c| {
        c.remove("iss");
    });
    assert_eq!(
        w.config.authenticate(&token_with(&w.key_a, &c)),
        Err(Reject::Malformed)
    );
}

#[test]
fn authenticate_rejects_garbage_and_oversized_tokens() {
    let w = world();
    assert_eq!(w.config.authenticate(""), Err(Reject::Malformed));
    assert_eq!(w.config.authenticate("a.b.c"), Err(Reject::Malformed));
    assert_eq!(
        w.config.authenticate(&"a".repeat(MAX_TOKEN_BYTES + 1)),
        Err(Reject::TooLarge)
    );
}
