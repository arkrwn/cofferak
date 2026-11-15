//! Workload identities (ADR 0022): let a program prove who it is with a
//! signed token from an identity provider it already has, instead of a
//! static secret handed to it in advance.
//!
//! The token is a JWT: a Kubernetes projected ServiceAccount token, a
//! GitHub Actions or GitLab CI identity token, a Google-signed identity
//! token. An administrator tells cofferak which **issuers** to trust (the
//! `iss` value, the one `aud` that must be named in the token, which
//! signature algorithms are allowed, and the issuer's public keys as a
//! JWKS), and **binds** one exact token subject to one service. A token
//! that verifies and whose subject is bound runs with that service's
//! prefixes and permission, exactly as if it had presented the service's
//! own token.
//!
//! Verification is offline, against the keys stored in the vault. What is
//! checked, in this order, and why:
//!
//! - the token is at most [`MAX_TOKEN_BYTES`] and has exactly three parts
//! - its `iss` names a configured issuer (only used to choose which
//!   issuer's keys to verify against, then checked again by the signature
//!   verification below)
//! - its `alg` is one of the algorithms **that issuer** allows, only
//!   asymmetric ones exist here (`RS256`, `ES256`, `ES384`): `none` and
//!   the HMAC family cannot be configured, so key confusion between RSA
//!   and HMAC is impossible by construction
//! - the key is chosen by `kid` among that issuer's keys only, never from
//!   a URL or a key embedded in the token, the key type and curve must fit
//!   the algorithm, an RSA key must be 2048 to 8192 bits with a small
//!   public exponent
//! - the signature, `exp` (required), `nbf`, `iss` and `aud` (exact match
//!   with the configured one, as a string or one entry of an array), `sub`
//!   (required), and that the token does not stay valid longer than the
//!   issuer's `max_ttl_secs`
//! - only then the subject is looked up among the bindings, by exact
//!   comparison

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Largest token accepted. Kubernetes and CI tokens are well under 4 KiB.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest JWKS accepted when an issuer is configured.
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Most issuers and most bindings one vault holds.
pub const MAX_ISSUERS: usize = 32;
pub const MAX_BINDINGS: usize = 1024;
/// Default clock leeway for `exp` and `nbf`, in seconds.
pub const DEFAULT_LEEWAY_SECS: u64 = 30;
/// Default longest remaining validity of an accepted token: one day.
pub const DEFAULT_MAX_TTL_SECS: u64 = 86_400;

/// A signature algorithm an issuer may be configured with. Only asymmetric
/// ones: there is no way to configure `none` or an HMAC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JwtAlg {
    Rs256,
    Es256,
    Es384,
}

impl JwtAlg {
    /// The name used in a token header and on the command line.
    pub fn name(self) -> &'static str {
        match self {
            JwtAlg::Rs256 => "RS256",
            JwtAlg::Es256 => "ES256",
            JwtAlg::Es384 => "ES384",
        }
    }

    pub fn parse(name: &str) -> Option<JwtAlg> {
        match name {
            "RS256" => Some(JwtAlg::Rs256),
            "ES256" => Some(JwtAlg::Es256),
            "ES384" => Some(JwtAlg::Es384),
            _ => None,
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            JwtAlg::Rs256 => Algorithm::RS256,
            JwtAlg::Es256 => Algorithm::ES256,
            JwtAlg::Es384 => Algorithm::ES384,
        }
    }

    fn from_algorithm(a: Algorithm) -> Option<JwtAlg> {
        match a {
            Algorithm::RS256 => Some(JwtAlg::Rs256),
            Algorithm::ES256 => Some(JwtAlg::Es256),
            Algorithm::ES384 => Some(JwtAlg::Es384),
            _ => None,
        }
    }

    fn curve(self) -> Option<&'static str> {
        match self {
            JwtAlg::Rs256 => None,
            JwtAlg::Es256 => Some("P-256"),
            JwtAlg::Es384 => Some("P-384"),
        }
    }
}

/// An identity provider whose tokens are trusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issuer {
    /// The exact `iss` value of its tokens.
    pub issuer: String,
    /// The one audience tokens must be issued for. Use a value that means
    /// "cofferak" (`cofferak`, or this deployment's URL), never a shared
    /// one like the issuer's own URL.
    pub audience: String,
    /// The algorithms a token's header may name.
    pub algorithms: Vec<JwtAlg>,
    /// The issuer's public keys, a JWKS document (RFC 7517).
    pub jwks: String,
    /// Clock leeway for `exp` and `nbf`.
    pub leeway_secs: u64,
    /// Longest remaining validity of an accepted token.
    pub max_ttl_secs: u64,
}

/// One exact token subject allowed to act as one service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Name of the issuer (its key in [`WorkloadConfig::issuers`]).
    pub issuer: String,
    /// The exact `sub` value, for example
    /// `system:serviceaccount:payments:api` or
    /// `repo:acme/app:ref:refs/heads/main`. No patterns.
    pub subject: String,
    /// The service whose paths and permission the workload gets.
    pub service: String,
}

/// All trusted issuers and bindings of a vault.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkloadConfig {
    pub issuers: BTreeMap<String, Issuer>,
    /// By binding name.
    pub bindings: BTreeMap<String, Binding>,
}

/// Why a token was not accepted. The reason goes to the audit log, the
/// client is only ever told "denied".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Malformed,
    TooLarge,
    UnknownIssuer,
    AlgorithmNotAllowed,
    UnknownKey,
    BadSignature,
    Expired,
    NotYetValid,
    ValidForTooLong,
    WrongAudience,
    WrongIssuer,
    MissingClaim,
    NoBinding,
}

impl Reject {
    /// Short fixed text for the audit log.
    pub fn reason(self) -> &'static str {
        match self {
            Reject::Malformed => "malformed token",
            Reject::TooLarge => "token too large",
            Reject::UnknownIssuer => "unknown issuer",
            Reject::AlgorithmNotAllowed => "algorithm not allowed",
            Reject::UnknownKey => "unknown signing key",
            Reject::BadSignature => "bad signature",
            Reject::Expired => "token expired",
            Reject::NotYetValid => "token not yet valid",
            Reject::ValidForTooLong => "token valid for too long",
            Reject::WrongAudience => "wrong audience",
            Reject::WrongIssuer => "wrong issuer",
            Reject::MissingClaim => "missing claim",
            Reject::NoBinding => "subject is not bound",
        }
    }
}

/// A token that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub subject: String,
    /// `exp`, Unix seconds.
    pub expires_at: i64,
}

/// A verified workload and the service it acts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub service: String,
    pub subject: String,
    /// Name of the issuer that signed the token.
    pub issuer: String,
    /// Name of the binding that matched.
    pub binding: String,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

fn parse_jwks(text: &str) -> Result<Jwks, String> {
    if text.len() > MAX_JWKS_BYTES {
        return Err(format!("the JWKS is larger than {MAX_JWKS_BYTES} bytes"));
    }
    serde_json::from_str(text).map_err(|e| format!("the JWKS is not valid JSON: {e}"))
}

/// The `kid` of every key in a JWKS (`-` for a key without one), for
/// showing an administrator which keys are configured.
pub fn key_ids(jwks: &str) -> Vec<String> {
    match parse_jwks(jwks) {
        Ok(j) => j
            .keys
            .iter()
            .map(|k| k.kid.clone().unwrap_or_else(|| "-".to_string()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Check one key's parameters for what a signature check needs. An RSA key
/// must have a 2048 to 8192 bit modulus and a public exponent of at least
/// 3, odd and below 2^32, an EC key a point of the right size for its
/// curve.
fn check_key(jwk: &Jwk) -> Result<(), String> {
    let dec = |what: &str, v: &Option<String>| -> Result<Vec<u8>, String> {
        let text = v.as_deref().ok_or_else(|| format!("key lacks {what}"))?;
        B64URL
            .decode(text)
            .map_err(|_| format!("key {what} is not unpadded base64url"))
    };
    match jwk.kty.as_str() {
        "RSA" => {
            let n = dec("n", &jwk.n)?;
            let e = dec("e", &jwk.e)?;
            let n_len = n.iter().skip_while(|b| **b == 0).count();
            if !(256..=1024).contains(&n_len) {
                return Err("an RSA key must be 2048 to 8192 bits".into());
            }
            let e_trim: Vec<u8> = e.iter().copied().skip_while(|b| *b == 0).collect();
            if e_trim.is_empty() || e_trim.len() > 4 {
                return Err("an RSA public exponent must be below 2^32".into());
            }
            let value = e_trim.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
            if value < 3 || value % 2 == 0 {
                return Err("an RSA public exponent must be odd and at least 3".into());
            }
            Ok(())
        }
        "EC" => {
            let size = match jwk.crv.as_deref() {
                Some("P-256") => 32,
                Some("P-384") => 48,
                _ => return Err("an EC key must use the curve P-256 or P-384".into()),
            };
            let x = dec("x", &jwk.x)?;
            let y = dec("y", &jwk.y)?;
            if x.len() != size || y.len() != size {
                return Err("an EC key's x and y must be exactly the curve's size".into());
            }
            Ok(())
        }
        other => Err(format!("unsupported key type {other:?}")),
    }
}

impl Issuer {
    /// Check that this configuration can work: the strings are set, at
    /// least one algorithm is allowed, and the JWKS is valid and holds at
    /// least one key usable with an allowed algorithm. An administrator
    /// finds out when adding an issuer, not on the first login.
    pub fn validate(&self) -> Result<(), String> {
        if self.issuer.is_empty() || self.issuer.len() > 512 {
            return Err("the issuer (iss) must be 1 to 512 characters".into());
        }
        if self.audience.is_empty() || self.audience.len() > 512 {
            return Err("the audience must be 1 to 512 characters".into());
        }
        if self.algorithms.is_empty() {
            return Err("at least one signature algorithm must be allowed".into());
        }
        if self.max_ttl_secs == 0 || self.leeway_secs > 300 {
            return Err("max_ttl_secs must be positive and the leeway at most 300".into());
        }
        let jwks = parse_jwks(&self.jwks)?;
        let mut usable = 0;
        for key in &jwks.keys {
            if key.use_.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            check_key(key).map_err(|e| format!("a key in the JWKS is not usable: {e}"))?;
            let fits = self.algorithms.iter().any(|alg| key_fits(key, *alg));
            if fits {
                usable += 1;
            }
        }
        if usable == 0 {
            return Err(
                "the JWKS holds no signing key that fits an allowed algorithm \
                 (RS256 needs an RSA key, ES256 a P-256 key, ES384 a P-384 key)"
                    .into(),
            );
        }
        Ok(())
    }

    /// Verify `token` against this issuer. Does not look at bindings.
    pub fn verify(&self, token: &str) -> Result<Verified, Reject> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Reject::TooLarge);
        }
        if token.split('.').count() != 3 {
            return Err(Reject::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| Reject::Malformed)?;
        // Anything but a configured algorithm: `none`, HS256 and the rest
        // do not exist for `JwtAlg`, so they can never match.
        let alg = JwtAlg::from_algorithm(header.alg)
            .filter(|a| self.algorithms.contains(a))
            .ok_or(Reject::AlgorithmNotAllowed)?;

        let jwks = parse_jwks(&self.jwks).map_err(|_| Reject::UnknownKey)?;
        let key = select_key(&jwks, header.kid.as_deref(), alg)?;

        let decoding_key = match alg {
            JwtAlg::Rs256 => DecodingKey::from_rsa_components(
                key.n.as_deref().unwrap_or_default(),
                key.e.as_deref().unwrap_or_default(),
            ),
            JwtAlg::Es256 | JwtAlg::Es384 => DecodingKey::from_ec_components(
                key.x.as_deref().unwrap_or_default(),
                key.y.as_deref().unwrap_or_default(),
            ),
        }
        .map_err(|_| Reject::UnknownKey)?;

        let mut validation = Validation::new(alg.algorithm());
        validation.leeway = self.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

        let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|e| map_error(e.kind()))?;
        let claims = data.claims;
        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s.len() <= 1024)
            .ok_or(Reject::MissingClaim)?
            .to_string();
        let expires_at = claims
            .get("exp")
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
            .ok_or(Reject::MissingClaim)?;
        let limit = now_unix()
            .saturating_add(self.max_ttl_secs.min(i64::MAX as u64) as i64)
            .saturating_add(self.leeway_secs as i64);
        if expires_at > limit {
            return Err(Reject::ValidForTooLong);
        }
        Ok(Verified {
            subject,
            expires_at,
        })
    }
}

fn key_fits(key: &Jwk, alg: JwtAlg) -> bool {
    match alg {
        JwtAlg::Rs256 => key.kty == "RSA",
        JwtAlg::Es256 | JwtAlg::Es384 => key.kty == "EC" && key.crv.as_deref() == alg.curve(),
    }
}

/// The key for a token. `kid` must match when the token has one, a token
/// without one is accepted only when exactly one key fits the algorithm.
fn select_key<'a>(jwks: &'a Jwks, kid: Option<&str>, alg: JwtAlg) -> Result<&'a Jwk, Reject> {
    let mut candidates = jwks.keys.iter().filter(|k| {
        k.use_.as_deref().is_none_or(|u| u == "sig")
            && key_fits(k, alg)
            && k.alg.as_deref().is_none_or(|a| a == alg.name())
            && check_key(k).is_ok()
    });
    match kid {
        Some(kid) => candidates
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or(Reject::UnknownKey),
        None => {
            let first = candidates.next().ok_or(Reject::UnknownKey)?;
            if candidates.next().is_some() {
                return Err(Reject::UnknownKey);
            }
            Ok(first)
        }
    }
}

fn map_error(kind: &jsonwebtoken::errors::ErrorKind) -> Reject {
    use jsonwebtoken::errors::ErrorKind as K;
    match kind {
        K::ExpiredSignature => Reject::Expired,
        K::ImmatureSignature => Reject::NotYetValid,
        K::InvalidAudience => Reject::WrongAudience,
        K::InvalidIssuer => Reject::WrongIssuer,
        K::InvalidSignature => Reject::BadSignature,
        K::InvalidAlgorithm | K::InvalidAlgorithmName => Reject::AlgorithmNotAllowed,
        K::MissingRequiredClaim(_) => Reject::MissingClaim,
        K::InvalidKeyFormat | K::InvalidEcdsaKey | K::InvalidRsaKey(_) => Reject::UnknownKey,
        _ => Reject::Malformed,
    }
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The `iss` of a token, read **without** checking anything, only to pick
/// which configured issuer's keys to verify the token against. Nothing
/// taken from the token is trusted until [`Issuer::verify`] succeeds.
fn unverified_issuer(token: &str) -> Option<String> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let payload = token.split('.').nth(1)?;
    let bytes = B64URL.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("iss")?.as_str().map(str::to_string)
}

impl WorkloadConfig {
    /// Whether anything is configured.
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty() && self.bindings.is_empty()
    }

    /// Check the whole configuration: every issuer is valid and their
    /// `iss` values differ, every binding names an existing issuer, and no
    /// subject is bound twice for the same issuer.
    pub fn validate(&self) -> Result<(), String> {
        if self.issuers.len() > MAX_ISSUERS || self.bindings.len() > MAX_BINDINGS {
            return Err("too many issuers or bindings".into());
        }
        let mut seen_iss = std::collections::BTreeSet::new();
        for (name, issuer) in &self.issuers {
            issuer
                .validate()
                .map_err(|e| format!("issuer '{name}': {e}"))?;
            if !seen_iss.insert(issuer.issuer.as_str()) {
                return Err(format!(
                    "issuer '{name}' has the same iss as another issuer, tokens could not be told apart"
                ));
            }
        }
        let mut seen_sub = std::collections::BTreeSet::new();
        for (name, b) in &self.bindings {
            if !self.issuers.contains_key(&b.issuer) {
                return Err(format!(
                    "binding '{name}' names an unknown issuer '{}'",
                    b.issuer
                ));
            }
            if b.subject.is_empty() || b.subject.len() > 1024 {
                return Err(format!(
                    "binding '{name}': the subject must be 1 to 1024 characters"
                ));
            }
            if !seen_sub.insert((b.issuer.as_str(), b.subject.as_str())) {
                return Err(format!(
                    "binding '{name}': that subject is already bound for issuer '{}'",
                    b.issuer
                ));
            }
        }
        Ok(())
    }

    /// The binding for an exact subject of an issuer, with its name.
    pub fn binding_for(&self, issuer_name: &str, subject: &str) -> Option<(&str, &Binding)> {
        self.bindings
            .iter()
            .find(|(_, b)| b.issuer == issuer_name && b.subject == subject)
            .map(|(name, b)| (name.as_str(), b))
    }

    /// Verify `token` and find the service it acts as.
    pub fn authenticate(&self, token: &str) -> Result<Principal, Reject> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Reject::TooLarge);
        }
        let iss = unverified_issuer(token).ok_or(Reject::Malformed)?;
        let (issuer_name, issuer) = self
            .issuers
            .iter()
            .find(|(_, i)| i.issuer == iss)
            .ok_or(Reject::UnknownIssuer)?;
        let verified = issuer.verify(token)?;
        let (binding_name, binding) = self
            .binding_for(issuer_name, &verified.subject)
            .ok_or(Reject::NoBinding)?;
        Ok(Principal {
            service: binding.service.clone(),
            subject: verified.subject,
            issuer: issuer_name.clone(),
            binding: binding_name.to_string(),
            expires_at: verified.expires_at,
        })
    }
}
