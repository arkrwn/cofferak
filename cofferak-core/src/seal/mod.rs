//! `HostSeal`: the one platform-dependent abstraction in cofferak.
//!
//! A vault's host key must be stored at rest in a form that is only usable
//! on the machine that sealed it, without cofferak having to invent its own
//! key-wrapping-at-rest scheme per platform. Each OS already ships a
//! facility for exactly this (Linux's `systemd-creds`, macOS's Keychain,
//! ...); `HostSeal` is the trait that lets the rest of cofferak (daemon,
//! CLI) call "seal"/"unseal" without caring which backend is in use.
//!
//! This module (`seal::mod`) defines the trait and its associated types on
//! every platform, since downstream crates need the types to exist even on
//! a platform that implements a different backend. Concrete backends live
//! in platform-gated submodules, e.g. [`linux`] for `systemd-creds`.

use std::fmt;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::SystemdCredsSeal;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{KeychainAnchorMirror, KeychainSeal};

mod file;

pub use file::FileSeal;

#[cfg(feature = "gcp-kms")]
mod gcp_kms;

#[cfg(feature = "gcp-kms")]
pub use gcp_kms::{GcpKmsConfig, GcpKmsSeal};

/// The backend chosen at run time with `$COFFERAK_SEAL` (ADR 0020), or
/// `None` when it is unset or `platform`: then the caller uses the
/// platform's own backend (systemd-creds, the Keychain), as before.
///
/// - `file`: the key is the file `$COFFERAK_HOST_KEY_FILE`. `{host}` in
///   that path stands for the host id, so several hosts can be enrolled
///   from one place.
/// - `gcp-kms`: the key is sealed with the Cloud KMS key
///   `$COFFERAK_GCP_KMS_KEY`. Needs a build with the `gcp-kms` feature.
///
/// The daemon and the CLI both choose through this one function, so they
/// can never disagree about where a host's key lives.
pub fn configured_seal(host_id: &str) -> Result<Option<Box<dyn HostSeal>>, SealError> {
    let choice = std::env::var("COFFERAK_SEAL").unwrap_or_default();
    match choice.as_str() {
        "" | "platform" => Ok(None),
        "file" => {
            let path = std::env::var("COFFERAK_HOST_KEY_FILE")
                .ok()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| {
                    SealError::Invalid(
                        "COFFERAK_SEAL=file needs $COFFERAK_HOST_KEY_FILE, the path of the host key file".into(),
                    )
                })?;
            Ok(Some(Box::new(FileSeal {
                path: path.replace("{host}", host_id).into(),
            })))
        }
        "gcp-kms" => gcp_kms_seal(host_id).map(Some),
        other => Err(SealError::Invalid(format!(
            "unknown $COFFERAK_SEAL {other:?}, expected platform, file or gcp-kms"
        ))),
    }
}

#[cfg(feature = "gcp-kms")]
fn gcp_kms_seal(host_id: &str) -> Result<Box<dyn HostSeal>, SealError> {
    Ok(Box::new(GcpKmsSeal {
        config: GcpKmsConfig::from_env()?,
        host_id: host_id.to_string(),
    }))
}

#[cfg(not(feature = "gcp-kms"))]
fn gcp_kms_seal(_host_id: &str) -> Result<Box<dyn HostSeal>, SealError> {
    Err(SealError::Invalid(
        "this build of cofferak has no Cloud KMS support, build it with `--features gcp-kms`"
            .into(),
    ))
}

/// A backend that fails every call with `message`. Lets a caller that
/// must hand back a `HostSeal` report a configuration error at the point
/// the key is first needed, with the real reason.
pub struct FailingSeal(pub String);

impl HostSeal for FailingSeal {
    fn seal(&self, _key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        Err(SealError::Invalid(self.0.clone()))
    }

    fn unseal(&self, _blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        Err(SealError::Invalid(self.0.clone()))
    }
}

/// An opaque, host-sealed blob produced by a [`HostSeal`] implementation.
///
/// The bytes are only meaningful to the backend (and host) that produced
/// them, callers must treat this as opaque and persist it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBlob(pub Vec<u8>);

/// Errors produced by [`HostSeal`] implementations.
#[derive(Debug)]
pub enum SealError {
    /// The host sealing facility (e.g. the `systemd-creds` binary) could not
    /// be invoked at all on this system - typically because it is not
    /// installed or not on `PATH`.
    Unavailable,
    /// The sealing facility ran but its output cannot be trusted: a
    /// non-zero exit status, empty output, or output that otherwise fails
    /// to decrypt/validate. Carries whatever diagnostic detail the backend
    /// captured (e.g. the subprocess's stderr) - never secret key material,
    /// only the backend's own operational error text - so a caller isn't
    /// left guessing between, say, "wrong name" and "permission denied."
    Invalid(String),
    /// An I/O error occurred while talking to the sealing facility (e.g.
    /// writing to its stdin or reading its stdout).
    Io(std::io::Error),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Unavailable => write!(f, "host seal backend is unavailable"),
            SealError::Invalid(detail) => {
                write!(
                    f,
                    "host seal backend rejected input or produced invalid output: {detail}"
                )
            }
            SealError::Io(e) => write!(f, "I/O error talking to host seal backend: {e}"),
        }
    }
}

impl std::error::Error for SealError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SealError::Io(e) => Some(e),
            SealError::Unavailable | SealError::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for SealError {
    fn from(e: std::io::Error) -> Self {
        SealError::Io(e)
    }
}

/// Seals and unseals a 32-byte key using a host-specific secret-storage
/// facility, so the raw key never needs to be persisted on disk in the
/// clear.
///
/// Implementations must never panic, and must never return `Ok` with
/// garbage/forged key bytes: a corrupted or tampered [`SealedBlob`] must
/// fail with `Err`, not decode into incorrect-but-valid-looking bytes.
pub trait HostSeal {
    /// Seal `key`, producing an opaque blob that only [`unseal`](Self::unseal)
    /// (on this host, with this backend) can recover it from.
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError>;

    /// Recover the original key from a blob produced by [`seal`](Self::seal).
    ///
    /// Returns `Err` for any blob that was not produced by this backend, or
    /// that has been truncated/corrupted/tampered with.
    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError>;
}
