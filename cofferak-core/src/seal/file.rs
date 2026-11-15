//! `HostSeal` backend for hosts with no sealing facility of their own: the
//! key is a file that something else protects and delivers (ADR 0020).
//!
//! The intended case is a container: the key is a Kubernetes Secret
//! mounted into the pod, or a file an external agent writes to a tmpfs.
//! [`FileSeal::seal`] writes the raw 32-byte key to `path`,
//! [`FileSeal::unseal`] reads it back. Like the macOS backend, the
//! [`SealedBlob`] is only a marker, the key itself lives at `path`.
//!
//! This backend does not encrypt the key. It is exactly as safe as the
//! place the file lives in: for a Kubernetes Secret, that is the cluster's
//! etcd encryption and its RBAC. Where the platform offers a real sealing
//! facility (systemd-creds, the Keychain, a cloud KMS), prefer that.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use super::{HostSeal, SealError, SealedBlob};

const SEALED_MARKER: &[u8] = b"cofferak-file-seal-v1";

/// A [`HostSeal`] backend that keeps the key in the file at `path`.
pub struct FileSeal {
    pub path: PathBuf,
}

impl HostSeal for FileSeal {
    /// Write `key` to `path`, mode 0600. Refuses to replace an existing
    /// file: an existing key file belongs to a host that is already
    /// enrolled, and overwriting it would lock that host out.
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    SealError::Invalid(format!(
                        "{} already exists, refusing to overwrite a host key",
                        self.path.display()
                    ))
                } else {
                    SealError::Invalid(format!(
                        "could not create host key file {}: {e}",
                        self.path.display()
                    ))
                }
            })?;
        file.write_all(key)?;
        file.sync_all()?;
        Ok(SealedBlob(SEALED_MARKER.to_vec()))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0 != SEALED_MARKER {
            return Err(SealError::Invalid(
                "this host's key was not sealed with the file backend".into(),
            ));
        }
        let bytes = zeroize::Zeroizing::new(std::fs::read(&self.path).map_err(|e| {
            SealError::Invalid(format!(
                "could not read host key file {}: {e}",
                self.path.display()
            ))
        })?);
        bytes.as_slice().try_into().map_err(|_| {
            SealError::Invalid(format!(
                "host key file {} is {} bytes, expected 32",
                self.path.display(),
                bytes.len()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cofferak-file-seal-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn round_trips_and_writes_a_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let seal = FileSeal {
            path: temp_path("roundtrip"),
        };
        let key = [0x5A; 32];
        let blob = seal.seal(&key).unwrap();
        assert!(!blob.0.windows(4).any(|w| w == [0x5A; 4]), "no key in blob");
        assert_eq!(seal.unseal(&blob).unwrap(), key);
        let mode = std::fs::metadata(&seal.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&seal.path);
    }

    #[test]
    fn never_overwrites_an_existing_key() {
        let seal = FileSeal {
            path: temp_path("exists"),
        };
        seal.seal(&[1; 32]).unwrap();
        assert!(matches!(seal.seal(&[2; 32]), Err(SealError::Invalid(_))));
        assert_eq!(
            std::fs::read(&seal.path).unwrap(),
            vec![1; 32],
            "the first key must be untouched"
        );
        let _ = std::fs::remove_file(&seal.path);
    }

    #[test]
    fn rejects_a_foreign_blob_a_missing_file_and_a_wrong_size() {
        let seal = FileSeal {
            path: temp_path("reject"),
        };
        let blob = SealedBlob(SEALED_MARKER.to_vec());
        assert!(seal.unseal(&blob).is_err(), "missing file");
        std::fs::write(&seal.path, [7u8; 31]).unwrap();
        assert!(seal.unseal(&blob).is_err(), "wrong size");
        std::fs::write(&seal.path, [7u8; 32]).unwrap();
        assert!(seal
            .unseal(&SealedBlob(b"something else".to_vec()))
            .is_err());
        assert_eq!(seal.unseal(&blob).unwrap(), [7u8; 32]);
        let _ = std::fs::remove_file(&seal.path);
    }
}
