//! `HostSeal` backend that seals the host key with Google Cloud KMS
//! (ADR 0020), for hosts with no TPM or Keychain: a pod on GKE, a Cloud
//! Run service, a Compute Engine VM.
//!
//! [`GcpKmsSeal::seal`] asks KMS to encrypt the key, the [`SealedBlob`] is
//! the KMS ciphertext and is useless without permission to use that KMS
//! key. [`GcpKmsSeal::unseal`] asks KMS to decrypt it. The host proves who
//! it is with the access token of its own service account, taken from the
//! metadata server (on GKE: Workload Identity), so no credential is stored
//! with the vault. Who may unseal is decided by IAM on the KMS key, and
//! every unseal is in Cloud Audit Logs.
//!
//! The ciphertext is bound to the host id as additional authenticated
//! data, so a blob sealed for one host does not unseal as another.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use zeroize::{Zeroize, Zeroizing};

use super::{HostSeal, SealError, SealedBlob};

const SEALED_MARKER: &str = "cofferak-gcp-kms-seal-v1";
const DEFAULT_ENDPOINT: &str = "https://cloudkms.googleapis.com";
const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// Where to find Cloud KMS and the caller's identity.
#[derive(Debug, Clone)]
pub struct GcpKmsConfig {
    /// `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>`.
    pub key_name: String,
    /// Base URL of the Cloud KMS API.
    pub endpoint: String,
    /// Host (and optional port) of the metadata server.
    pub metadata_host: String,
    /// Fall back to `gcloud auth print-access-token` when there is no
    /// metadata server (an administrator's own machine).
    pub allow_gcloud: bool,
}

impl GcpKmsConfig {
    /// Configuration from the environment: `$COFFERAK_GCP_KMS_KEY`
    /// (required), `$COFFERAK_GCP_KMS_ENDPOINT` (optional, for a private
    /// endpoint) and `$GCE_METADATA_HOST` (optional, the variable Google's
    /// own clients read).
    pub fn from_env() -> Result<GcpKmsConfig, SealError> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let key_name = var("COFFERAK_GCP_KMS_KEY").ok_or_else(|| {
            SealError::Invalid(
                "COFFERAK_SEAL=gcp-kms needs $COFFERAK_GCP_KMS_KEY, the key's full name \
                 (projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>)"
                    .into(),
            )
        })?;
        let config = GcpKmsConfig {
            key_name,
            endpoint: var("COFFERAK_GCP_KMS_ENDPOINT").unwrap_or_else(|| DEFAULT_ENDPOINT.into()),
            metadata_host: var("GCE_METADATA_HOST").unwrap_or_else(|| DEFAULT_METADATA_HOST.into()),
            allow_gcloud: true,
        };
        config.validate()?;
        Ok(config)
    }

    /// Refuse a key name that is not exactly a crypto key's resource name
    /// (it becomes part of a URL), and an endpoint that would send the
    /// host key over plain HTTP to anything but this machine.
    pub fn validate(&self) -> Result<(), SealError> {
        let parts: Vec<&str> = self.key_name.split('/').collect();
        let labels = ["projects", "locations", "keyRings", "cryptoKeys"];
        let well_formed = parts.len() == 8
            && labels.iter().enumerate().all(|(i, label)| {
                let id = parts[2 * i + 1];
                parts[2 * i] == *label
                    && !id.is_empty()
                    && id.len() <= 63
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !well_formed {
            return Err(SealError::Invalid(format!(
                "{:?} is not a Cloud KMS key name, expected \
                 projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>",
                self.key_name
            )));
        }
        if !(self.endpoint.starts_with("https://") || self.endpoint_is_loopback()) {
            return Err(SealError::Invalid(format!(
                "Cloud KMS endpoint {:?} must be https",
                self.endpoint
            )));
        }
        Ok(())
    }
}

impl GcpKmsConfig {
    /// A plain-HTTP endpoint on this machine: a local emulator or test.
    fn endpoint_is_loopback(&self) -> bool {
        ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
            .iter()
            .any(|p| self.endpoint.starts_with(p))
    }
}

/// A [`HostSeal`] backend that seals `host_id`'s key with a Cloud KMS key.
pub struct GcpKmsSeal {
    pub config: GcpKmsConfig,
    pub host_id: String,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(serde::Deserialize)]
struct DecryptResponse {
    #[serde(default)]
    plaintext: String,
}

impl GcpKmsSeal {
    fn aad(&self) -> String {
        B64.encode(format!("cofferak/v1/host-key\0{}", self.host_id))
    }

    fn agent(timeout: Duration, use_proxy: bool) -> ureq::Agent {
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::WebPki)
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .tls_config(tls);
        if !use_proxy {
            builder = builder.proxy(None);
        }
        ureq::Agent::new_with_config(builder.build())
    }

    /// An OAuth access token for this host's own identity: from the
    /// metadata server, or, on a machine without one, from `gcloud`.
    fn access_token(&self) -> Result<Zeroizing<String>, SealError> {
        let url = format!(
            "http://{}/computeMetadata/v1/instance/service-accounts/default/token",
            self.config.metadata_host
        );
        // The metadata server is link-local, never reached through a proxy.
        let from_metadata = Self::agent(Duration::from_secs(5), false)
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .call()
            .map_err(|e| e.to_string())
            .and_then(|mut response| {
                if response.status() != 200 {
                    return Err(format!("HTTP {}", response.status().as_u16()));
                }
                response
                    .body_mut()
                    .read_json::<TokenResponse>()
                    .map_err(|e| e.to_string())
            });
        let metadata_error = match from_metadata {
            Ok(token) => return Ok(Zeroizing::new(token.access_token)),
            Err(e) => e,
        };
        if self.config.allow_gcloud {
            if let Ok(out) = std::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .stderr(std::process::Stdio::null())
                .output()
            {
                let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if out.status.success() && !token.is_empty() {
                    return Ok(Zeroizing::new(token));
                }
            }
        }
        Err(SealError::Invalid(format!(
            "no Google Cloud identity: the metadata server at {} did not give a token \
             ({metadata_error}), and `gcloud auth print-access-token` did not either",
            self.config.metadata_host
        )))
    }

    /// POST `body` to the key's `:encrypt` or `:decrypt` method.
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<T, SealError> {
        self.config.validate()?;
        let token = self.access_token()?;
        let url = format!(
            "{}/v1/{}:{method}",
            self.config.endpoint.trim_end_matches('/'),
            self.config.key_name
        );
        // A proxy from the environment is used for the real API, never for
        // an endpoint on this machine.
        let use_proxy = !self.config.endpoint_is_loopback();
        let mut response = Self::agent(Duration::from_secs(20), use_proxy)
            .post(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .send_json(body)
            .map_err(|e| SealError::Invalid(format!("Cloud KMS {method} failed: {e}")))?;
        let status = response.status().as_u16();
        if status != 200 {
            // Google's error body names the cause (permission denied, key
            // disabled, ...) and never contains key material.
            let detail = response.body_mut().read_to_string().unwrap_or_default();
            let detail: String = detail
                .chars()
                .filter(|c| !c.is_control())
                .take(300)
                .collect();
            return Err(SealError::Invalid(format!(
                "Cloud KMS {method} on {} returned HTTP {status}: {detail}",
                self.config.key_name
            )));
        }
        response
            .body_mut()
            .read_json::<T>()
            .map_err(|e| SealError::Invalid(format!("Cloud KMS {method} response: {e}")))
    }
}

impl HostSeal for GcpKmsSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let mut plaintext = B64.encode(key);
        let body = serde_json::json!({
            "plaintext": plaintext,
            "additionalAuthenticatedData": self.aad(),
        });
        plaintext.zeroize();
        let response: Result<EncryptResponse, _> = self.call("encrypt", &body);
        wipe(body);
        let ciphertext = response?.ciphertext;
        if B64.decode(&ciphertext).map_or(true, |c| c.is_empty()) {
            return Err(SealError::Invalid(
                "Cloud KMS encrypt returned no ciphertext".into(),
            ));
        }
        Ok(SealedBlob(
            format!("{SEALED_MARKER}\n{}\n{ciphertext}\n", self.config.key_name).into_bytes(),
        ))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        let not_ours =
            || SealError::Invalid("this host's key was not sealed with the gcp-kms backend".into());
        let text = std::str::from_utf8(&blob.0).map_err(|_| not_ours())?;
        let mut lines = text.lines();
        if lines.next() != Some(SEALED_MARKER) {
            return Err(not_ours());
        }
        let (Some(sealed_with), Some(ciphertext), None) =
            (lines.next(), lines.next(), lines.next())
        else {
            return Err(SealError::Invalid("the sealed host key is damaged".into()));
        };
        if sealed_with != self.config.key_name {
            return Err(SealError::Invalid(format!(
                "this host's key was sealed with {sealed_with}, \
                 but $COFFERAK_GCP_KMS_KEY names {}",
                self.config.key_name
            )));
        }
        let body = serde_json::json!({
            "ciphertext": ciphertext,
            "additionalAuthenticatedData": self.aad(),
        });
        let mut response: DecryptResponse = self.call("decrypt", &body)?;
        let decoded = B64.decode(&response.plaintext).map(Zeroizing::new);
        response.plaintext.zeroize();
        let bytes = decoded
            .map_err(|_| SealError::Invalid("Cloud KMS decrypt returned invalid base64".into()))?;
        bytes.as_slice().try_into().map_err(|_| {
            SealError::Invalid(format!(
                "Cloud KMS decrypt returned {} bytes, expected 32",
                bytes.len()
            ))
        })
    }
}

/// Wipe the strings of a request body that carried key material.
fn wipe(body: serde_json::Value) {
    if let serde_json::Value::Object(map) = body {
        for (_, value) in map {
            if let serde_json::Value::String(mut s) = value {
                s.zeroize();
            }
        }
    }
}
