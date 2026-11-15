//! `cofferak workload ...`: which identity providers are trusted and which
//! workload (by its exact token subject) acts as which service (ADR 0022).
//!
//! The configuration is one [`WorkloadConfig`] stored encrypted in the
//! vault. Every command here reads it, changes it, validates the whole
//! thing and writes it back sealed, under the same vault lock, integrity
//! check and anchor update as every other admin command. The running
//! daemon picks the change up without a restart.

use std::path::Path;

use cofferak_core::crypto::{decrypt_entry, encrypt_entry, Aad};
use cofferak_core::format::VaultFile;
use cofferak_core::seal::HostSeal;
use cofferak_core::workload::{Binding, Issuer, JwtAlg, WorkloadConfig};
use zeroize::Zeroizing;

use super::init::CliError;
use super::transfer::{open_vault, save_vault};

fn invalid(msg: impl Into<String>) -> CliError {
    CliError::Invalid(msg.into())
}

/// A change to the workload configuration.
#[derive(Debug, Clone)]
pub enum Change {
    /// Trust an identity provider. `replace` allows overwriting an issuer
    /// of the same name.
    AddIssuer {
        name: String,
        issuer: String,
        audience: String,
        algorithms: Vec<JwtAlg>,
        jwks: String,
        leeway_secs: u64,
        max_ttl_secs: u64,
        replace: bool,
    },
    /// Replace an issuer's public keys (the provider rotated them).
    UpdateJwks {
        name: String,
        jwks: String,
    },
    /// Stop trusting an issuer, and drop every binding that named it.
    RmIssuer {
        name: String,
    },
    /// Let the workload with this exact subject act as a service.
    Bind {
        name: String,
        issuer: String,
        subject: String,
        service: String,
    },
    Unbind {
        name: String,
    },
}

/// What a change did, for the command to report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Bindings removed together with their issuer.
    pub dropped_bindings: Vec<String>,
}

fn decrypt_config(vault: &VaultFile, dek: &[u8; 32]) -> Result<WorkloadConfig, CliError> {
    let Some(entry) = &vault.workload else {
        return Ok(WorkloadConfig::default());
    };
    let plain = Zeroizing::new(
        decrypt_entry(dek, &Aad::workload(), entry)
            .map_err(|e| invalid(format!("could not decrypt the workload configuration: {e}")))?,
    );
    bincode::deserialize(&plain)
        .map_err(|e| invalid(format!("the workload configuration is damaged: {e}")))
}

/// The current configuration.
pub fn run_list_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<WorkloadConfig, CliError> {
    let (vault, dek) = open_vault(data_dir, host_id, seal)?;
    decrypt_config(&vault, &dek)
}

/// Apply `change` and write the vault.
pub fn run_change_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    change: Change,
) -> Result<Outcome, CliError> {
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    let mut config = decrypt_config(&vault, &dek)?;
    let mut outcome = Outcome::default();

    match change {
        Change::AddIssuer {
            name,
            issuer,
            audience,
            algorithms,
            jwks,
            leeway_secs,
            max_ttl_secs,
            replace,
        } => {
            if config.issuers.contains_key(&name) && !replace {
                return Err(invalid(format!(
                    "an issuer named {name} already exists (use --replace to overwrite it, or `workload update-jwks` to rotate its keys)"
                )));
            }
            let mut algorithms = algorithms;
            algorithms.sort();
            algorithms.dedup();
            config.issuers.insert(
                name,
                Issuer {
                    issuer,
                    audience,
                    algorithms,
                    jwks,
                    leeway_secs,
                    max_ttl_secs,
                },
            );
        }
        Change::UpdateJwks { name, jwks } => {
            let issuer = config
                .issuers
                .get_mut(&name)
                .ok_or_else(|| invalid(format!("no issuer named {name}")))?;
            issuer.jwks = jwks;
        }
        Change::RmIssuer { name } => {
            if config.issuers.remove(&name).is_none() {
                return Err(invalid(format!("no issuer named {name}")));
            }
            let dropped: Vec<String> = config
                .bindings
                .iter()
                .filter(|(_, b)| b.issuer == name)
                .map(|(n, _)| n.clone())
                .collect();
            for n in &dropped {
                config.bindings.remove(n);
            }
            outcome.dropped_bindings = dropped;
        }
        Change::Bind {
            name,
            issuer,
            subject,
            service,
        } => {
            if !vault.services.contains_key(&service) {
                return Err(invalid(format!(
                    "no service named {service}: enroll it first with `cofferak enroll-service {service} --paths ... --perm ...`"
                )));
            }
            if config.bindings.contains_key(&name) {
                return Err(invalid(format!("a binding named {name} already exists")));
            }
            config.bindings.insert(
                name,
                Binding {
                    issuer,
                    subject,
                    service,
                },
            );
        }
        Change::Unbind { name } => {
            if config.bindings.remove(&name).is_none() {
                return Err(invalid(format!("no binding named {name}")));
            }
        }
    }

    config.validate().map_err(invalid)?;
    let plain = Zeroizing::new(
        bincode::serialize(&config).map_err(|e| invalid(format!("could not encode: {e}")))?,
    );
    vault.workload = Some(encrypt_entry(&dek, &Aad::workload(), &plain));
    save_vault(data_dir, host_id, &mut vault, &dek)?;
    Ok(outcome)
}
