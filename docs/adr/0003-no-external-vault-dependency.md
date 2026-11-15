# ADR 0003: No external vault/KMS dependency

Status: accepted, amended by [ADR 0020](0020-runtime-seal-backends.md)

## Decision

cofferak does not call HashiCorp Vault, a cloud KMS, or any other
network-based secret service. It is a standalone, self-contained process
pair (`cofferakd` + `cofferak` CLI) over a local Unix socket, using only
the host OS's own credential-sealing primitive (ADR 0002) and a local
on-disk file (`vault.cofferak`). (Server mode, ADR 0008, later added an
opt-in TLS listener to the same daemon, mutual TLS only since ADR 0011;
it does not add an external dependency.)

## Consequences

This trades the operational features of a managed vault (clustering,
dynamic secrets, multi-region replication) for zero external
dependencies and a minimal trust boundary: anyone who can read this
repo's code can audit everything the vault does, with nothing to
configure or trust beyond the local OS.

## Amendment (ADR 0020)

This holds for the default build and the default configuration. A build
with the `gcp-kms` feature, started with `COFFERAK_SEAL=gcp-kms`, asks
Google Cloud KMS to unwrap the host's 32-byte unseal key once at startup,
so that the daemon can run where the operating system has nothing to seal
a key with (a container). KMS never sees a secret or the data encryption
key, and it is not on the request path.
