# ADR 0020: Seal backends chosen at run time: a key file and Google Cloud KMS

Status: accepted. Amends [ADR 0003](0003-no-external-vault-dependency.md).

## Context

A host's unseal key is sealed by the operating system: `systemd-creds`
and the TPM2 on Linux, the Keychain on macOS (ADR 0002, ADR 0009). The
backend was fixed when cofferak was built.

A container has neither. A pod has no TPM of its own, no systemd and no
Keychain, so `cofferakd` could not start in one. That blocks the first
step of the Kubernetes roadmap (ADR 0014, phase 1).

ADR 0003 ruled out calling a cloud KMS. That was right for the
single-host case and stays the default. For a pod, though, the realistic
choices are a key in a Kubernetes Secret or a key sealed by the cloud's
KMS, and the second is the stronger one: nothing in the cluster holds a
key that opens the vault.

## Decision

`$COFFERAK_SEAL` chooses the backend when the process starts. The daemon
and the CLI both choose through one function
(`cofferak_core::seal::configured_seal`), so they cannot disagree about
where a host's key lives.

| `COFFERAK_SEAL` | Where the host key lives | Needs |
|---|---|---|
| unset, or `platform` | `systemd-creds` (Linux), Keychain (macOS). Unchanged. | - |
| `file` | A file with the raw 32-byte key | `COFFERAK_HOST_KEY_FILE` |
| `gcp-kms` | Encrypted by a Cloud KMS key, stored in `hosts/<id>.seal` | `COFFERAK_GCP_KMS_KEY`, a build with `--features gcp-kms` |

A chosen backend is the only source of the key. There is no fallback to
another one: a missing key file, an unknown value or a KMS error stops
the daemon at startup with the reason.

### `file`

`init --host` writes the key to `$COFFERAK_HOST_KEY_FILE`, mode 0600, and
refuses to replace an existing file. `{host}` in the path stands for the
host id. `hosts/<id>.seal` holds only a marker, as with the Keychain.

This backend does not encrypt the key. It is exactly as safe as the place
the file lives in. For a Kubernetes Secret that is etcd encryption at rest
and RBAC on the Secret: anyone who can read the Secret and the vault file
can open the vault. Use it for development clusters, or where something
else protects the file (an agent that writes it to a tmpfs).

### `gcp-kms`

`init --host` asks Cloud KMS to encrypt the key. `hosts/<id>.seal` holds
the KMS ciphertext and the name of the KMS key. At startup the daemon
asks KMS to decrypt it.

- **Identity.** The access token of the host's own service account, from
  the metadata server (on GKE: Workload Identity). No credential is
  stored with the vault. On a machine with no metadata server (an
  administrator's laptop running `init --host`), `gcloud auth
  print-access-token` is used.
- **Authorisation** is IAM on the KMS key
  (`roles/cloudkms.cryptoKeyEncrypterDecrypter`, or only the decrypter
  role for the daemon), and every unseal is in Cloud Audit Logs.
- **Binding.** The ciphertext carries the host id as additional
  authenticated data, so a blob sealed for one host does not unseal as
  another. Unsealing with a different KMS key than the one named in the
  blob is refused before any call is made.
- **Scope.** KMS is called once, at startup (and by admin commands that
  need the host key). It is never on the request path, so reads stay as
  fast as before and keep working if KMS is unreachable later.
- **Transport.** HTTPS to `cloudkms.googleapis.com` with `rustls` on
  AWS-LC, the same stack as server mode, trusting the public web roots.
  `$COFFERAK_GCP_KMS_ENDPOINT` points at a private endpoint, it must be
  `https` unless it is on the loopback interface.
- **Build.** Behind the `gcp-kms` cargo feature, off by default. A plain
  build contains no HTTP client and makes no network calls, as ADR 0003
  promised.

## What changes in ADR 0003

"cofferak does not call a cloud KMS" becomes: cofferak does not call a
cloud KMS **unless you build it in and turn it on**. The default build,
the default configuration, and every deployment that exists today are
unchanged. Secrets are still encrypted and decrypted only by cofferak
itself: KMS wraps one 32-byte host key and never sees a secret or the
data encryption key.

## Proof

- `cofferak-core/src/seal/file.rs` tests: round trip, mode 0600, never
  overwrites, rejects a foreign blob, a missing file and a wrong size.
- `cofferak-core/tests/seal_gcp_kms.rs` (feature `gcp-kms`), against an
  in-process fake of the metadata server and KMS: round trip, host
  binding, key-name mismatch refused without a call, tampered and foreign
  blobs, a KMS permission error reported with its reason, no identity,
  a wrong-size answer, and validation of key names and endpoints.
- `scripts/seal-backends-check.sh`, in CI on Linux and macOS: the real
  `cofferak` and `cofferakd` with both backends (KMS against
  `scripts/fake-gcp-kms.py`), restart durability, a second host, and every
  misconfiguration refused at startup.

Not proved here: a successful call to the real Cloud KMS. During
development `init --host` was pointed at `cloudkms.googleapis.com` with a
made-up token, and Google answered `401 UNAUTHENTICATED` in its usual
JSON, which shows that the TLS setup and the request reach the real API
and that its errors are reported. An encrypt and decrypt with real
credentials has not been run, and no test in this repository talks to
Google. Run `init --host` against a real key before relying on it.

## Consequences

- `cofferakd` can run in a container. The Helm chart and image (ADR 0014,
  phase 1) build on this.
- With `gcp-kms`, starting the daemon depends on Cloud KMS and IAM being
  reachable. A running daemon does not.
- Other clouds' KMS services fit the same trait and the same variable.
  None is implemented.
- On macOS a backend chosen with `$COFFERAK_SEAL` is not gated by Touch
  ID: that check belongs to the Keychain backend.
