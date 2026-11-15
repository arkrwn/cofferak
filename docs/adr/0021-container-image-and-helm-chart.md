# ADR 0021: Container image, Helm chart and waiting for initialisation

Status: accepted

## Context

ADR 0014 (phase 1) calls for running `cofferakd` as a single-replica
StatefulSet. ADR 0020 gave a pod a way to get its host key without a TPM.
Two things were still missing: something to run, and a way to start on an
empty volume. A pod's volume is empty the first time, and the daemon used
to exit when there was no vault. Under Kubernetes that is a crash loop
with growing back-off delays, in the minutes during which the operator is
about to run `cofferak init`.

## Decision

### Image

`deployment/docker/Dockerfile`, two stages. The build stage is the pinned
Rust toolchain (`rust-toolchain.toml`) with `--locked`. The runtime stage
is `gcr.io/distroless/cc-debian12:nonroot`: no shell, no package manager,
user `65532`. It holds exactly `cofferakd` and `cofferak`, built with the
`gcp-kms` feature so the Cloud KMS backend (ADR 0020) is available.

The entrypoint is the daemon. The CLI is in the same image because admin
commands run inside the pod (`kubectl exec ... cofferak init --root`), as
the same unprivileged user that owns the data. Nothing needs root, no
file is created with another owner.

### Waiting for initialisation

`COFFERAK_WAIT_FOR_INIT=1` makes the daemon wait, once per second, for a
vault with at least one enrolled host instead of exiting, and say what it
waits for (once per change). The chart sets it. It is off by default: a
daemon under systemd should still fail loudly on a machine that was never
initialised. A vault that exists but is damaged is **not** waited for:
that goes straight to the normal startup path, which refuses to start. On
a fresh volume the daemon also creates the data directory with mode 0700,
so `cofferak doctor` is satisfied whatever the umask of the first admin
command.

### Chart

`deployment/helm/cofferak`, one StatefulSet with **one** replica (the
vault is one file with one writer, more replicas would each hold a
different vault, ADR 0014 phase 4 is the way to more).

- Pod and container: `runAsNonRoot`, read-only root filesystem, all
  capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp,
  no service account token mounted (the daemon never talks to the
  Kubernetes API).
- Volumes: the data volume, a second small volume for the rollback anchor
  mirror (ADR 0017) so restoring a snapshot of the data volume alone is
  still detected, an in-memory volume for the socket, and with the `file`
  backend a third volume for the key, kept apart from the vault.
- Seal backend: `gcp-kms` (default) or `file`, chosen with
  `seal.backend`. The chart **refuses to render** for a `gcp-kms` without a
  key, an unknown backend, or TLS without a certificate Secret. A
  configuration that cannot work is an error at `helm install`, not a pod
  that fails later.
- Server mode (mutual TLS 1.3, ADR 0008/0011) is off by default and, when
  on, needs a Secret with the server certificate, key and client CA. A
  token still works only with the certificate of its own service
  (ADR 0017).
- Readiness is `cofferak doctor`, which reads no secret and needs no
  token: the pod is Ready when the vault is initialised and the daemon is
  listening.

Initialisation stays a deliberate, manual step done by a person
(`cofferak init --root` prints the recovery key once, to the terminal of
whoever runs it). The chart does not generate or store it.

## What this does not do

Everything else in ADR 0014 is still open: workload authentication with
ServiceAccount tokens (phase 2), delivery into pods (phase 3), replicas
(phase 4), dynamic secrets (phase 5), and the independent audit (phase 6).
Services still authenticate with their static token, over mutual TLS.
Backups are the volume's snapshots, there is no scheduled `cofferak
backup` in the chart yet.

## Proof

- `cofferakd` unit test: a data directory counts as not initialised
  until a host is enrolled, and a damaged vault is not waited for.
- `scripts/kubernetes-check.sh`, the `kubernetes` job in CI, on a kind
  cluster with the real image and chart:
  - the chart refuses bad settings, with the reason
  - the pod starts on an empty volume, stays not Ready without
    restarting, and says what it waits for
  - it is non-root, read-only, without capabilities
  - `init --root`, `init --host` and `enroll-service` run inside the pod
    and the pod becomes Ready
  - a client outside the cluster, through a port-forward, runs the Python
    SDK's mutual-TLS smoke test with sessions, and a client with no
    certificate is refused
  - deleting the pod brings it back Ready by itself, without a new
    initialisation, and a secret written before is still readable
- By hand while developing, outside Kubernetes: the same image run with
  `docker run --read-only --cap-drop ALL`, through init, readiness and a
  restart.

Not proved: the `gcp-kms` backend inside a pod on GKE with Workload
Identity (ADR 0020 explains what is and is not proved of KMS itself).
