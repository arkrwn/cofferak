# Running cofferak on Kubernetes

A single-replica StatefulSet with persistent storage, from the Helm chart
in [`deployment/helm/cofferak`](https://github.com/arkrwn/cofferak/tree/main/deployment/helm/cofferak)
([ADR 0021](adr/0021-container-image-and-helm-chart.md)).

!!! warning "Read this first"
    This is **phases 1 and 2** of the [Kubernetes roadmap](adr/0014-kubernetes-and-fleet-roadmap.md).
    It gives you a vault in a pod, reachable over mutual TLS, where
    workloads can sign in with their ServiceAccount token
    ([workload identity](workload-identity.md)) or a static token. It does
    not yet give you delivery into pods (an init container or CSI
    driver), replicas, or an independent security audit. The vault is one
    pod: while it restarts, reads fail. If you need those today, keep
    HashiCorp Vault for the cluster.

## What you need

- A cluster with a default `StorageClass` (ReadWriteOnce volumes), and
  `kubectl` and `helm` 3 on your machine.
- The image. Build it from the repository root and push it where your
  cluster can pull it:

  ```bash
  docker build -f deployment/docker/Dockerfile -t YOUR_REGISTRY/cofferak:0.1.0 .
  docker push YOUR_REGISTRY/cofferak:0.1.0
  ```

  The image holds `cofferakd` and the `cofferak` CLI on a distroless base,
  and runs as user 65532.

## On GKE with Cloud KMS (recommended)

The host key is sealed by a Cloud KMS key. Nothing stored in the cluster
can open the vault on its own, IAM on the KMS key decides who may unseal,
and every unseal is in Cloud Audit Logs ([ADR 0020](adr/0020-runtime-seal-backends.md)).

**1. Create the KMS key**

```bash
gcloud kms keyrings create cofferak --location global
gcloud kms keys create host-key --keyring cofferak --location global --purpose encryption
```

**2. A Google service account for the pod, allowed to use only that key**

```bash
gcloud iam service-accounts create cofferak --project YOUR_PROJECT
gcloud kms keys add-iam-policy-binding host-key --keyring cofferak --location global \
  --member "serviceAccount:cofferak@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

**3. Let the pod's Kubernetes service account act as it (Workload Identity)**

```bash
gcloud iam service-accounts add-iam-policy-binding \
  cofferak@YOUR_PROJECT.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:YOUR_PROJECT.svc.id.goog[cofferak/cofferak]"
```

The member is `PROJECT.svc.id.goog[NAMESPACE/KUBERNETES_SERVICE_ACCOUNT]`.
The chart names the service account after the release.

**4. Install**

Save as `values-gke.yaml`:

```yaml
image:
  repository: YOUR_REGISTRY/cofferak
  tag: "0.1.0"
hostId: cofferak-0
seal:
  backend: gcp-kms
  gcpKms:
    key: projects/YOUR_PROJECT/locations/global/keyRings/cofferak/cryptoKeys/host-key
serviceAccount:
  name: cofferak
  annotations:
    iam.gke.io/gcp-service-account: cofferak@YOUR_PROJECT.iam.gserviceaccount.com
```

```bash
kubectl create namespace cofferak
helm install cofferak deployment/helm/cofferak -n cofferak -f values-gke.yaml
```

The pod starts and waits. It stays **not Ready** until the next step, and
its log says so (`kubectl logs -n cofferak cofferak-0`).

**5. Initialise the vault, once**

```bash
kubectl exec -it -n cofferak cofferak-0 -- cofferak init --root
```

This prints the **root private key once**. Copy the whole block into your
offline storage now, it is your recovery key
([key security](key-security.md)). Then:

```bash
kubectl exec -n cofferak cofferak-0 -- cofferak init --host cofferak-0
```

The pod becomes Ready. `init --host` is where the KMS key is first used,
with the pod's own identity: if it fails with a permission error, step 2
or 3 is wrong.

## Giving a service access

Each service gets its own token, limited to the paths you give it:

```bash
kubectl exec -n cofferak cofferak-0 -- \
  cofferak enroll-service myapp --paths myapp --perm rw
```

The token is printed once. Give it to the service as you would any
credential (a Kubernetes Secret, for example), and read secrets with an
[SDK](sdks.md#sessions).

**Or skip the static token:** let the pod sign in with its ServiceAccount
token. Enroll the service with `--identity-only` and bind the
ServiceAccount to it, see [workload identity](workload-identity.md#kubernetes).

## Reaching it from other pods: mutual TLS

Server mode is off by default, so the vault is reachable only inside its
own pod. To let other pods connect, turn on mutual TLS. Create the
certificates ([`scripts/gen-certs.sh`](https://github.com/arkrwn/cofferak/blob/main/scripts/gen-certs.sh),
or your own PKI), with a client certificate **named after the service**
it is for (the token only works with its own service's certificate):

```bash
./scripts/gen-certs.sh ./tls cofferak.cofferak.svc myapp
kubectl create secret generic cofferak-tls -n cofferak \
  --from-file=tls.crt=tls/server.pem --from-file=tls.key=tls/server.key \
  --from-file=ca.crt=tls/ca.pem
```

Add to your values:

```yaml
tls:
  enabled: true
  existingSecret: cofferak-tls
```

and `helm upgrade`. Services then connect to
`cofferak.cofferak.svc:8443` with `server_name` equal to the name in the
server certificate, their client certificate and key, and their token. Use
a session, so the TLS handshake is paid once.

## Without a cloud: a key file (development)

```yaml
seal:
  backend: file
```

The host key is a file on its own volume. It is **not encrypted**: it is
as safe as that volume and the cluster's RBAC. Use it for development and
test clusters, and `gcp-kms` for anything real. The chart's notes warn
about it at install.

## Things to know

- **One replica.** Do not scale the StatefulSet. A second pod would have
  its own, different vault.
- **Back up the volumes.** Use your platform's volume snapshots on the
  data volume. A restored older snapshot is detected as a rollback
  (ADR 0015) and the daemon refuses to start with it, `cofferak
  accept-restore` accepts one on purpose. Keep the anchor volume
  (`persistence.anchor`) enabled, it is what makes restoring only the data
  volume detectable.
- **Upgrades.** `helm upgrade` with a new image tag restarts the pod. The
  vault format is upgraded in place on the first write, older formats are
  read.
- **Loss of the KMS key** (or of the permission to use it) makes the
  vault unopenable by the pod. The root private key from step 5 is the way
  back: [recovery runbook](recovery-runbook.md).
- **While the pod restarts, reads fail** for the few seconds it takes.
  SDK sessions reconnect on their own.

## Settings

Every value is documented in
[`values.yaml`](https://github.com/arkrwn/cofferak/blob/main/deployment/helm/cofferak/values.yaml).
The daemon's own variables are in [Deployment](deployment.md#environment-variables).
