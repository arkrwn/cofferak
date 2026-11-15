# Workload identity

Let a program sign in with the token its platform already gave it, instead
of a static secret you generate and hand over
([ADR 0022](adr/0022-workload-identity.md)).

!!! info "How it works in one paragraph"
    You tell cofferak which identity provider to trust (its issuer name,
    the one audience for cofferak, its public keys) and which exact subject
    acts as which service. The workload sends its token, cofferak checks the
    signature and claims offline against those keys, and the workload gets
    that service's paths and permission, for as long as the token is valid
    and the binding exists.

## Set up, any provider

**1. A service for the workload to act as**, with no token shown (nobody
needs to hold one):

```bash
cofferak enroll-service payments-api --paths payments --perm rw --identity-only
```

**2. Trust the provider.** You need its `iss`, the keys it signs with
(a JWKS document), and an audience that means "cofferak":

```bash
cofferak workload add-issuer k8s \
  --iss "https://ISSUER_URL" \
  --audience cofferak \
  --jwks jwks.json            # or `-` to read standard input
```

Only `RS256`, `ES256` and `ES384` can be allowed (`--alg RS256,ES256`
narrows it), `none` and the HMAC family cannot be configured at all. An
issuer whose keys do not fit an allowed algorithm is refused when you add
it, not on the first login.

**3. Bind one exact subject to the service:**

```bash
cofferak workload bind payments-main \
  --issuer k8s \
  --subject "system:serviceaccount:payments:api" \
  --service payments-api
```

The subject is compared exactly, there are no patterns. Bind each subject
you mean to allow. Check it:

```bash
cofferak workload list
```

A running daemon applies every change without a restart. `workload unbind`
and `rm-issuer` take effect on open sessions at once.

## Kubernetes

**The cluster's issuer and keys** come from the API server (you need
permission to read them, a cluster admin has it):

```bash
kubectl get --raw /.well-known/openid-configuration   # "issuer": ...
kubectl get --raw /openid/v1/jwks > jwks.json
```

On a Kubernetes pod running cofferak with the
[Helm chart](kubernetes.md), run step 2 and 3 inside the pod, passing the
keys on standard input:

```bash
kubectl exec -i -n cofferak cofferak-0 -- cofferak workload add-issuer k8s \
  --iss "ISSUER_FROM_ABOVE" --audience cofferak --jwks - < jwks.json
kubectl exec -n cofferak cofferak-0 -- cofferak workload bind payments-main \
  --issuer k8s --subject "system:serviceaccount:payments:api" --service payments-api
```

**In the workload's pod**, project a token whose audience is cofferak (not
the default one, which any service of the cluster accepts) and keep it
short:

```yaml
spec:
  serviceAccountName: api
  containers:
    - name: app
      volumeMounts:
        - name: cofferak-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: cofferak-token
      projected:
        sources:
          - serviceAccountToken:
              path: cofferak
              audience: cofferak
              expirationSeconds: 3600
```

The kubelet rotates the file before it expires. Give the SDK the file, it
reads it again every time it connects:

```python
from cofferak_sdk import Client

client = Client.connect_tls(addr="cofferak.cofferak.svc:8443", server_name="cofferak.cofferak.svc",
                            ca_cert_path="ca.pem", client_cert_path="api.pem", client_key_path="api.key")
with client.session_jwt_file("/var/run/secrets/tokens/cofferak") as s:
    password = s.get("payments/DB_PASSWORD")
```

```go
s, err := client.SessionJWTFile("/var/run/secrets/tokens/cofferak")
```

```ts
const s = await client.sessionJwtFile("/var/run/secrets/tokens/cofferak");
```

```rust
let mut s = client.session_jwt_file("/var/run/secrets/tokens/cofferak")?;
```

When the token expires the daemon closes the session, and the SDK
reconnects with the fresh file on its next call.

!!! note "The client certificate is still needed"
    In server mode the workload still connects over mutual TLS with a
    client certificate, and by default a login only works with the
    certificate of the service it acts as (ADR 0017): name it `payments-api`
    here. Workload identity replaces the static *token*, not the transport.
    If you issue certificates per namespace rather than per service, set
    `COFFERAK_TLS_BIND_SERVICE=0` and accept that the certificate no longer
    has to match the service.

**When the cluster rotates its signing keys** (rare), tokens signed by the
new key are refused until you give cofferak the new keys. Keep the old and
the new key in the document while it happens:

```bash
kubectl get --raw /openid/v1/jwks | kubectl exec -i -n cofferak cofferak-0 -- \
  cofferak workload update-jwks k8s --jwks -
```

## CI systems and other providers

The same three steps, with the provider's issuer, keys and subject
format. These follow the providers' documentation and have **not** been
tried against real tokens from them here, only the Kubernetes path has:

| Provider | `--iss` | Keys | Subject looks like |
|---|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `https://token.actions.githubusercontent.com/.well-known/jwks` | `repo:ORG/REPO:ref:refs/heads/main` |
| GitLab CI (`id_tokens`) | your GitLab URL, e.g. `https://gitlab.com` | `https://gitlab.com/oauth/discovery/keys` | `project_path:GROUP/PROJECT:ref_type:branch:ref:main` |
| Google identity tokens | `https://accounts.google.com` | `https://www.googleapis.com/oauth2/v3/certs` | the service account's numeric id |

Request the token with the audience you passed to `--audience`, and bind
the narrowest subject (a branch or an environment, not a whole repository).

## What to know

- **A stolen token works until it expires.** Verification is offline, so
  cofferak cannot see that a pod was deleted. Keep `expirationSeconds`
  short and the audience private to cofferak. `--max-ttl` refuses tokens
  that are valid longer than you want.
- **Keys are updated by hand** (`workload update-jwks`) for now.
- **Everything is audited.** Each login is in the audit log (`cofferak audit
  tail`) with the issuer and subject, each refusal with a short reason
  (`wrong audience`, `token expired`, `subject is not bound`, ...), never
  with the token.
- **A damaged configuration fails closed**: no identity is accepted, service
  tokens keep working.
