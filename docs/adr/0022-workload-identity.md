# ADR 0022: Workload identity: sign in with a token from your identity provider

Status: accepted

## Context

Every service so far proves itself with a static token that an
administrator generated and handed to it (`enroll-service`). In Kubernetes
that means a long-lived secret to distribute, rotate and keep out of
manifests, to protect a vault of secrets: the first secret problem is not
solved by the tool meant to solve it. ADR 0014 (phase 2) asks for pods to
prove who they are with what the platform already gives them.

The platform already gives them a signed token: a projected Kubernetes
ServiceAccount token, a GitHub Actions or GitLab CI OIDC token, a
Google-signed identity token. All are JWTs signed by a key the provider
publishes as a JWKS. Protocol version 2 (ADR 0019) already has a named
authentication method on `Auth`, so a new method needs no new protocol.

## Decision

`Auth` accepts method `jwt`: the credential is the token. The daemon
verifies it **offline**, against public keys kept in the vault, and maps
its subject to a service.

### Configuration, in the vault (format 5)

Two kinds of entries, one encrypted `WorkloadConfig` in `VaultFile.workload`
(format 5, format 4 vaults are read and their integrity code still
verifies until the next write seals them as format 5):

- **Issuer**: a name, the exact `iss`, the one `aud` tokens must carry, the
  algorithms allowed (`RS256`, `ES256`, `ES384`), the issuer's JWKS, a
  clock leeway (default 30 s) and the longest remaining validity accepted
  (default one day).
- **Binding**: a name, an issuer, an **exact** subject (`sub`), and an
  enrolled service. That subject then has that service's path prefixes and
  permission.

`cofferak workload add-issuer | update-jwks | rm-issuer | bind | unbind |
list` manage it, under the same lock, integrity check and anchor update as
every admin command. A running daemon applies a change without a restart.
`enroll-service --identity-only` creates a service without showing its
token, for a service that is only reachable by identity. `rotate-dek`
re-encrypts the configuration.

### What is checked

In this order, a failure at any step is "denied" to the client and a
fixed reason in the audit log (never the token):

1. at most 16 KiB, exactly three parts
2. the `iss` picks the issuer (only to choose whose keys to verify with,
   `iss` is checked again by the verification)
3. the header's `alg` is one **that issuer** allows. Only asymmetric
   algorithms exist in the configuration, so `none` and the HMAC family
   cannot be allowed and a key-confusion attack has nothing to confuse
4. the key is chosen by `kid` among that issuer's keys only. Never from a
   URL or a key embedded in the token (`jku`, `x5u`, `jwk` are ignored). The
   key type and curve must fit the algorithm, an RSA key is 2048 to 8192
   bits with a small odd public exponent, the JWK's own `alg` must agree.
   A token without `kid` is accepted only if exactly one key fits
5. the signature, `exp` (required), `nbf`, `iss`, `aud` (exact, a string or
   one entry of an array), `sub` (required), a `crit` header it does not
   understand is refused, and `exp` not further away than the issuer's
   maximum validity
6. only then the subject is looked up among the bindings, by exact string
   comparison. No patterns, no prefixes

The verification itself is the `jsonwebtoken` crate on the AWS-LC backend
(two new crates on Linux and macOS, no `ring`), the choices above are
enforced around it and tested by minting attack tokens.

### Sessions

A session authenticated by token keeps acting as the identity it
verified, but the daemon **checks it again on every request**: the binding
must still exist for that subject and service, the service must still be
enrolled and the token must not have expired. Removing a binding, an
issuer or the service therefore cuts an open session at once. When the
token expires the daemon closes the connection without an answer, as it
does for an idle session, and never lets the session outlive it. A client
that has a fresh token reconnects and carries on.

With certificate binding (ADR 0017) the client certificate must name the
service the identity acts as, exactly as for a token.

The SDKs take the token from a function or a file, read again on every
connect, so the kubelet's rotation of a projected token file needs no code:
Rust `session_jwt` / `session_jwt_file`, Go `SessionJWT` / `SessionJWTFile`,
Python `session_jwt` / `session_jwt_file`, TypeScript `sessionJwt` /
`sessionJwtFile`.

### Why offline and why exact subjects

Verifying against stored keys means no call to the identity provider or
the Kubernetes API on the login path, nothing to be up for a login to
work, and the same code for Kubernetes, GitHub, GitLab and Google. The
cost is revocation: **a token that was stolen is accepted until it
expires.** Kubernetes bound tokens die with their pod only at the API
server, `TokenReview` would see that and this does not. Keep tokens short
(a projected token's `expirationSeconds`, the issuer's `max_ttl`), use an
audience only cofferak accepts, and bind to the narrowest subject. A
`TokenReview` check for Kubernetes tokens is a possible later addition.

Subjects are matched exactly because every pattern language is a new way
to bind more workloads than meant: `repo:acme/*` also matches
`repo:acme/anything-an-attacker-creates`. Bind each subject you mean.

## What this does not do

- **Keys are updated by hand.** `workload update-jwks` replaces an issuer's
  keys. When a provider rotates its signing key, tokens signed by the new
  key are refused until you do, so keep old and new keys in the JWKS during
  a rotation. Fetching a JWKS from a URL, with caching and rate-limited
  refresh on an unknown `kid`, is the next step.
- No claim-based rules beyond `sub` (for example "namespace is payments").
  CI providers put what you need in `sub`, Kubernetes does too.
- Not in exports or peer transfers: a bundle carries secrets and service
  tokens, not trust configuration.
- The workload still reaches the daemon over mutual TLS (ADR 0011) in a
  cluster, with a client certificate. Identity replaces the static
  *token*, not the transport.

## Proof

- `cofferak-core/tests/workload_jwt.rs` (89 tests): valid ES256, ES384 and
  RS256 tokens; every rejection with its exact reason: expired, not yet
  valid, no `exp`, valid too long, wrong audience or issuer, missing or
  empty `sub`; `none`, HS256 key confusion, algorithms the issuer did not
  allow, PS256, EdDSA; wrong key, unknown `kid`, ambiguous keys, `use: enc`,
  mismatching `alg`, curve mismatch; tampered header, payload and
  signature; size and shape limits; `jku`, `x5u` and an embedded `jwk`
  ignored; `crit` refused; configuration validation for every key and
  issuer rule; exact-only subject matching.
- `cofferak-core/src/format.rs`: a format 4 vault upgrades, its integrity
  code and rollback protection still verify, a tampered one is refused.
- `cofferakd/tests/session_jwt.rs` (16 tests): login, access limited to the service's
  prefixes, audit reasons without tokens, an open session denied the
  moment its binding, issuer or service is removed, expiry closing the
  session, certificate binding, a damaged configuration failing closed.
- `cofferak-cli/tests/cli_workload.rs` (9 tests): every admin command and refusal,
  the configuration encrypted in the vault file, generation and anchor.
- `scripts/workload-check.sh`, in CI on Linux and macOS: the real
  binaries with real signed tokens, every bad-token kind refused, an
  open session cut by `workload unbind`, `rotate-dek` and a restart
  keeping the configuration, and all four SDKs: login, reconnect with a
  fresh token file after the old one expired, revocation as "denied".
- `scripts/kubernetes-check.sh`, in CI on kind: a **real Kubernetes
  ServiceAccount token** (`kubectl create token`, RS256, signed by the
  cluster) logs a workload in with no static token, with the issuer and
  keys taken from the API server, a token for another audience, another
  ServiceAccount, or a tampered one is refused, and the configuration
  survives deleting the pod.

Not proved: tokens from GitHub, GitLab or Google (the same code path, no
real tokens from them were used), GKE's issuer and key layout.
