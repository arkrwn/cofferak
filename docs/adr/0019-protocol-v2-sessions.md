# ADR 0019: Protocol version 2: sessions, batch reads and base64 values

Status: accepted

## Context

The first wire protocol (SPEC §6) is one request per line, each carrying
its own token, and every SDK opens a new connection for every call. That
is simple and right for a CLI. It is a poor fit for the next steps in
ADR 0014:

- **Cost over the network.** In server mode every `get` pays a full
  TLS 1.3 handshake with ML-KEM-1024 and mutual certificate checks. A
  service that reads twenty secrets at startup pays it twenty times.
- **No place for other ways to authenticate.** The token is a field of
  every request. A workload that proves who it is with something other
  than a static token (a Kubernetes ServiceAccount token, an OIDC token)
  has nowhere to put it.
- **No way to change the protocol.** There is no version and no
  handshake, so any change breaks every deployed client.
- **Values are JSON arrays of numbers**, up to four characters per byte,
  and a trap for every new SDK (Go's JSON encoder writes bytes as base64
  by default).

## Decision

Add protocol version 2 next to version 1. Version 1 is unchanged and
stays supported: the same listener serves both, and a connection chooses
with its first line.

### Handshake

A client that wants version 2 sends `{"Hello":{"version":2}}` first. The
daemon answers `{"Hello":{"version":2,"features":["session","batch",
"base64"]}}` with the newest version it speaks. `Hello` is not a version 1
request, so an older daemon answers `{"Err":"malformed request"}`, which
the SDKs report as "this cofferakd does not support sessions".

### One authentication per connection

`{"Auth":{"method":"token","credential":"<hex>"}}` is answered with
`{"Authed":{"service":"<id>"}}` or `"Denied"`. `method` exists so that
other ways to authenticate can be added without another protocol version,
`"token"` is the only one today. After three wrong credentials the daemon
closes the connection. Every attempt is written to the audit log (action
`auth`), never with the credential.

After that, requests carry no token:

```
{"Get":{"path":"a/b"}}                    → {"Value":"<base64>"}
{"GetMany":{"paths":["a/b","a/c"]}}       → {"Values":[{"path":"a/b","value":"<base64>"},
                                                       {"path":"a/c","error":"not_found"}]}
{"Set":{"path":"a/b","value":"<base64>"}} → "Ok"
{"Rm":{"path":"a/b"}}                     → "Ok"
{"List":{"prefix":"a"}}                   → {"Listed":["a/b"]}
"Ping"                                    → "Ok"
```

`"Denied"`, `"NotFound"` and `{"Err":"..."}` mean what they mean in
version 1. Values are base64 (standard alphabet, padded).

### Batch reads

`GetMany` reads up to 256 paths and at most 4 MiB of values in one round
trip, under one lock of the daemon, so the batch is one consistent view.
Each path is checked and audited on its own: a path the session may not
read is reported as `denied` without failing the others.

### A session never outlives its access

The daemon keeps the credential a session authenticated with and checks
it again on every request, through the same code as version 1. So access
control, the binding of tokens to client certificates (ADR 0017),
persistence and the audit log are identical for both versions, and a
service removed from the vault is denied on the next request of an open
session, not when the session ends.

### Time limits

Until a connection holds an authenticated session it keeps the 30 second
hard deadline of version 1, so a client that does not authenticate cannot
hold a slot. An authenticated session has an idle timeout between
requests (`$COFFERAK_SESSION_IDLE_SECS`, default 300) and a maximum
lifetime (`$COFFERAK_SESSION_MAX_SECS`, default 3600). The connection
limits of both listeners still apply.

### SDKs

All four SDKs add a session next to their existing per-call methods, which
keep working unchanged: `get`, `get_many`, `get_all(prefix)`, `set`, `rm`,
`list`, `ping`, `close`. A session reconnects and authenticates again on
its own when the daemon has closed the connection. `rm` is the exception:
it is not sent a second time, because a removal that did go through would
then be reported as "not found".

## Proof

- `cofferakd/tests/session_integration.rs`: handshake, one session for
  many requests, every byte value through base64, batch results and
  limits, requests before authentication refused, three wrong credentials
  close the connection, an open session loses access when its service is
  removed, certificate binding, version 1 still served.
- `cofferakd/tests/session_idle.rs`: an idle session is closed, a busy one
  ends at its lifetime.
- `scripts/sdk-smoke.sh` and `scripts/server-mode-smoke.sh`: every SDK
  runs the same session checks against a real daemon over the Unix socket
  and over mutual TLS, including waiting out the idle timeout and
  reconnecting.
- `scripts/bench.sh`: sessions against a fresh connection per request
  ([benchmarks](../benchmarks.md)).

## Consequences

- Reading secrets over mutual TLS is more than ten times faster for a
  service that keeps a session, with no change to the cryptography.
- Workload authentication (ADR 0014, phase 2) can be added as a new
  `method`, without touching version 1 or the request handling.
- A long-lived connection holds one of the listener's slots for up to its
  lifetime. The idle timeout and the connection limits bound that.
- The CLI still uses version 1: one request per process, where a session
  gains nothing.
- The daemon still handles requests one at a time behind one lock. With
  sessions that lock, not connection setup, is now the limit on
  throughput, and is the next thing to look at.
