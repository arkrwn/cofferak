# SDKs

A consuming service talks to `cofferakd` over its Unix socket - or, in
[server mode](server-mode.md), TLS/mTLS over TCP - using the
newline-delimited JSON protocol in [`docs/SPEC.md`](SPEC.md) §6, one
request per connection or a [session](#sessions).
Four client SDKs implement it today, **all four over both transports**
 - each is smoke-tested for real against a running daemon in CI
(`scripts/sdk-smoke.sh` for the Unix socket, `scripts/server-mode-smoke.sh`
for TLS/mTLS including adversarial reject cases, both wired into
`.github/workflows/ci.yml`), not just documented:

| Language | Package | TLS library | Example |
|---|---|---|---|
| Rust | [`sdk/rust/cofferak-sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/rust/cofferak-sdk) | `rustls` | [`docs/sample-integration/rust.md`](sample-integration/rust.md) |
| Go | [`sdk/go/cofferak`](https://github.com/arkrwn/cofferak/blob/main/sdk/go/cofferak) | `crypto/tls` (stdlib) | [`docs/sample-integration/go.md`](sample-integration/go.md) |
| Python | [`sdk/python/cofferak_sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/python/cofferak_sdk) | `ssl` (stdlib) | [`docs/sample-integration/python.md`](sample-integration/python.md) |
| TypeScript | [`sdk/javascript/cofferak-sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/javascript/cofferak-sdk) | `node:tls` (stdlib) | [`docs/sample-integration/typescript.md`](sample-integration/typescript.md) |
| JavaScript | same package, compiled `dist/` | `node:tls` (stdlib) | [`docs/sample-integration/javascript.md`](sample-integration/javascript.md) |

The Go, Python and Node SDKs use only their language's standard library;
the Rust SDK uses `rustls` on AWS-LC, the same stack as the daemon.
Copy-paste samples for all four, verified against a running daemon, are
in [docs/getting-started.md](getting-started.md#6-read-secrets-from-code-sdks).

```python
# Python, the shortest example - same shape in every SDK above.
from cofferak_sdk import Client

client = Client("/run/cofferak/cofferakd.sock")
client.set("<token>", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("<token>", "myapp/DB_PASSWORD")
```

## Sessions

The calls above open a new connection each time and send the token with
every request. That is fine for a script. A service should open a
**session** instead (protocol version 2,
[ADR 0019](adr/0019-protocol-v2-sessions.md)): it authenticates once,
keeps one connection, and can read many secrets in one round trip. Over
mutual TLS that is more than ten times faster, because the handshake is
paid once ([benchmarks](benchmarks.md)).

```python
# Python
with client.session("<token>") as s:
    password = s.get("myapp/DB_PASSWORD")
    config = s.get_all("myapp")              # {path: value} under a prefix
    some = s.get_many(["myapp/A", "myapp/B"])
```

```go
// Go
s, err := client.Session(token)
defer s.Close()
password, err := s.Get("myapp/DB_PASSWORD")
config, err := s.GetAll("myapp")             // map[string][]byte
```

```ts
// TypeScript / JavaScript
const s = await client.session(token);
const password = await s.get("myapp/DB_PASSWORD");
const config = await s.getAll("myapp");      // Map<string, Buffer>
s.close();
```

```rust
// Rust
let mut s = client.session(&token)?;
let password = s.get("myapp/DB_PASSWORD")?;
let config = s.get_all("myapp")?;            // BTreeMap<String, Vec<u8>>
```

Every SDK's session has the same methods: `get`, `get_many`, `get_all`,
`set`, `rm`, `list`, `ping` and `close`.

- `get_many` and `get_all` return the values that exist. A path with no
  value is left out, a path the token may not read is a "denied" error.
- The daemon closes a session that has been idle for five minutes, or
  open for an hour. The session reconnects and authenticates again on the
  next call, you don't have to handle it.
- A session never outlives its access: remove the service, and its open
  sessions are denied on their next request.
- Sessions need a `cofferakd` with protocol version 2. Against an older
  daemon, opening one fails with a clear protocol error, and the per-call
  methods keep working.

### Sessions with an identity token (no static token)

A workload can open a session with the signed token its platform gave it
instead of a service token ([workload identity](workload-identity.md)).
Give the SDK the **file** (it is read again every time the SDK connects,
so a Kubernetes projected token that the kubelet rotates needs no code) or
a function that returns the token:

| | From a file | From a function |
|---|---|---|
| Rust | `client.session_jwt_file(path)?` | `client.session_jwt(\|\| Ok(token))?` |
| Go | `client.SessionJWTFile(path)` | `client.SessionJWT(func() (string, error) {...})` |
| Python | `client.session_jwt_file(path)` | `client.session_jwt(lambda: token)` |
| TypeScript | `await client.sessionJwtFile(path)` | `await client.sessionJwt(() => token)` |

The session is the same as above, with the same methods. A token the
daemon refuses is a "denied" error. When the token expires the daemon
closes the session and the SDK reconnects with the then-current token on
its next call. If the token was withdrawn (the binding removed) that
reconnect is denied.

None of these are published to a package registry yet - consume them via
a local path/relative reference (see each SDK's own page above) until
the wire protocol and SDK surface area are stable enough to commit to.
Planned next: C, C++, Perl, Ruby - see
[`docs/sample-integration/roadmap.md`](sample-integration/roadmap.md).
