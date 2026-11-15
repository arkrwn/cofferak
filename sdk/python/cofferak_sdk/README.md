# cofferak-sdk (Python)

Minimal, dependency-free Python client for [cofferak](https://github.com/arkrwn/cofferak).

```python
from cofferak_sdk import Client

client = Client("/run/cofferak/cofferakd.sock")
client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("my-token", "myapp/DB_PASSWORD")
```

See [`examples/smoke.py`](examples/smoke.py) for a complete, runnable
example, and [`docs/sample-integration/python.md`](../../../docs/sample-integration/python.md)
in the main repo for a walkthrough.

## Workload identity (JWT)

A workload can authenticate with a JWT from its platform instead of a
cofferak token (the daemon must have the issuer and a binding configured,
see ADR 0022). Both methods return the same `Session` as `client.session`.

```python
# A file holding the JWT, re-read on every connect and reconnect.
with client.session_jwt_file("/var/run/secrets/tokens/cofferak") as s:
    password = s.get("myapp/DB_PASSWORD")

# Or any callable returning the current JWT string.
with client.session_jwt(lambda: my_token_source()) as s:
    password = s.get("myapp/DB_PASSWORD")
```

In Kubernetes, mount a projected service account token with the daemon's
audience and pass its path to `session_jwt_file`. The kubelet rotates the
file before the token expires. When the daemon closes the connection
(the JWT expired, or it was idle) the next call reconnects with the
freshly read token. `DeniedError` means the JWT was refused (the reason is
in the daemon's audit log); errors from the provider, such as a missing
file, are raised unchanged. The JWT never appears in an error message.
See [`examples/smoke_jwt.py`](examples/smoke_jwt.py).
