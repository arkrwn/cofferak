"""End-to-end smoke test of JWT (workload identity) sessions against a real
cofferakd, run by scripts/workload-check.sh (see the contract in its header).

Environment: COFFERAK_SOCKET, COFFERAK_JWT_DIR (good.jwt wrong-aud.jwt
unbound.jwt expired.jwt wrong-key.jwt long.jwt current.jwt),
COFFERAK_JWT_EXPIRES_IN (seconds until current.jwt expires),
COFFERAK_REVOKE_CMD (shell command that removes the binding).

Usage: python3 examples/smoke_jwt.py <allowed-path-prefix> <denied-path>
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cofferak_sdk import Client, DeniedError  # noqa: E402


def expect_denied(call, what: str) -> None:
    try:
        call()
    except DeniedError:
        return
    raise AssertionError(f"expected DeniedError for {what}")


def main() -> int:
    try:
        socket_path = os.environ["COFFERAK_SOCKET"]
        jwt_dir = os.environ["COFFERAK_JWT_DIR"]
        expires_in = float(os.environ["COFFERAK_JWT_EXPIRES_IN"])
        revoke_cmd = os.environ["COFFERAK_REVOKE_CMD"]
    except KeyError as e:
        print(f"{e.args[0]} must be set", file=sys.stderr)
        return 1
    prefix = sys.argv[1] if len(sys.argv) > 1 else "sdk-smoke/python"
    denied_path = sys.argv[2] if len(sys.argv) > 2 else "other/denied"

    client = Client(socket_path)
    jwt = lambda name: os.path.join(jwt_dir, name)  # noqa: E731

    # a. a good token: service id, binary round trip, batch, list, denied.
    binary = bytes(range(256))
    path = f"{prefix}/jwt"
    with client.session_jwt_file(jwt("good.jwt")) as s:
        assert s.service == "app1", f"service: {s.service!r}"
        s.set(path, binary)
        assert s.get(path) == binary, "binary value must round-trip"
        assert s.get_many([path, f"{prefix}/jwt-missing"]) == {path: binary}
        assert s.get_all(prefix)[path] == binary
        assert path in s.list(prefix)
        expect_denied(lambda: s.get(denied_path), "a denied path")
        expect_denied(lambda: s.get_many([path, denied_path]), "get_many of a denied path")
        s.ping()

    # b. every bad token is refused when the session opens.
    for name in ("wrong-aud.jwt", "unbound.jwt", "expired.jwt", "wrong-key.jwt"):
        expect_denied(lambda n=name: client.session_jwt_file(jwt(n)), name)

    # c. the token expires, the daemon closes the connection, the SDK
    # reconnects with the token re-read from the (rotated) file.
    with client.session_jwt_file(jwt("current.jwt")) as s:
        opened = time.monotonic()
        assert s.get(path) == binary
        tmp = jwt("current.jwt.tmp")
        with open(jwt("long.jwt"), "rb") as src, open(tmp, "wb") as dst:
            dst.write(src.read())
        os.replace(tmp, jwt("current.jwt"))
        time.sleep(max(0.0, opened + expires_in + 1.5 - time.monotonic()))
        assert s.get(path) == binary, "must reconnect with the fresh token"

    # e. a provider callable (before d: revoking removes the binding).
    with client.session_jwt(lambda: open(jwt("good.jwt")).read()) as s:
        assert s.service == "app1"

    # d. revocation: the binding is removed, the next call is denied.
    with client.session_jwt_file(jwt("good.jwt")) as s:
        assert s.get(path) == binary
        subprocess.run(revoke_cmd, shell=True, check=True)
        expect_denied(lambda: s.get(path), "a revoked binding")

    print("python SDK JWT smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
