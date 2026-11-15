"""Session (protocol version 2) checks shared by smoke.py and smoke_tls.py,
so both transports prove the same behaviour against a real cofferakd."""

from __future__ import annotations

import os
import time

from cofferak_sdk import Client, DeniedError, NotFoundError


def session_checks(client: Client, token: str, allowed_path: str, denied_path: str) -> None:
    base = allowed_path + "-session"
    binary = bytes(range(256))
    with client.session(token) as s:
        assert s.service, "the session must report its service id"
        s.ping()
        s.set(f"{base}/A", b"alpha")
        s.set(f"{base}/B", binary)
        assert s.get(f"{base}/B") == binary, "binary value must round-trip"
        got = s.get_many([f"{base}/A", f"{base}/B", f"{base}/MISSING"])
        assert got == {f"{base}/A": b"alpha", f"{base}/B": binary}, got
        assert s.get_all(base) == got
        assert sorted(s.list(base)) == [f"{base}/A", f"{base}/B"]
        for call in (lambda: s.get(denied_path), lambda: s.get_many([denied_path])):
            try:
                call()
                raise AssertionError("expected DeniedError in a session")
            except DeniedError:
                pass
        # With $COFFERAK_SMOKE_IDLE_SECS the daemon closes idle sessions
        # after that many seconds: wait it out, the next call must reconnect.
        idle = os.environ.get("COFFERAK_SMOKE_IDLE_SECS")
        if idle:
            time.sleep(float(idle) + 1)
        assert s.get(f"{base}/A") == b"alpha", "session must reconnect"
        # A closed session reconnects when used again.
        s.close()
        s.rm(f"{base}/A")
        s.rm(f"{base}/B")
        try:
            s.get(f"{base}/A")
            raise AssertionError("expected NotFoundError after rm")
        except NotFoundError:
            pass
    try:
        client.session("0" * 64)
        raise AssertionError("expected DeniedError for an unknown token")
    except DeniedError:
        pass
