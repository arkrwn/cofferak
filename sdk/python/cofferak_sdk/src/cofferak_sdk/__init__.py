"""Minimal Python client SDK for cofferak.

Connects to a running ``cofferakd`` over its Unix socket, or (server
mode, ADR 0008) over TLS-wrapped TCP, and speaks the same
newline-delimited JSON protocol documented in
``cofferakd/src/protocol.rs`` (``Request``/``Response``, serde's default
externally-tagged enum encoding). Standard library only - including
Python's own ``ssl`` module for the TLS transport, no third-party TLS
library.

Example::

    from cofferak_sdk import Client

    client = Client("/run/cofferak/cofferakd.sock")
    client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
    value = client.get("my-token", "myapp/DB_PASSWORD")
    assert value == b"s3cr3t"

Server mode::

    client = Client.connect_tls(
        addr="cofferak.example.internal:8443",
        server_name="cofferak.example.internal",
        ca_cert_path="/path/to/ca.pem",
    )

Sessions (protocol version 2): authenticate once, keep one connection, and
read many values in one round trip::

    with client.session("my-token") as s:
        password = s.get("myapp/DB_PASSWORD")
        config = s.get_all("myapp")          # {path: value} for a prefix

Workload identity (JWT sessions): instead of a cofferak token, a workload
presents a JWT issued by its platform (for example a Kubernetes projected
service account token). The credential is read again on every connect and
reconnect, so a rotated token is picked up without restarting::

    with client.session_jwt_file("/var/run/secrets/tokens/cofferak") as s:
        password = s.get("myapp/DB_PASSWORD")

    with client.session_jwt(lambda: fetch_current_jwt()) as s:
        ...
"""

from __future__ import annotations

import base64 as _base64
import json
import os as _os
import socket as _socket
import ssl as _ssl
from typing import Any, Callable

# Mirrors cofferakd's protocol::MAX_LINE_BYTES (and the Rust/Go SDKs'
# identical constant) - a hard ceiling on one response line, so a
# malicious or compromised daemon that never terminates a response
# can't grow this client's buffer without limit.
_MAX_LINE_BYTES = 16 * 1024 * 1024

# Bounds how long one call can block on the network - a stalled or
# malicious daemon otherwise ties up the caller indefinitely. Matches
# cofferakd's own per-connection timeout (ADR 0008).
_IO_TIMEOUT_SECONDS = 30.0

# Mirrors cofferakd's protocol::MAX_BATCH_PATHS: the most paths one
# GetMany request may carry. Session.get_many splits longer lists.
_MAX_BATCH_PATHS = 256


class CofferakError(Exception):
    """Base class for every error this SDK raises."""


class DeniedError(CofferakError):
    """The token doesn't have access to the requested path, or the token
    is unknown to the daemon."""

    def __init__(self) -> None:
        super().__init__("denied")


class NotFoundError(CofferakError):
    """The requested path has no value set."""

    def __init__(self) -> None:
        super().__init__("not found")


class RemoteError(CofferakError):
    """The daemon returned an error message."""

    def __init__(self, message: str) -> None:
        super().__init__(f"remote error: {message}")
        self.message = message


class ProtocolError(CofferakError):
    """The daemon's response didn't match any known ``Response`` shape,
    or exceeded this client's size limit."""


def _build_tls_context(
    ca_cert_path: str,
    client_cert_path: str | None,
    client_key_path: str | None,
) -> _ssl.SSLContext:
    # PROTOCOL_TLS_CLIENT pre-configures check_hostname=True and
    # verify_mode=CERT_REQUIRED (Python's own secure default for a
    # client context) - neither is weakened anywhere in this function.
    context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = _ssl.TLSVersion.TLSv1_3
    context.maximum_version = _ssl.TLSVersion.TLSv1_3
    # Deliberately NOT calling load_default_certs(): this context's
    # trust store starts empty, and load_verify_locations below adds
    # ONLY the given CA. cofferak's TLS is for a self-managed deployment,
    # not the public web - this client must never also trust the OS's
    # public root store (that would let any public-CA-issued cert
    # impersonate the cofferak server).
    context.load_verify_locations(cafile=ca_cert_path)
    if client_cert_path or client_key_path:
        if not (client_cert_path and client_key_path):
            raise ValueError(
                "client_cert_path and client_key_path must both be set, or neither"
            )
        context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return context


class Client:
    """A client connected to one cofferakd endpoint - a Unix socket, or
    (server mode) a TLS/TCP address. Each call opens a fresh connection,
    matching the convention established by cofferakd's own CLI client."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path: str | None = socket_path
        self._tls_addr: tuple[str, int] | None = None
        self._tls_server_name: str | None = None
        self._tls_context: _ssl.SSLContext | None = None

    @classmethod
    def connect_tls(
        cls,
        addr: str,
        server_name: str,
        ca_cert_path: str,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
    ) -> Client:
        """Build a client for the daemon's TLS/TCP listener (server
        mode, ADR 0008). ``addr`` is ``"host:port"``. cofferakd's server
        mode always requires a client certificate (mutual TLS, ADR 0011);
        the cert/key arguments are optional only so a client can be built
        to prove that a certificate-less connection is refused. Loads and
        validates the CA (and client cert/key) eagerly, so a
        misconfiguration fails here rather than on the first call."""
        host, _, port_str = addr.rpartition(":")
        if not host or not port_str.isdigit():
            raise ValueError(f"addr must be 'host:port', got {addr!r}")
        context = _build_tls_context(ca_cert_path, client_cert_path, client_key_path)

        instance = cls.__new__(cls)
        instance.socket_path = None
        instance._tls_addr = (host, int(port_str))
        instance._tls_server_name = server_name
        instance._tls_context = context
        return instance

    def _open(self) -> Any:
        """Open one connection to the daemon: a connected Unix socket, or
        a TLS socket whose handshake has completed."""
        if self.socket_path is not None:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            try:
                sock.settimeout(_IO_TIMEOUT_SECONDS)
                sock.connect(self.socket_path)
            except BaseException:
                sock.close()
                raise
            return sock
        assert self._tls_addr is not None and self._tls_context is not None
        raw_sock = _socket.create_connection(self._tls_addr, timeout=_IO_TIMEOUT_SECONDS)
        try:
            tls_sock = self._tls_context.wrap_socket(
                raw_sock, server_hostname=self._tls_server_name
            )
        except BaseException:
            raw_sock.close()
            raise
        tls_sock.settimeout(_IO_TIMEOUT_SECONDS)
        return tls_sock

    def _send(self, request: dict[str, Any]) -> Any:
        payload = (json.dumps(request) + "\n").encode("utf-8")
        with self._open() as sock:
            sock.sendall(payload)
            buf = self._read_line_bounded(sock)
        try:
            return json.loads(buf.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ProtocolError(f"invalid JSON response: {e}") from e

    def session(self, token: str) -> Session:
        """Open a session (protocol version 2): authenticate once with
        ``token``, then make any number of calls on one connection. Use it
        as a context manager, or call ``close()`` when done. Raises
        :class:`DeniedError` if the token is not accepted, and
        :class:`ProtocolError` if the daemon is too old for sessions."""
        return Session(self, token)

    def session_jwt(self, provider: Callable[[], str]) -> Session:
        """Open a session (protocol version 2) as a workload identity:
        authenticate with a JWT instead of a cofferak token. ``provider``
        is a zero-argument callable returning the current JWT string; it
        is called on every connect and on every reconnect (for example
        after the JWT expired and the daemon closed the connection), so
        it should return the freshest token. Raises :class:`DeniedError`
        if the JWT is not accepted (the reason is only in the daemon's
        audit log). Exceptions raised by ``provider`` propagate
        unchanged. The JWT never appears in an error message."""
        if not callable(provider):
            raise TypeError("provider must be a callable returning the JWT")
        return Session(self, jwt_provider=provider)

    def session_jwt_file(self, path: "str | _os.PathLike[str]") -> Session:
        """Like :meth:`session_jwt`, with the JWT read from the file at
        ``path`` (surrounding whitespace and the trailing newline are
        stripped). The file is read again on every connect and reconnect,
        so a token rotated in place (a Kubernetes projected service
        account token, refreshed by the kubelet) is used from then on. A
        missing or unreadable file raises its :class:`OSError` unchanged."""
        file_path = _os.fspath(path)

        def read_jwt() -> str:
            with open(file_path, encoding="utf-8") as f:
                return f.read()

        return Session(self, jwt_provider=read_jwt)

    @staticmethod
    def _read_line_bounded(sock: Any) -> bytes:
        """Read until ``\\n`` or ``_MAX_LINE_BYTES``, whichever comes
        first - never growing the buffer past that limit. Each call
        makes exactly one request and expects exactly one response line
        before the connection closes, so there's no "next request" to
        preserve across calls."""
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            if len(buf) + len(chunk) > _MAX_LINE_BYTES:
                raise ProtocolError("response line exceeded the maximum allowed size")
            buf += chunk
        return buf

    @staticmethod
    def _check_ok(response: Any) -> None:
        if response == "Ok":
            return
        if response == "Denied":
            raise DeniedError()
        if response == "NotFound":
            raise NotFoundError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to a write/delete request: {response!r}")

    def get(self, token: str, path: str) -> bytes:
        """Read a secret's value."""
        response = self._send({"Get": {"token": token, "path": path}})
        if isinstance(response, dict) and "Value" in response:
            return bytes(response["Value"])
        if response == "Denied":
            raise DeniedError()
        if response == "NotFound":
            raise NotFoundError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to Get: {response!r}")

    def set(self, token: str, path: str, value: bytes) -> None:
        """Write a secret's value. Requires a read-write token."""
        response = self._send(
            {"Set": {"token": token, "path": path, "value": list(value)}}
        )
        self._check_ok(response)

    def rm(self, token: str, path: str) -> None:
        """Remove a secret. Requires a read-write token."""
        response = self._send({"Rm": {"token": token, "path": path}})
        self._check_ok(response)

    def list(self, token: str, prefix: str) -> list[str]:
        """List secret paths under ``prefix``."""
        response = self._send({"List": {"token": token, "prefix": prefix}})
        if isinstance(response, dict) and "Listed" in response:
            return list(response["Listed"])
        if response == "Denied":
            raise DeniedError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to List: {response!r}")


class Session:
    """An authenticated connection to cofferakd (protocol version 2).

    One connection carries every call, so over TLS the handshake is paid
    once instead of once per secret. If the daemon closes the connection
    (it does after an idle period), the next call reconnects and
    authenticates again without the caller noticing. A JWT session
    (:meth:`Client.session_jwt`, :meth:`Client.session_jwt_file`) asks for
    the current JWT on every reconnect, so it keeps working across a token
    rotation; once a JWT has expired and cannot be replaced, the
    reconnect raises :class:`DeniedError`.

    Not safe to share between threads without a lock: open one session
    per thread.
    """

    def __init__(
        self,
        client: Client,
        token: str | None = None,
        *,
        jwt_provider: Callable[[], str] | None = None,
    ) -> None:
        if (token is None) == (jwt_provider is None):
            raise ValueError("give exactly one of token and jwt_provider")
        self._client = client
        # The credential source: a static token, or a provider of JWTs.
        self._token = token
        self._jwt_provider = jwt_provider
        self._sock: Any = None
        self._buf = b""
        #: The service id the daemon knows this token as.
        self.service: str = ""
        self._connect()

    def __repr__(self) -> str:
        # Never include the credential.
        kind = "jwt" if self._jwt_provider is not None else "token"
        return f"<cofferak_sdk.Session {kind} service={self.service!r}>"

    def _credential(self) -> tuple[str, str]:
        """The ``(method, credential)`` to authenticate with now."""
        if self._jwt_provider is None:
            assert self._token is not None
            return "token", self._token
        jwt = self._jwt_provider()
        if not isinstance(jwt, str):
            raise TypeError("the JWT provider must return a str")
        jwt = jwt.strip()
        if not jwt:
            raise ValueError("the JWT provider returned an empty token")
        return "jwt", jwt

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection. The session reconnects if used again."""
        sock, self._sock, self._buf = self._sock, None, b""
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _connect(self) -> None:
        self.close()
        # Ask for the credential first: a provider error (file missing)
        # propagates as is, before any connection is opened.
        method, credential = self._credential()
        self._sock = self._client._open()
        try:
            hello = self._roundtrip({"Hello": {"version": 2}})
            if not (isinstance(hello, dict) and "Hello" in hello):
                raise ProtocolError(
                    "this cofferakd does not support sessions (protocol version 2), "
                    "upgrade it or use the per-call Client methods"
                )
            authed = self._roundtrip(
                {"Auth": {"method": method, "credential": credential}}
            )
            if authed == "Denied":
                raise DeniedError()
            if isinstance(authed, dict) and "Err" in authed:
                raise RemoteError(authed["Err"])
            if not (isinstance(authed, dict) and "Authed" in authed):
                raise ProtocolError(f"unexpected response to Auth: {authed!r}")
            self.service = str(authed["Authed"].get("service", ""))
        except BaseException:
            self.close()
            raise

    def _roundtrip(self, request: Any) -> Any:
        self._sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        while b"\n" not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("cofferakd closed the connection")
            if len(self._buf) + len(chunk) > _MAX_LINE_BYTES:
                raise ProtocolError("response line exceeded the maximum allowed size")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ProtocolError(f"invalid JSON response: {e}") from e

    def _call(self, request: Any, retry: bool = True) -> Any:
        """Send one request. If the connection is gone, reconnect and send
        it again once - except when ``retry`` is false (a request that must
        not be repeated), where the connection error is raised."""
        if self._sock is None:
            self._connect()
        try:
            return self._roundtrip(request)
        except OSError:
            self.close()
            if not retry:
                raise
        self._connect()
        try:
            return self._roundtrip(request)
        except OSError:
            self.close()
            raise

    @staticmethod
    def _raise_for(response: Any, what: str) -> None:
        if response == "Denied":
            raise DeniedError()
        if response == "NotFound":
            raise NotFoundError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to {what}: {response!r}")

    def get(self, path: str) -> bytes:
        """Read a secret's value."""
        response = self._call({"Get": {"path": path}})
        if isinstance(response, dict) and "Value" in response:
            return _base64.b64decode(response["Value"], validate=True)
        self._raise_for(response, "Get")
        raise AssertionError("unreachable")

    def get_many(self, paths: list[str]) -> dict[str, bytes]:
        """Read several secrets in one round trip. Returns ``{path:
        value}`` for the paths that exist, a path with no value is left
        out. Raises :class:`DeniedError` if any path is outside what the
        token may read."""
        out: dict[str, bytes] = {}
        for start in range(0, len(paths), _MAX_BATCH_PATHS):
            chunk = paths[start : start + _MAX_BATCH_PATHS]
            response = self._call({"GetMany": {"paths": chunk}})
            if not (isinstance(response, dict) and "Values" in response):
                self._raise_for(response, "GetMany")
            for item in response["Values"]:
                error = item.get("error")
                if error is None:
                    out[item["path"]] = _base64.b64decode(item["value"], validate=True)
                elif error == "denied":
                    raise DeniedError()
                elif error != "not_found":
                    raise RemoteError(f"could not read {item['path']}")
        return out

    def get_all(self, prefix: str) -> dict[str, bytes]:
        """Read every secret under ``prefix``: ``{path: value}``."""
        return self.get_many(self.list(prefix))

    def set(self, path: str, value: bytes) -> None:
        """Write a secret's value. Requires a read-write token."""
        encoded = _base64.b64encode(value).decode("ascii")
        response = self._call({"Set": {"path": path, "value": encoded}})
        if response != "Ok":
            self._raise_for(response, "Set")

    def rm(self, path: str) -> None:
        """Remove a secret. Requires a read-write token."""
        # Not repeated on a lost connection: a second try after a removal
        # that did go through would wrongly report "not found".
        response = self._call({"Rm": {"path": path}}, retry=False)
        if response != "Ok":
            self._raise_for(response, "Rm")

    def list(self, prefix: str) -> list[str]:
        """List secret paths under ``prefix``."""
        response = self._call({"List": {"prefix": prefix}})
        if isinstance(response, dict) and "Listed" in response:
            return list(response["Listed"])
        self._raise_for(response, "List")
        raise AssertionError("unreachable")

    def ping(self) -> None:
        """Check that the daemon answers on this session."""
        response = self._call("Ping")
        if response != "Ok":
            self._raise_for(response, "Ping")


__all__ = [
    "Client",
    "Session",
    "CofferakError",
    "DeniedError",
    "NotFoundError",
    "RemoteError",
    "ProtocolError",
]
