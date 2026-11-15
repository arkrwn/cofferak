#!/usr/bin/env python3
# TEST DOUBLE ONLY. This is a fake Google Cloud KMS plus metadata server for
# scripts/seal-backends-check.sh. Its "cipher" is a trivial XOR with a fixed
# byte: it does NOT protect anything, it only has the shape of the real API
# (so the gcp-kms seal backend can be exercised end to end without Google
# credentials). Never use it outside tests, never point a real vault at it.
#
# Usage: fake-gcp-kms.py --port PORT --key projects/P/locations/L/keyRings/R/cryptoKeys/K [--log FILE]
# Port 0 picks a free port. Prints "listening on 127.0.0.1:<port>" once ready.
# The log gets one line per request: method, path, status (never bodies).
#
# Serves:
#   GET  /computeMetadata/v1/instance/service-accounts/default/token
#        (needs header "Metadata-Flavor: Google"; token is "fake-token")
#   POST /v1/<key>:encrypt   {"plaintext", "additionalAuthenticatedData"}
#   POST /v1/<key>:decrypt   {"ciphertext", "additionalAuthenticatedData"}
#        (only for exactly the --key name; needs "Authorization: Bearer fake-token")
# Ciphertext = b"FAKE" + 4-byte big-endian len(aad) + aad + (plaintext XOR 0xA5).
import argparse
import base64
import json
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "fake-token"
TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token"
LOG_LOCK = threading.Lock()


def google_error(code, message, status):
    return code, {"error": {"code": code, "message": message, "status": status}}


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-gcp-kms"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log = self.server.log_path
        if log:
            with LOG_LOCK, open(log, "a") as f:
                f.write(f"{self.command} {self.path} {code}\n")

    def do_GET(self):
        if self.path != TOKEN_PATH:
            return self._reply(*google_error(404, "Not found", "NOT_FOUND"))
        if self.headers.get("Metadata-Flavor") != "Google":
            return self._reply(403, {"error": "Missing Metadata-Flavor:Google header."})
        self._reply(200, {"access_token": TOKEN, "expires_in": 3599, "token_type": "Bearer"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        prefix = "/v1/"
        if not self.path.startswith(prefix) or ":" not in self.path:
            return self._reply(*google_error(404, "Not found", "NOT_FOUND"))
        name, _, method = self.path[len(prefix):].rpartition(":")
        if name != self.server.key or method not in ("encrypt", "decrypt"):
            return self._reply(*google_error(403, "Permission denied on resource", "PERMISSION_DENIED"))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._reply(*google_error(401, "Request had invalid authentication credentials.", "UNAUTHENTICATED"))
        try:
            req = json.loads(raw or b"{}")
            aad = base64.b64decode(req.get("additionalAuthenticatedData", ""), validate=True)
            if method == "encrypt":
                pt = base64.b64decode(req["plaintext"], validate=True)
                ct = b"FAKE" + struct.pack(">I", len(aad)) + aad + bytes(b ^ 0xA5 for b in pt)
                return self._reply(200, {"name": name, "ciphertext": base64.b64encode(ct).decode()})
            ct = base64.b64decode(req["ciphertext"], validate=True)
            if ct[:4] != b"FAKE" or len(ct) < 8:
                raise ValueError("prefix")
            (n,) = struct.unpack(">I", ct[4:8])
            if ct[8:8 + n] != aad or len(ct) < 8 + n:
                raise ValueError("aad")
            pt = bytes(b ^ 0xA5 for b in ct[8 + n:])
            return self._reply(200, {"plaintext": base64.b64encode(pt).decode()})
        except Exception:
            if method == "encrypt":
                return self._reply(*google_error(400, "Invalid request.", "INVALID_ARGUMENT"))
            return self._reply(*google_error(400, "Decryption failed: the ciphertext is invalid.", "INVALID_ARGUMENT"))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--log")
    a = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    srv.key = a.key
    srv.log_path = a.log
    print(f"listening on 127.0.0.1:{srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
