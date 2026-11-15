#!/usr/bin/env python3
"""Mint ES256 JWTs and a matching JWKS for tests (ADR 0022). TEST HELPER
ONLY: it signs with a key file on disk, nothing here is a way to run an
identity provider. Standard library plus the `openssl` command line.

  mint-jwt.py genkey KEY.pem
  mint-jwt.py jwks   KEY.pem --kid KID            # JWKS document on stdout
  mint-jwt.py token  KEY.pem --kid KID --iss ISS --aud AUD --sub SUB
                     [--exp-in SECS] [--nbf-in SECS] [--no-exp]
                     [--aud-extra AUD2]           # make `aud` an array
  (--exp-in may be negative: an already expired token)
"""
import argparse
import base64
import json
import subprocess
import sys
import time


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def openssl(*args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *args], input=stdin, check=True, capture_output=True
    ).stdout


def public_point(key: str) -> bytes:
    """The uncompressed point 0x04 || x || y of a P-256 key."""
    der = openssl("ec", "-in", key, "-pubout", "-outform", "DER")
    point = der[-65:]
    assert point[0] == 4, "not an uncompressed P-256 point"
    return point


def der_to_jose(der: bytes) -> bytes:
    """An ECDSA DER signature (SEQUENCE of two INTEGERs) as r || s."""
    assert der[0] == 0x30
    pos = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    out = b""
    for _ in range(2):
        assert der[pos] == 0x02
        length = der[pos + 1]
        value = der[pos + 2 : pos + 2 + length]
        out += value.lstrip(b"\x00").rjust(32, b"\x00")
        pos += 2 + length
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["genkey", "jwks", "token"])
    p.add_argument("key")
    p.add_argument("--kid", default="test-key")
    p.add_argument("--iss", default="https://issuer.test")
    p.add_argument("--aud", default="cofferak")
    p.add_argument("--aud-extra")
    p.add_argument("--sub", default="system:serviceaccount:ns:app1")
    p.add_argument("--exp-in", type=int, default=300)
    p.add_argument("--nbf-in", type=int)
    p.add_argument("--no-exp", action="store_true")
    a = p.parse_args()

    if a.command == "genkey":
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", a.key)
        return
    if a.command == "jwks":
        pt = public_point(a.key)
        jwk = {
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": a.kid,
            "x": b64(pt[1:33]), "y": b64(pt[33:]),
        }
        json.dump({"keys": [jwk]}, sys.stdout)
        return

    now = int(time.time())
    claims = {
        "iss": a.iss,
        "sub": a.sub,
        "aud": [a.aud, a.aud_extra] if a.aud_extra else a.aud,
        "iat": now,
    }
    if not a.no_exp:
        claims["exp"] = now + a.exp_in
    if a.nbf_in is not None:
        claims["nbf"] = now + a.nbf_in
    header = {"alg": "ES256", "typ": "JWT", "kid": a.kid}
    signing_input = (
        b64(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64(json.dumps(claims, separators=(",", ":")).encode())
    )
    der = openssl("dgst", "-sha256", "-sign", a.key, stdin=signing_input.encode())
    print(signing_input + "." + b64(der_to_jose(der)))


if __name__ == "__main__":
    main()
