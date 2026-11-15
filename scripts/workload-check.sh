#!/usr/bin/env bash
# End-to-end check of workload identities (ADR 0022) with the REAL `cofferak`
# and `cofferakd` binaries and real signed JWTs (scripts/mint-jwt.py):
#
#   - the admin commands: add-issuer, bind, list, an identity-only service
#   - a raw protocol client: a valid token authenticates and acts as the
#     bound service (its paths, its permission), and every kind of bad token
#     is refused: wrong audience, wrong issuer, unbound subject, expired,
#     signed by another key, tampered, `alg: none`, no `exp`
#   - the audit log says why, never shows a token
#   - removing the binding, or the service, cuts an open session at once
#   - each SDK (Rust, Go, Python, TypeScript) opens a session with a JWT,
#     reconnects with the fresh token from its file after the old one
#     expired, and sees a revoked binding as "denied"
#
# Usage: ./scripts/workload-check.sh [python] [go] [javascript] [rust]
#   (no argument: the raw protocol checks and all four SDKs, `none`: only
#   the raw protocol checks)
#
# Each SDK example (smoke_jwt.*) is run with:
#   COFFERAK_SOCKET        the daemon's Unix socket
#   COFFERAK_JWT_DIR       holds good.jwt wrong-aud.jwt unbound.jwt
#                          expired.jwt wrong-key.jwt long.jwt and current.jwt
#                          (a token that expires in a few seconds)
#   COFFERAK_JWT_EXPIRES_IN  seconds until current.jwt expires
#   COFFERAK_REVOKE_CMD    a shell command that removes the binding
#   args: <allowed-path-prefix> <denied-path>
# and must exit 0 and print a line ending in "passed".
#
# Needs no root, no systemd and no Keychain; Linux and macOS.
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
SDKS=("$@")
[[ ${#SDKS[@]} -gt 0 ]] || SDKS=(python go javascript rust)
# `none`: only the raw protocol checks.
[[ "${SDKS[0]}" != none ]] || SDKS=()

step() { echo "== $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "build (release)"
cargo build --release --quiet -p cofferak-cli -p cofferakd
CLI="$REPO_ROOT/target/release/cofferak"
DAEMON_CMD=("$REPO_ROOT/target/release/cofferakd")
MINT="$REPO_ROOT/scripts/mint-jwt.py"

WORK="$(mktemp -d /tmp/cofferak-wl.XXXXXX)"
HOST="wl-host"
if [[ "$(uname -s)" == "Darwin" ]]; then
  # The rollback anchor is mirrored in the Keychain, which serves an item
  # without a prompt only to the binary that created it (ADR 0007).
  DAEMON_CMD=("$CLI" daemon)
  HOST="wl-host-$$"
fi
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
  if [[ "$(uname -s)" == "Darwin" ]]; then
    security delete-generic-password -s cofferak-anchor -a "$HOST" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

export COFFERAK_DATA_DIR="$WORK/data"
export COFFERAK_SOCKET="$WORK/d.sock"
export COFFERAK_SEAL=file
export COFFERAK_HOST_KEY_FILE="$WORK/keys/{host}.key"
export COFFERAK_HOST_ID="$HOST"
mkdir -p "$COFFERAK_DATA_DIR" "$WORK/keys" "$WORK/jwt"
chmod 700 "$COFFERAK_DATA_DIR" "$WORK/keys"

ISS="https://issuer.test"
SUB="system:serviceaccount:ns:app1"
JWT_DIR="$WORK/jwt"

step "vault: an identity-only service, a trusted issuer, one binding"
"$CLI" init --root >/dev/null
"$CLI" init --host "$HOST" >/dev/null
OUT="$("$CLI" enroll-service app1 --paths app --perm rw --identity-only)"
grep -qE '[0-9a-f]{64}' <<<"$OUT" && fail "--identity-only printed a token"
"$MINT" genkey "$WORK/key.pem"
"$MINT" genkey "$WORK/other.pem"
"$MINT" jwks "$WORK/key.pem" --kid k1 >"$WORK/jwks.json"
"$CLI" workload add-issuer test --iss "$ISS" --audience cofferak --jwks "$WORK/jwks.json" >/dev/null
"$CLI" workload bind app-main --issuer test --subject "$SUB" --service app1 >/dev/null
LISTING="$("$CLI" workload list)"
grep -q "$ISS" <<<"$LISTING" && grep -q "app-main" <<<"$LISTING" || fail "workload list does not show the configuration"
"$CLI" workload bind dup --issuer test --subject "$SUB" --service app1 2>/dev/null \
  && fail "the same subject was bound twice"
"$CLI" workload bind ghost --issuer test --subject x --service nobody 2>/dev/null \
  && fail "a binding to a service that does not exist was accepted"
"$CLI" workload add-issuer test --iss "$ISS" --audience cofferak --jwks "$WORK/jwks.json" 2>/dev/null \
  && fail "an existing issuer was overwritten without --replace"
echo '{"keys":[]}' | "$CLI" workload add-issuer empty --iss https://other.test --audience cofferak --jwks - 2>/dev/null \
  && fail "an issuer with no usable key was accepted"

mint() { "$MINT" token "$WORK/key.pem" --kid k1 --iss "$ISS" --aud cofferak --sub "$SUB" "$@"; }
mint >"$JWT_DIR/good.jwt"
mint --aud other-audience >"$JWT_DIR/wrong-aud.jwt"
mint --sub "system:serviceaccount:ns:someone-else" >"$JWT_DIR/unbound.jwt"
mint --exp-in -600 >"$JWT_DIR/expired.jwt"
"$MINT" token "$WORK/other.pem" --kid k1 --iss "$ISS" --aud cofferak --sub "$SUB" >"$JWT_DIR/wrong-key.jwt"
mint --exp-in 3000 >"$JWT_DIR/long.jwt"

start_daemon() {
  rm -f "$COFFERAK_SOCKET"
  "${DAEMON_CMD[@]}" >"$WORK/daemon.log" 2>&1 &
  DPID=$!
  PIDS="$PIDS $DPID"
  for _ in $(seq 1 100); do
    [[ -S "$COFFERAK_SOCKET" ]] && return 0
    kill -0 "$DPID" 2>/dev/null || { cat "$WORK/daemon.log" >&2; fail "daemon exited"; }
    sleep 0.1
  done
  cat "$WORK/daemon.log" >&2; fail "daemon did not create its socket"
}
step "start the daemon"
start_daemon

# A small raw-protocol client: each line of stdin is one JSON request, the
# reply goes to stdout, `--expect-closed` checks the daemon hangs up.
raw() {
  python3 - "$COFFERAK_SOCKET" "$@" <<'PY'
import json, socket, sys
sock_path, lines = sys.argv[1], sys.argv[2:]
s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sock_path)
f = s.makefile("rwb")
for line in lines:
    try:
        f.write(line.encode() + b"\n"); f.flush()
        reply = f.readline()
    except OSError:
        reply = b""   # the daemon hung up
    print(reply.decode().strip() if reply else "<closed>")
PY
}
hello='{"Hello":{"version":2}}'
auth_with() { printf '{"Auth":{"method":"jwt","credential":"%s"}}' "$(cat "$1")"; }

step "raw protocol: the valid token acts as the bound service"
R="$(raw "$hello" "$(auth_with "$JWT_DIR/good.jwt")" \
  '{"Set":{"path":"app/x","value":"aGVsbG8="}}' '{"Get":{"path":"app/x"}}' \
  '{"Get":{"path":"other/x"}}' '{"List":{"prefix":"app"}}')"
[[ "$(sed -n 2p <<<"$R")" == '{"Authed":{"service":"app1"}}' ]] || fail "good token: $(sed -n 2p <<<"$R")"
[[ "$(sed -n 3p <<<"$R")" == '"Ok"' ]] || fail "set as the bound service: $(sed -n 3p <<<"$R")"
[[ "$(sed -n 4p <<<"$R")" == '{"Value":"aGVsbG8="}' ]] || fail "get: $(sed -n 4p <<<"$R")"
[[ "$(sed -n 5p <<<"$R")" == '"Denied"' ]] || fail "a path outside the service's prefix: $(sed -n 5p <<<"$R")"

step "raw protocol: every bad token is denied"
refused() { # LABEL FILE
  local out; out="$(raw "$hello" "$(auth_with "$2")" | sed -n 2p)"
  [[ "$out" == '"Denied"' ]] || fail "$1 was not denied: $out"
}
refused "a wrong audience" "$JWT_DIR/wrong-aud.jwt"
refused "an unbound subject" "$JWT_DIR/unbound.jwt"
refused "an expired token" "$JWT_DIR/expired.jwt"
refused "a token signed by another key" "$JWT_DIR/wrong-key.jwt"
mint --no-exp >"$WORK/no-exp.jwt";            refused "a token without exp" "$WORK/no-exp.jwt"
mint --nbf-in 3600 >"$WORK/nbf.jwt";          refused "a token not valid yet" "$WORK/nbf.jwt"
mint --exp-in 864000 >"$WORK/forever.jwt";    refused "a token valid for ten days" "$WORK/forever.jwt"
"$MINT" token "$WORK/key.pem" --kid k1 --iss https://evil.test --aud cofferak --sub "$SUB" >"$WORK/evil-iss.jwt"
refused "an unknown issuer" "$WORK/evil-iss.jwt"
python3 - "$JWT_DIR/good.jwt" >"$WORK/tampered.jwt" <<'PY'
import base64, json, sys
h, p, sig = open(sys.argv[1]).read().strip().split(".")
pad = lambda s: s + "=" * (-len(s) % 4)
claims = json.loads(base64.urlsafe_b64decode(pad(p)))
claims["sub"] = "system:serviceaccount:ns:admin"
p2 = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(f"{h}.{p2}.{sig}")
PY
refused "a tampered payload" "$WORK/tampered.jwt"
python3 - "$JWT_DIR/good.jwt" >"$WORK/none.jwt" <<'PY'
import base64, json, sys
_, p, _ = open(sys.argv[1]).read().strip().split(".")
h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
print(f"{h}.{p}.")
PY
refused "alg none" "$WORK/none.jwt"
three="$(raw "$hello" "$(auth_with "$JWT_DIR/wrong-aud.jwt")" "$(auth_with "$JWT_DIR/wrong-aud.jwt")" \
  "$(auth_with "$JWT_DIR/wrong-aud.jwt")" "$(auth_with "$JWT_DIR/wrong-aud.jwt")" | tail -1)"
[[ "$three" == "<closed>" ]] || fail "the connection stayed open after three bad tokens: $three"

step "the audit log says why, and never shows a token"
AUDIT="$COFFERAK_DATA_DIR/audit.jsonl"
grep -q "denied: wrong audience" "$AUDIT" || fail "no 'wrong audience' in the audit log"
grep -q "denied: token expired" "$AUDIT" || fail "no 'token expired' in the audit log"
grep -q "denied: bad signature" "$AUDIT" || fail "no 'bad signature' in the audit log"
grep -q "denied: subject is not bound" "$AUDIT" || fail "no 'subject is not bound' in the audit log"
grep -q "ok: jwt issuer test subject $SUB" "$AUDIT" || fail "no successful login with its subject in the audit log"
for f in "$JWT_DIR"/*.jwt "$WORK"/*.jwt; do
  grep -qF "$(cut -d. -f3 "$f")" "$AUDIT" && [[ -n "$(cut -d. -f3 "$f")" ]] && fail "a token signature is in the audit log"
done

step "an open session loses access the moment its binding is removed"
( { printf '%s\n' "$hello" "$(auth_with "$JWT_DIR/good.jwt")" '{"Get":{"path":"app/x"}}'; sleep 3; printf '%s\n' '{"Get":{"path":"app/x"}}'; } \
  | python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(15); s.connect(sys.argv[1]); f = s.makefile("rwb")
out = []
for line in sys.stdin:
    f.write(line.encode()); f.flush()
    out.append(f.readline().decode().strip())
    if len(out) == 3:
        open(sys.argv[2], "w").write("up\n")   # tell the shell the session is open
print("\n".join(out[2:]))' "$COFFERAK_SOCKET" "$WORK/up" >"$WORK/session.out" ) &
SESSION_PID=$!
for _ in $(seq 1 50); do [[ -f "$WORK/up" ]] && break; sleep 0.1; done
[[ -f "$WORK/up" ]] || fail "the session did not open"
"$CLI" workload unbind app-main >/dev/null
wait "$SESSION_PID"
[[ "$(sed -n 1p "$WORK/session.out")" == '{"Value":"aGVsbG8="}' ]] || fail "first read in the session: $(cat "$WORK/session.out")"
[[ "$(sed -n 2p "$WORK/session.out")" == '"Denied"' ]] || fail "read after unbind was not denied: $(cat "$WORK/session.out")"
"$CLI" workload bind app-main --issuer test --subject "$SUB" --service app1 >/dev/null

step "rotate-dek keeps the workload configuration, and the daemon can be restarted"
kill "$DPID" 2>/dev/null || true; wait "$DPID" 2>/dev/null || true
"$CLI" rotate-dek --hosts "$HOST" >/dev/null
"$CLI" workload list | grep -q "app-main" || fail "the configuration is gone after rotate-dek"
start_daemon
R="$(raw "$hello" "$(auth_with "$JWT_DIR/good.jwt")" | sed -n 2p)"
[[ "$R" == '{"Authed":{"service":"app1"}}' ]] || fail "login after rotate-dek and restart: $R"

# ---------------------------------------------------------------------
# SDKs
run_sdk() { # NAME COMMAND...
  local name="$1"; shift
  step "$name SDK: session with a JWT, reconnect with a fresh token file, revocation"
  local expires_in=6
  mint --exp-in "$expires_in" >"$JWT_DIR/current.jwt"
  COFFERAK_JWT_DIR="$JWT_DIR" COFFERAK_JWT_EXPIRES_IN="$expires_in" \
  COFFERAK_REVOKE_CMD="'$CLI' workload unbind app-main" \
    "$@" "app/$name" other/denied || fail "$name SDK JWT smoke test"
  # The example removed the binding to prove revocation: put it back.
  "$CLI" workload bind app-main --issuer test --subject "$SUB" --service app1 >/dev/null
}
for sdk in "${SDKS[@]}"; do
  case "$sdk" in
    python) run_sdk python python3 sdk/python/cofferak_sdk/examples/smoke_jwt.py ;;
    go) run_sdk go bash -c 'cd sdk/go/cofferak && go run ./examples/smoke_jwt "$@"' _ ;;
    javascript)
      (cd sdk/javascript/cofferak-sdk && npm install --no-audit --no-fund --silent && npm run build --silent)
      run_sdk javascript node sdk/javascript/cofferak-sdk/examples/smoke_jwt.js ;;
    rust)
      cargo build --release --quiet --example smoke_jwt -p cofferak-sdk
      run_sdk rust "$REPO_ROOT/target/release/examples/smoke_jwt" ;;
    *) fail "unknown SDK $sdk (python go javascript rust)" ;;
  esac
done

echo "== workload identity check passed (raw protocol${SDKS[*]:+, ${SDKS[*]}}) =="
