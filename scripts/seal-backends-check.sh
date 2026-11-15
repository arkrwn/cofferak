#!/usr/bin/env bash
# End-to-end check of the host-key seal backends selected by $COFFERAK_SEAL
# (ADR 0020), with the REAL `cofferak` and `cofferakd` binaries:
#
#   Part A, file:    the key is a 0600 file, the vault and the .seal file never
#                    contain it, the daemon serves and keeps secrets across a
#                    restart, a second host can be enrolled, and every broken
#                    key file (missing, truncated, wrong) or unknown backend
#                    makes the daemon refuse to start, quickly, with a clear
#                    message and no socket.
#   Part B, gcp-kms: the same against scripts/fake-gcp-kms.py (a test double
#                    for the metadata server and Cloud KMS on 127.0.0.1): the
#                    key is encrypted with KMS at init and decrypted at every
#                    daemon start, and a wrong KMS key, no metadata server, a
#                    damaged .seal file or no KMS at all each fail cleanly
#                    instead of hanging.
#
# Needs no root, no systemd and no Keychain; runs on Linux and macOS.
# Every daemon start in a negative case is bounded by a timeout implemented
# here in bash (macOS has no `timeout`).
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

echo "== build (release, --features gcp-kms) =="
cargo build --release --quiet --features gcp-kms -p cofferak-cli -p cofferakd
CLI="$REPO_ROOT/target/release/cofferak"
DAEMON="$REPO_ROOT/target/release/cofferakd"
FAKE="$REPO_ROOT/scripts/fake-gcp-kms.py"
[[ -x "$CLI" && -x "$DAEMON" ]] || { echo "binaries missing after build" >&2; exit 1; }

WORK="$(mktemp -d /tmp/cofferak-seal.XXXXXX)"
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
size_of() { wc -c <"$1" | tr -d ' '; }
hex_of() { od -An -v -tx1 "$1" | tr -d ' \n'; }
untrack() { local keep=""; for p in $PIDS; do [[ "$p" == "$1" ]] || keep="$keep $p"; done; PIDS="$keep"; }

# start_daemon LOG SOCKET [VAR=value ...]: run cofferakd in the background
# with the current environment plus the given settings; sets DPID.
start_daemon() {
  local log="$1" sock="$2"; shift 2
  rm -f "$sock"
  env COFFERAK_SOCKET="$sock" "$@" "$DAEMON" >"$log" 2>&1 &
  DPID=$!
  PIDS="$PIDS $DPID"
}
# wait_socket PID SOCKET LOG: the daemon must create its socket within 10 s.
wait_socket() {
  local pid="$1" sock="$2" log="$3" i
  for i in $(seq 1 100); do
    [[ -S "$sock" ]] && return 0
    kill -0 "$pid" 2>/dev/null || { cat "$log" >&2; fail "daemon exited before creating $sock"; }
    sleep 0.1
  done
  cat "$log" >&2
  fail "daemon did not create $sock in 10 s"
}
stop_daemon() {
  local pid="$1"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  untrack "$pid"
}
# expect_refusal LABEL SOCKET LOG TEXT [VAR=value ...]: the daemon must exit
# non-zero within 10 s, without creating SOCKET, printing TEXT (a substring).
# Sets LAST_MSG to what it printed.
expect_refusal() {
  local label="$1" sock="$2" log="$3" text="$4"; shift 4
  start_daemon "$log" "$sock" "$@"
  local pid="$DPID" i rc=0
  for i in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; untrack "$pid"
    cat "$log" >&2
    fail "$label: daemon still running after 10 s (hang instead of refusing)"
  fi
  wait "$pid" || rc=$?
  untrack "$pid"
  [[ $rc -ne 0 ]] || fail "$label: daemon exited 0, expected a refusal"
  [[ ! -e "$sock" ]] || fail "$label: daemon created its socket despite refusing"
  grep -qF -- "$text" "$log" || { cat "$log" >&2; fail "$label: message lacks '$text'"; }
  LAST_MSG="$(tr '\n' ' ' <"$log")"
  echo "ok: $label (exit $rc): $LAST_MSG"
}

# ---------------------------------------------------------------- Part A
step "A1. file backend: create vault, host pod-a, service myapp"
DATA_A="$WORK/a"; mkdir -m 700 "$DATA_A"
KEYDIR="$WORK/keys"; mkdir -m 700 "$KEYDIR"
SOCK_A="$WORK/a.sock"
export COFFERAK_DATA_DIR="$DATA_A"
export COFFERAK_SEAL=file
export COFFERAK_HOST_KEY_FILE="$KEYDIR/{host}.key"
"$CLI" init --root >/dev/null
"$CLI" init --host pod-a
TOKEN="$("$CLI" enroll-service myapp --paths myapp --perm rw | grep -E '^[0-9a-f]{64}$')"
[[ -n "$TOKEN" ]] || fail "could not parse the service token"

step "A2. key file is 32 bytes, 0600; neither vault nor .seal contain it"
KEY_A="$KEYDIR/pod-a.key"
[[ -f "$KEY_A" ]] || fail "no key file at $KEY_A"
[[ "$(size_of "$KEY_A")" == "32" ]] || fail "key file is not 32 bytes"
[[ "$(mode_of "$KEY_A")" == "600" ]] || fail "key file mode is $(mode_of "$KEY_A"), expected 600"
[[ "$(cat "$DATA_A/hosts/pod-a.seal")" == "cofferak-file-seal-v1" ]] || fail "pod-a.seal is not exactly the marker"
KEYHEX="$(hex_of "$KEY_A")"
if hex_of "$DATA_A/vault.cofferak" | grep -q "$KEYHEX"; then fail "raw key found in vault.cofferak"; fi
if hex_of "$DATA_A/hosts/pod-a.seal" | grep -q "$KEYHEX"; then fail "raw key found in pod-a.seal"; fi
unset KEYHEX

step "A3. daemon serves; path outside the grant is denied"
start_daemon "$WORK/a1.log" "$SOCK_A" COFFERAK_HOST_ID=pod-a
wait_socket "$DPID" "$SOCK_A" "$WORK/a1.log"
DPID_A="$DPID"
export COFFERAK_SOCKET="$SOCK_A"
export COFFERAK_TOKEN="$TOKEN"
printf 'value-1' | "$CLI" set myapp/A --stdin
[[ "$("$CLI" get myapp/A)" == "value-1" ]] || fail "get myapp/A != value-1"
if "$CLI" get other/thing >/dev/null 2>&1; then fail "path outside myapp was not denied"; fi

step "A4. restart: the value is durable"
stop_daemon "$DPID_A"
start_daemon "$WORK/a2.log" "$SOCK_A" COFFERAK_HOST_ID=pod-a
wait_socket "$DPID" "$SOCK_A" "$WORK/a2.log"
DPID_A="$DPID"
[[ "$("$CLI" get myapp/A)" == "value-1" ]] || fail "value lost across restart"

step "A5. a second 'init --host pod-a' fails and leaves the key untouched"
SUM_BEFORE="$(cksum <"$KEY_A")"
if "$CLI" init --host pod-a >"$WORK/reinit.log" 2>&1; then fail "second init --host pod-a succeeded"; fi
[[ "$(cksum <"$KEY_A")" == "$SUM_BEFORE" ]] || fail "key file changed by the failed init"
[[ "$(mode_of "$KEY_A")" == "600" ]] || fail "key file mode changed"

step "A6. enroll a second host (pod-b) and serve from it"
stop_daemon "$DPID_A"
"$CLI" enroll-host --this-host pod-a pod-b
[[ "$(size_of "$KEYDIR/pod-b.key")" == "32" ]] || fail "pod-b key file is not 32 bytes"
SOCK_B="$WORK/b.sock"
start_daemon "$WORK/b.log" "$SOCK_B" COFFERAK_HOST_ID=pod-b
wait_socket "$DPID" "$SOCK_B" "$WORK/b.log"
DPID_B="$DPID"
[[ "$(COFFERAK_SOCKET="$SOCK_B" "$CLI" get myapp/A)" == "value-1" ]] || fail "pod-b cannot read myapp/A"
stop_daemon "$DPID_B"
unset COFFERAK_SOCKET COFFERAK_TOKEN

step "A7. broken key material: the daemon refuses to start"
expect_refusal "missing key file" "$WORK/n1.sock" "$WORK/n1.log" "could not read host key file" \
  COFFERAK_HOST_ID=pod-a COFFERAK_HOST_KEY_FILE="$KEYDIR/nonexistent.key"
head -c 31 "$KEY_A" >"$KEYDIR/short.key"
expect_refusal "key file truncated to 31 bytes" "$WORK/n2.sock" "$WORK/n2.log" "expected 32" \
  COFFERAK_HOST_ID=pod-a COFFERAK_HOST_KEY_FILE="$KEYDIR/short.key"
head -c 32 /dev/urandom >"$KEYDIR/wrong.key"
cmp -s "$KEYDIR/wrong.key" "$KEY_A" && fail "random key equals the real key"
# the wrong key is well-formed, so only the message is unknown: any text matches ""
expect_refusal "wrong 32-byte key" "$WORK/n3.sock" "$WORK/n3.log" "" \
  COFFERAK_HOST_ID=pod-a COFFERAK_HOST_KEY_FILE="$KEYDIR/wrong.key"
expect_refusal "unknown seal backend" "$WORK/n4.sock" "$WORK/n4.log" 'unknown $COFFERAK_SEAL' \
  COFFERAK_HOST_ID=pod-a COFFERAK_SEAL=bogus
[[ "$(cksum <"$KEY_A")" == "$SUM_BEFORE" ]] || fail "key file changed during the negative cases"

# ---------------------------------------------------------------- Part B
step "B1. start the fake Cloud KMS / metadata server"
unset COFFERAK_HOST_KEY_FILE COFFERAK_DATA_DIR
KMS_KEY="projects/test-p/locations/global/keyRings/test-r/cryptoKeys/test-k"
OTHER_KEY="projects/test-p/locations/global/keyRings/test-r/cryptoKeys/other-k"
FAKE_LOG="$WORK/fake.log"; : >"$FAKE_LOG"
python3 "$FAKE" --port 0 --key "$KMS_KEY" --log "$FAKE_LOG" >"$WORK/fake.out" 2>&1 &
FAKE_PID=$!
PIDS="$PIDS $FAKE_PID"
PORT=""
for _ in $(seq 1 50); do
  PORT="$(sed -n 's/^listening on 127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' "$WORK/fake.out")"
  [[ -n "$PORT" ]] && break
  kill -0 "$FAKE_PID" 2>/dev/null || { cat "$WORK/fake.out" >&2; fail "fake KMS exited"; }
  sleep 0.1
done
[[ -n "$PORT" ]] || fail "fake KMS did not report its port"
export COFFERAK_SEAL=gcp-kms
export COFFERAK_GCP_KMS_KEY="$KMS_KEY"
export COFFERAK_GCP_KMS_ENDPOINT="http://127.0.0.1:$PORT"
export GCE_METADATA_HOST="127.0.0.1:$PORT"
# A gcloud that always fails, so the daemon's gcloud fallback cannot succeed.
STUB="$WORK/stub"; mkdir "$STUB"
printf '#!/bin/sh\nexit 1\n' >"$STUB/gcloud"; chmod +x "$STUB/gcloud"

step "B2. gcp-kms backend: create vault, host kms-a, service myapp"
DATA_B="$WORK/b"; mkdir -m 700 "$DATA_B"
SOCK_K="$WORK/k.sock"
export COFFERAK_DATA_DIR="$DATA_B"
"$CLI" init --root >/dev/null
"$CLI" init --host kms-a
TOKEN="$("$CLI" enroll-service myapp --paths myapp --perm rw | grep -E '^[0-9a-f]{64}$')"
[[ -n "$TOKEN" ]] || fail "could not parse the service token"
[[ "$(sed -n 1p "$DATA_B/hosts/kms-a.seal")" == "cofferak-gcp-kms-seal-v1" ]] || fail "kms-a.seal line 1"
[[ "$(sed -n 2p "$DATA_B/hosts/kms-a.seal")" == "$KMS_KEY" ]] || fail "kms-a.seal line 2 is not the key name"

step "B3. daemon: round trip, restart, read back"
count() { grep -c -- "$1" "$FAKE_LOG" || true; }
D0="$(count ':decrypt')"
start_daemon "$WORK/k1.log" "$SOCK_K" COFFERAK_HOST_ID=kms-a
wait_socket "$DPID" "$SOCK_K" "$WORK/k1.log"
DPID_K="$DPID"
[[ "$(count ':decrypt')" -gt "$D0" ]] || fail "first daemon start made no :decrypt call"
export COFFERAK_SOCKET="$SOCK_K" COFFERAK_TOKEN="$TOKEN"
printf 'kms-value' | "$CLI" set myapp/K --stdin
[[ "$("$CLI" get myapp/K)" == "kms-value" ]] || fail "kms round trip"
stop_daemon "$DPID_K"
D1="$(count ':decrypt')"
start_daemon "$WORK/k2.log" "$SOCK_K" COFFERAK_HOST_ID=kms-a
wait_socket "$DPID" "$SOCK_K" "$WORK/k2.log"
DPID_K="$DPID"
[[ "$(count ':decrypt')" -gt "$D1" ]] || fail "second daemon start made no :decrypt call"
[[ "$("$CLI" get myapp/K)" == "kms-value" ]] || fail "value lost across restart"
stop_daemon "$DPID_K"
unset COFFERAK_SOCKET COFFERAK_TOKEN

step "B4. the fake's log: :encrypt at init, :decrypt per start, all 200"
[[ "$(count ':encrypt')" -ge 1 ]] || fail "no :encrypt call logged"
[[ "$(grep -c -- ':encrypt 200$' "$FAKE_LOG" || true)" -ge 1 ]] || fail "no :encrypt with 200"
[[ "$(grep -c -- ':decrypt 200$' "$FAKE_LOG" || true)" -ge 2 ]] || fail "fewer than 2 :decrypt with 200"
if grep -v ' 200$' "$FAKE_LOG"; then fail "fake log has a non-200 request"; fi
if grep -q 'fake-token\|kms-value' "$FAKE_LOG"; then fail "fake log leaks a token or value"; fi

step "B5. negative: wrong KMS key, no metadata server, damaged .seal, no KMS"
expect_refusal "other KMS key" "$WORK/m1.sock" "$WORK/m1.log" "$OTHER_KEY" \
  COFFERAK_HOST_ID=kms-a COFFERAK_GCP_KMS_KEY="$OTHER_KEY"
grep -qF -- "$KMS_KEY" "$WORK/m1.log" || fail "other KMS key: message does not name the sealing key"

CLOSED="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
expect_refusal "no metadata server" "$WORK/m2.sock" "$WORK/m2.log" "metadata server" \
  COFFERAK_HOST_ID=kms-a GCE_METADATA_HOST="127.0.0.1:$CLOSED" PATH="$STUB"

cp -R "$DATA_B" "$WORK/b-damaged"; chmod 700 "$WORK/b-damaged"
awk 'NR==3 { print ($0 ~ /^A/ ? "B" : "A") substr($0, 2); next } { print }' \
  "$DATA_B/hosts/kms-a.seal" >"$WORK/b-damaged/hosts/kms-a.seal"
cmp -s "$DATA_B/hosts/kms-a.seal" "$WORK/b-damaged/hosts/kms-a.seal" && fail "failed to damage the .seal copy"
expect_refusal "damaged ciphertext" "$WORK/m3.sock" "$WORK/m3.log" "" \
  COFFERAK_HOST_ID=kms-a COFFERAK_DATA_DIR="$WORK/b-damaged"

step "B6. negative: KMS gone, the daemon fails instead of hanging"
stop_daemon "$FAKE_PID"
expect_refusal "KMS killed" "$WORK/m4.sock" "$WORK/m4.log" "" \
  COFFERAK_HOST_ID=kms-a PATH="$STUB"

echo "== seal backends check passed (file, gcp-kms) =="
