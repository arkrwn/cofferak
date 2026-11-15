#!/usr/bin/env bash
# End-to-end check of the container image and the Helm chart (ADR 0021) on
# a real Kubernetes cluster (kind in CI), with mutual TLS from outside.
#
# Proves, against the real image and chart:
#   - the chart renders only for valid settings (bad ones are refused with a
#     message, not deployed half-configured)
#   - the pod starts on an EMPTY volume, stays not-Ready and says what it
#     waits for, and becomes Ready after `cofferak init --root` and
#     `init --host` run inside it
#   - the container is non-root with a read-only root filesystem
#   - a client outside the cluster, through a port-forward, reads and writes
#     secrets with all four kinds of check the SDK smoke tests make (mTLS,
#     token bound to its certificate, denied paths, sessions)
#   - the data survives the pod being deleted, without initialising again
#
# Needs: kubectl pointing at a cluster that can run the image, helm, python3,
# openssl. The image must already be in the cluster (kind load docker-image).
#   IMAGE=cofferak:dev ./scripts/kubernetes-check.sh
# It uses the file seal backend, so it needs no cloud account. The Cloud KMS
# backend is covered by scripts/seal-backends-check.sh.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
IMAGE="${IMAGE:-cofferak:dev}"
REPO="${IMAGE%:*}"; TAG="${IMAGE##*:}"
NS="cofferak-check-$$"
REL="cofferak-test"
POD="$REL-0"
HOST_ID="pod-a"
SERVICE="app1"
LOCAL_PORT="${LOCAL_PORT:-18443}"
CHART="$REPO_ROOT/deployment/helm/cofferak"
WORK="$(mktemp -d /tmp/cofferak-k8s.XXXXXX)"
PF_PID=""

fail() { echo "FAIL: $*" >&2; diagnose; exit 1; }
step() { echo "== $* =="; }
k() { kubectl -n "$NS" "$@"; }

diagnose() {
  echo "-- pods" >&2; k get pods -o wide >&2 2>&1 || true
  echo "-- describe" >&2; k describe pod "$POD" 2>&1 | tail -40 >&2 || true
  echo "-- logs" >&2; k logs "$POD" --tail=40 >&2 2>&1 || true
}
cleanup() {
  [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true
  helm uninstall "$REL" -n "$NS" >/dev/null 2>&1 || true
  kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pf_start() {
  kubectl -n "$NS" port-forward "pod/$POD" "$LOCAL_PORT:8443" >"$WORK/pf.log" 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 100); do
    python3 -c "import socket,sys; socket.create_connection(('127.0.0.1',$LOCAL_PORT),1).close()" 2>/dev/null && return 0
    kill -0 "$PF_PID" 2>/dev/null || { cat "$WORK/pf.log" >&2; fail "port-forward exited"; }
    sleep 0.2
  done
  cat "$WORK/pf.log" >&2; fail "port-forward did not open $LOCAL_PORT"
}
pf_stop() { [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; PF_PID=""; }

# sdk_py FILE: run a python program with the SDK and the TLS settings.
sdk_py() {
  COFFERAK_TLS_ADDR="127.0.0.1:$LOCAL_PORT" COFFERAK_TLS_SERVER_NAME="cofferak.test" \
  COFFERAK_TLS_CA="$WORK/tls/ca.pem" COFFERAK_TLS_CLIENT_CERT="$WORK/tls/$SERVICE.pem" \
  COFFERAK_TLS_CLIENT_KEY="$WORK/tls/$SERVICE.key" COFFERAK_TOKEN="$TOKEN" \
  PYTHONPATH="$REPO_ROOT/sdk/python/cofferak_sdk/src" python3 "$@"
}
connect_py='
import os
from cofferak_sdk import Client
c = Client.connect_tls(addr=os.environ["COFFERAK_TLS_ADDR"], server_name=os.environ["COFFERAK_TLS_SERVER_NAME"],
    ca_cert_path=os.environ["COFFERAK_TLS_CA"], client_cert_path=os.environ["COFFERAK_TLS_CLIENT_CERT"],
    client_key_path=os.environ["COFFERAK_TLS_CLIENT_KEY"])
t = os.environ["COFFERAK_TOKEN"]
'

step "chart: lint, and refusal of settings that cannot work"
helm lint "$CHART" --set seal.backend=file >/dev/null || fail "helm lint"
refuses() { # TEXT helm-args...
  local text="$1"; shift
  local out
  if out="$(helm template x "$CHART" "$@" 2>&1)"; then fail "helm template accepted: $*"; fi
  grep -q "$text" <<<"$out" || { echo "$out" >&2; fail "refusal for '$*' did not say '$text'"; }
}
refuses "seal.gcpKms.key" --set seal.backend=gcp-kms
refuses "seal.backend must be" --set seal.backend=nonsense
refuses "tls.existingSecret" --set seal.backend=file --set tls.enabled=true
helm template x "$CHART" --set seal.backend=gcp-kms \
  --set seal.gcpKms.key=projects/p/locations/global/keyRings/r/cryptoKeys/k >/dev/null \
  || fail "gcp-kms with a key must render"

step "certificates for server mode (CA, server, client named after its service)"
./scripts/gen-certs.sh "$WORK/tls" cofferak.test "$SERVICE" >/dev/null

step "install the chart on an empty volume (file seal backend, TLS on)"
kubectl create namespace "$NS" >/dev/null
k create secret generic cofferak-tls \
  --from-file=tls.crt="$WORK/tls/server.pem" --from-file=tls.key="$WORK/tls/server.key" \
  --from-file=ca.crt="$WORK/tls/ca.pem" >/dev/null
helm install "$REL" "$CHART" -n "$NS" \
  --set image.repository="$REPO" --set image.tag="$TAG" --set image.pullPolicy=Never \
  --set hostId="$HOST_ID" --set seal.backend=file \
  --set tls.enabled=true --set tls.existingSecret=cofferak-tls >/dev/null
k wait --for=jsonpath='{.status.phase}'=Running "pod/$POD" --timeout=240s >/dev/null \
  || fail "pod did not start"

step "the pod waits for initialisation and is not Ready"
for _ in $(seq 1 30); do k logs "$POD" 2>/dev/null | grep -q "waiting for initialisation" && break; sleep 1; done
k logs "$POD" | grep -q "waiting for initialisation" || fail "the daemon did not say it waits for initialisation"
[[ "$(k get pod "$POD" -o jsonpath='{.status.containerStatuses[0].ready}')" == "false" ]] \
  || fail "the pod is Ready before the vault exists"
[[ "$(k get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')" == "0" ]] \
  || fail "the daemon restarted instead of waiting"

step "the container is non-root, read-only, without capabilities"
[[ "$(k get pod "$POD" -o jsonpath='{.spec.securityContext.runAsNonRoot}')" == "true" ]] || fail "not runAsNonRoot"
[[ "$(k get pod "$POD" -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}')" == "true" ]] || fail "root filesystem is writable"
[[ "$(k get pod "$POD" -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}')" == "false" ]] || fail "privilege escalation allowed"
[[ "$(k get pod "$POD" -o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[0]}')" == "ALL" ]] || fail "capabilities not dropped"

step "initialise the vault inside the pod: root key, host, service"
ROOT_OUT="$(k exec "$POD" -- /usr/local/bin/cofferak init --root)"
grep -q "BEGIN COFFERAK ROOT PRIVATE KEY" <<<"$ROOT_OUT" || fail "init --root did not print the root key"
k exec "$POD" -- /usr/local/bin/cofferak init --host "$HOST_ID" >/dev/null
TOKEN="$(k exec "$POD" -- /usr/local/bin/cofferak enroll-service "$SERVICE" --paths app --perm rw | grep -E '^[0-9a-f]{64}$')"
[[ -n "$TOKEN" ]] || fail "could not read the service token"

step "the pod becomes Ready without a restart"
k wait --for=condition=Ready "pod/$POD" --timeout=120s >/dev/null || fail "pod never became Ready after init"
[[ "$(k get pod "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')" == "0" ]] \
  || fail "the daemon restarted during initialisation"
k exec "$POD" -- /usr/local/bin/cofferak doctor | grep -q "daemon is listening" || fail "doctor does not see the daemon"

step "a client outside the cluster: mutual TLS, token bound to its certificate, sessions"
pf_start
sdk_py "$REPO_ROOT/sdk/python/cofferak_sdk/examples/smoke_tls.py" app/k8s other/denied
sdk_py - <<PY
$connect_py
c.set(t, "app/persisted", b"survives-a-pod-restart")
assert c.get(t, "app/persisted") == b"survives-a-pod-restart"
PY
# A client with no certificate must be refused at the handshake.
if python3 - <<PY 2>/dev/null
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations("$WORK/tls/ca.pem")
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", $LOCAL_PORT), 5), server_hostname="cofferak.test")
s.sendall(b'{"List":{"token":"x","prefix":"app"}}\n')
data = s.recv(100)
raise SystemExit(0 if data else 1)
PY
then fail "a client without a certificate was served"; fi
pf_stop

step "delete the pod: the data is still there, no new initialisation"
k delete pod "$POD" --wait=true >/dev/null
for _ in $(seq 1 60); do k get pod "$POD" >/dev/null 2>&1 && break; sleep 1; done
k wait --for=condition=Ready "pod/$POD" --timeout=240s >/dev/null || fail "pod did not become Ready again by itself"
k logs "$POD" | grep -q "waiting for initialisation" && fail "the restarted pod asked to be initialised again"
pf_start
sdk_py - <<PY
$connect_py
assert c.get(t, "app/persisted") == b"survives-a-pod-restart", "the secret is gone after the restart"
PY
pf_stop

echo "== kubernetes check passed (chart, empty-volume start, init in pod, mTLS client, restart) =="
