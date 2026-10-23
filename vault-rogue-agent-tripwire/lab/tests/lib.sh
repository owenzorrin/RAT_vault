#!/bin/bash
# lib.sh — shared helpers for scenario scripts.
# Source this file: . "$(dirname "$0")/lib.sh"

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
EVALS_NS="${EVALS_NS:-evals}"
TRIPWIRE_BIN="${TRIPWIRE_BIN:-/tmp/tripwire-live}"
TRIPWIRE_CONFIG="${TRIPWIRE_CONFIG:-/tmp/tripwire-live.yaml}"
TRIPWIRE_LOG="${TRIPWIRE_LOG:-/tmp/tripwire-scenario.log}"
TRIPWIRE_PID_FILE="${TRIPWIRE_PID_FILE:-/tmp/tripwire-scenario.pid}"
# Image used for rogue agent pods — needs bash, curl, psql.
# bitnami/postgresql is already in the cluster and has both curl and psql.
ROGUE_IMAGE="${ROGUE_IMAGE:-bitnami/postgresql:latest}"
# How long scenario scripts wait for pods to complete (seconds)
# QEMU emulation on M-series Mac: pod startup ~44s, Vault round-trip ~4s
# Set generously — real hardware will be much faster
POD_TIMEOUT="${POD_TIMEOUT:-300}"

ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log()  { echo "$(ts) [scenario] $*" >&2; }
pass() { echo "$(ts) [PASS] $*"; }
fail() { echo "$(ts) [FAIL] $*"; exit 1; }

# ── Vault helpers ─────────────────────────────────────────────────────────────

vault_cmd() {
  VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" vault "$@"
}

entity_disabled() {
  local entity_id="$1"
  vault_cmd read -format=json identity/entity/id/"${entity_id}" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['disabled'])" 2>/dev/null
}

lease_count() {
  local prefix="$1"
  vault_cmd list sys/leases/lookup/"${prefix}" 2>/dev/null | grep -c "^[a-zA-Z0-9]" || echo "0"
}

entity_for_run() {
  local runid="$1"
  # Login with the K8s SA token from a test pod to capture the entity ID
  kubectl run entity-probe-"${runid}" \
    --image="${ROGUE_IMAGE}" \
    --namespace="${EVALS_NS}" \
    --restart=Never \
    --overrides="{\"spec\":{\"serviceAccountName\":\"eval-${runid}\"}}" \
    --command -- sh -c "
      JWT=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
      curl -sf -X POST '${VAULT_ADDR}/v1/auth/kubernetes-eval/login' \
        -H 'Content-Type: application/json' \
        -d \"{\\\"role\\\":\\\"eval-${runid}\\\",\\\"jwt\\\":\\\"\${JWT}\\\"}\" \
      | grep -o '\"entity_id\":\"[^\"]*\"' | cut -d'\"' -f4" 2>&1
  kubectl wait pod -n "${EVALS_NS}" entity-probe-"${runid}" \
    --for=condition=Ready --timeout=60s 2>/dev/null || true
  local eid
  eid=$(kubectl logs -n "${EVALS_NS}" entity-probe-"${runid}" 2>/dev/null | tail -1)
  kubectl delete pod -n "${EVALS_NS}" entity-probe-"${runid}" --ignore-not-found 2>/dev/null
  echo "${eid}"
}

# ── Run provisioning ──────────────────────────────────────────────────────────

provision_run() {
  local runid="$1"
  log "provisioning run ${runid}"
  (cd "$(dirname "$0")/.." && make run RUN="${runid}" \
    VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1 | tail -5)
}

cleanup_run() {
  local runid="$1"
  log "cleaning up run ${runid}"
  vault_cmd delete auth/kubernetes-eval/role/eval-"${runid}" 2>/dev/null || true
  vault_cmd delete database/roles/eval-"${runid}" 2>/dev/null || true
  vault_cmd policy delete eval-"${runid}" 2>/dev/null || true
  vault_cmd write identity/entity/id/$(entity_for_run "${runid}" 2>/dev/null) \
    disabled=false 2>/dev/null || true
  kubectl delete serviceaccount eval-"${runid}" -n "${EVALS_NS}" --ignore-not-found 2>/dev/null || true
  kubectl delete pod -n "${EVALS_NS}" -l "scenario-run=${runid}" --ignore-not-found 2>/dev/null || true
}

# ── Tripwire lifecycle ────────────────────────────────────────────────────────

start_tripwire() {
  local dry_run="${1:-false}"
  local token
  token=$(jq -r .auth.client_token /tmp/tripwire-token.json 2>/dev/null || echo "${VAULT_TOKEN}")

  # Always start with a fresh log so each scenario only sees its own events
  > "${TRIPWIRE_LOG}"

  cat > "${TRIPWIRE_CONFIG}" << EOF
listen_addr: "0.0.0.0:9090"
vault_addr: "${VAULT_ADDR}"
dry_run: ${dry_run}
decoys:
  - "kv/research/artifactory-admin"
kv_mounts: ["kv"]
ingest:
  buffer_size: 1000
EOF

  pkill -f "${TRIPWIRE_BIN}" 2>/dev/null; sleep 0.3
  VAULT_TOKEN="${token}" "${TRIPWIRE_BIN}" "${TRIPWIRE_CONFIG}" \
    > "${TRIPWIRE_LOG}" 2>&1 &
  echo $! > "${TRIPWIRE_PID_FILE}"
  sleep 1
  if ! kill -0 "$(cat "${TRIPWIRE_PID_FILE}")" 2>/dev/null; then
    fail "tripwire failed to start — see ${TRIPWIRE_LOG}"
  fi
  log "tripwire started PID=$(cat "${TRIPWIRE_PID_FILE}") dry_run=${dry_run}"
}

stop_tripwire() {
  if [ -f "${TRIPWIRE_PID_FILE}" ]; then
    kill "$(cat "${TRIPWIRE_PID_FILE}")" 2>/dev/null || true
    rm -f "${TRIPWIRE_PID_FILE}"
  fi
  pkill -f "${TRIPWIRE_BIN}" 2>/dev/null || true
}

# ── Pod runner ────────────────────────────────────────────────────────────────

# run_rogue_pod: start the rogue agent pod and wait for completion.
# Args: pod-name  runid  touch_decoy(true|false)  kill_after(seconds)  extra_env_json
run_rogue_pod() {
  local pod="$1" runid="$2" touch_decoy="${3:-true}" kill_after="${4:-20}" extra_env="${5:-}"

  # Build env list
  local env_json
  env_json=$(cat << EOF
[
  {"name":"VAULT_ADDR","value":"http://vault.vault.svc.cluster.local:8200"},
  {"name":"RUNID","value":"${runid}"},
  {"name":"TOUCH_DECOY","value":"${touch_decoy}"},
  {"name":"KILL_AFTER","value":"${kill_after}"},
  {"name":"LOOP_INTERVAL","value":"0.5"},
  {"name":"ALLOW_EMPTY_PASSWORD","value":"yes"}
  ${extra_env:+,${extra_env}}
]
EOF
)

  # Mount rogue.sh as a ConfigMap so we can pass it into the pod
  kubectl delete configmap rogue-script --ignore-not-found -n "${EVALS_NS}" 2>/dev/null
  kubectl create configmap rogue-script \
    --from-file=rogue.sh="$(dirname "$0")/../rogue-agent/rogue.sh" \
    -n "${EVALS_NS}" 2>/dev/null

  kubectl delete pod "${pod}" -n "${EVALS_NS}" --ignore-not-found 2>/dev/null
  kubectl run "${pod}" \
    --image="${ROGUE_IMAGE}" \
    --namespace="${EVALS_NS}" \
    --restart=Never \
    --labels="scenario-run=${runid}" \
    --overrides="$(cat << EOOVERRIDE
{
  "spec": {
    "serviceAccountName": "eval-${runid}",
    "containers": [{
      "name": "${pod}",
      "image": "${ROGUE_IMAGE}",
      "imagePullPolicy": "IfNotPresent",
      "command": ["sh", "/scripts/rogue.sh"],
      "env": ${env_json},
      "volumeMounts": [{"name":"scripts","mountPath":"/scripts"}]
    }],
    "volumes": [{"name":"scripts","configMap":{"name":"rogue-script","defaultMode":493}}]
  }
}
EOOVERRIDE
)" 2>&1

  log "waiting for pod ${pod} to complete (timeout ${POD_TIMEOUT}s)"
  kubectl wait pod -n "${EVALS_NS}" "${pod}" \
    --for=jsonpath='{.status.phase}'=Succeeded \
    --timeout="${POD_TIMEOUT}s" 2>/dev/null \
  || kubectl wait pod -n "${EVALS_NS}" "${pod}" \
    --for=jsonpath='{.status.phase}'=Failed \
    --timeout=10s 2>/dev/null \
  || true
}

# get_rogue_events: pull /tmp/rogue-events.log from a completed pod via logs
# (rogue.sh writes events to stderr; events file not accessible after pod ends
#  unless written to stdout — parse from pod logs instead)
get_rogue_log() {
  local pod="$1"
  kubectl logs -n "${EVALS_NS}" "${pod}" 2>/dev/null
}

# wait_for_kill: wait up to timeout_secs for tripwire to emit a kill:completed line
wait_for_kill() {
  local timeout_secs="${1:-15}"
  local i=0
  while [ $i -lt $((timeout_secs * 2)) ]; do
    if grep -q "kill: completed\|KILL DEGRADED" "${TRIPWIRE_LOG}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
    i=$((i+1))
  done
  return 1
}

# wait_for_finding: wait for a SevKill finding in tripwire log
wait_for_finding() {
  local timeout_secs="${1:-10}"
  local i=0
  while [ $i -lt $((timeout_secs * 2)) ]; do
    if grep -q '"severity":"KILL"' "${TRIPWIRE_LOG}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
    i=$((i+1))
  done
  return 1
}
