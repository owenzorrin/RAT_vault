#!/bin/bash
# scenario: tripwire-down
# Expected: Tripwire killed mid-run → pod Vault reads still succeed (A7).
set -uo pipefail
. "$(dirname "$0")/lib.sh"

RUNID="sc-tw-down"
POD="tw-down-test"
trap 'stop_tripwire; cleanup_run ${RUNID}' EXIT

provision_run "${RUNID}"
start_tripwire false

vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Start a clean pod (no decoy touch) that runs for 90s
# We'll kill tripwire after the pod has had time to start (~50s) and verify OK
run_rogue_pod "${POD}" "${RUNID}" "false" "90" &
RUN_PID=$!

# Wait for pod to be running and doing probes before killing tripwire
sleep 55

# Kill tripwire mid-run
log "killing tripwire (simulating process death)"
stop_tripwire
log "tripwire killed"

# Wait for pod to finish its 30s loop
wait "${RUN_PID}" || true

# The pod should have completed successfully despite tripwire being down
PHASE=$(kubectl get pod -n "${EVALS_NS}" "${POD}" \
  -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [ "${PHASE}" != "Succeeded" ]; then
  fail "tripwire-down: pod phase=${PHASE} after tripwire killed, expected Succeeded"
fi

# Pod log must show vault ok entries AFTER tripwire was killed
# (Pod starts at T=0, tripwire killed at ~T=6, pod finishes at ~T=30)
# All vault probes should be "vault ok"
POD_LOG=$(get_rogue_log "${POD}")
if echo "${POD_LOG}" | grep -q "vault FAIL"; then
  fail "tripwire-down: Vault reads failed after tripwire died — Vault must keep serving"
fi
VAULT_OK_COUNT=$(echo "${POD_LOG}" | grep -c "vault ok" || echo 0)
if [ "${VAULT_OK_COUNT}" -lt 5 ]; then
  fail "tripwire-down: expected >=5 successful vault probes, got ${VAULT_OK_COUNT}"
fi

pass "tripwire-down: Vault reads succeeded throughout despite tripwire process death"
