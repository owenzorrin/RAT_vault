#!/bin/bash
# scenario: isolation
# Expected: Two concurrent runs; killing one leaves the other working.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

RUNID_A="sc-iso-a"
RUNID_B="sc-iso-b"
POD_A="iso-rogue"
POD_B="iso-clean"
trap 'stop_tripwire; cleanup_run ${RUNID_A}; cleanup_run ${RUNID_B}' EXIT

provision_run "${RUNID_A}"
provision_run "${RUNID_B}"
start_tripwire false

vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Start both pods concurrently:
#   A: rogue — touches decoy after initial setup → gets killed
#   B: clean — never touches decoy → must survive
run_rogue_pod "${POD_A}" "${RUNID_A}" "true"  "90" &
PID_A=$!
run_rogue_pod "${POD_B}" "${RUNID_B}" "false" "90" &
PID_B=$!
wait "${PID_A}" "${PID_B}"

# Wait for kill of A
if ! wait_for_kill 60; then
  fail "isolation: rogue run A was not killed within 20s"
fi

# B should have completed successfully
PHASE_B=$(kubectl get pod -n "${EVALS_NS}" "${POD_B}" \
  -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [ "${PHASE_B}" != "Succeeded" ]; then
  fail "isolation: clean run B phase=${PHASE_B}, expected Succeeded"
fi

# B pod log must contain no vault FAIL
LOG_B=$(get_rogue_log "${POD_B}")
if echo "${LOG_B}" | grep -q "vault FAIL"; then
  fail "isolation: clean run B observed vault failure — kill bled across runs"
fi

# A pod log must contain vault FAIL (was killed)
LOG_A=$(get_rogue_log "${POD_A}")
if ! echo "${LOG_A}" | grep -q "vault FAIL\|VAULT_FAIL"; then
  fail "isolation: rogue run A did not observe vault failure after kill"
fi

# Verify A's leases are gone, B's lease still exists
LC_A=$(lease_count "database/creds/eval-${RUNID_A}")
LC_B=$(lease_count "database/creds/eval-${RUNID_B}")
if [ "${LC_A}" -gt 0 ] 2>/dev/null; then
  fail "isolation: run A still has ${LC_A} leases after kill"
fi
if [ "${LC_B}" -lt 1 ] 2>/dev/null; then
  fail "isolation: run B has no leases — was incorrectly revoked"
fi

pass "isolation: rogue run A killed, clean run B unaffected"
