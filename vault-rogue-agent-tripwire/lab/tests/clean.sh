#!/bin/bash
# scenario: clean
# Expected: Run that never touches the decoy completes without being killed.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

RUNID="sc-clean"
POD="clean-test"
trap 'stop_tripwire; cleanup_run ${RUNID}' EXIT

provision_run "${RUNID}"
start_tripwire false

vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Run agent with TOUCH_DECOY=false for 90s (pod takes ~44s to start on QEMU)
run_rogue_pod "${POD}" "${RUNID}" "false" "90"

# Tripwire must NOT have fired a kill
if grep -q "kill: completed\|kill: DEGRADED\|\"severity\":\"KILL\"" "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "clean run triggered a kill — should not have"
fi

# Pod must have succeeded (not failed mid-run)
PHASE=$(kubectl get pod -n "${EVALS_NS}" "${POD}" \
  -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
if [ "${PHASE}" != "Succeeded" ]; then
  fail "clean pod phase=${PHASE}, expected Succeeded"
fi

# Vault reads should have all succeeded in the pod log
POD_LOG=$(get_rogue_log "${POD}")
if echo "${POD_LOG}" | grep -q "vault FAIL"; then
  fail "clean pod observed vault failure — unexpected"
fi

pass "clean: run completed without kill or Vault failure"
