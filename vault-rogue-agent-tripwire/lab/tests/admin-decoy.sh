#!/bin/bash
# scenario: admin-decoy
# Expected: Admin token reads decoy → SevPage alert logged, no kill fired.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

trap 'stop_tripwire' EXIT

start_tripwire false

vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Admin (root) token reads the decoy directly via port-forward
vault_cmd kv get kv/research/artifactory-admin > /dev/null 2>&1
sleep 2

# Must have a PAGE finding, must NOT have a KILL finding
if ! grep -q '"severity":"PAGE"' "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "admin-decoy: expected SevPage finding, none found in tripwire log"
fi

if grep -q '"severity":"KILL"' "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "admin-decoy: SevKill was fired for admin token — should be SevPage only"
fi

if grep -q "kill: completed\|kill: DEGRADED" "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "admin-decoy: kill action was executed — should not happen for admin token"
fi

pass "admin-decoy: SevPage logged, no kill executed"
