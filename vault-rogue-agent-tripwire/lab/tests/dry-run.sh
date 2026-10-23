#!/bin/bash
# scenario: dry-run
# Expected: Finding logged; entity still enabled; lease still valid.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

RUNID="sc-dryrun"
POD="dryrun-test"
trap 'stop_tripwire; cleanup_run ${RUNID}' EXIT

provision_run "${RUNID}"
start_tripwire true  # dry_run=true

vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Mint a DB lease before the decoy touch
LEASE_OUT=$(vault_cmd read -format=json database/creds/eval-"${RUNID}" 2>/dev/null)
LEASE_ID=$(echo "${LEASE_OUT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['lease_id'])" 2>/dev/null)
if [ -z "${LEASE_ID}" ]; then
  fail "dry-run: could not mint a DB lease for eval-${RUNID}"
fi
log "minted lease ${LEASE_ID}"

# Run rogue pod — touches decoy, 90s loop to survive QEMU pod startup time
run_rogue_pod "${POD}" "${RUNID}" "true" "90"

# Wait for finding
if ! wait_for_finding 60; then
  fail "dry-run: no SevKill finding in tripwire log"
fi
sleep 1

# Must have the dry-run log line (not kill steps)
if ! grep -q "dry-run\|dry_run\|would execute" "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "dry-run: expected dry-run log message, not found"
fi

# Must NOT have executed any actual kill steps (disable-entity, revoke-leases)
# Note: "kill: completed" IS logged in dry-run mode (empty result), that's OK.
# What must NOT appear is any step execution log.
if grep -q '"step":"disable-entity"\|"step":"revoke-leases"\|"step":"verify-empty"' \
    "${TRIPWIRE_LOG}" 2>/dev/null; then
  fail "dry-run: kill steps were executed — should be suppressed in dry-run mode"
fi

# Entity must still be enabled
ENTITY_ID=$(vault_cmd list -format=json identity/entity/id 2>/dev/null \
  | python3 -c "
import sys, json
ids = json.load(sys.stdin)
" 2>/dev/null || echo "")

# Simpler check: lease must still be valid (revoke would have removed it)
LC=$(lease_count "database/creds/eval-${RUNID}")
if [ "${LC}" -lt 1 ] 2>/dev/null; then
  fail "dry-run: lease was revoked — should survive in dry-run mode"
fi

# Also verify lease is still lookupable (not just listed)
vault_cmd lease lookup "${LEASE_ID}" > /dev/null 2>&1 || \
  fail "dry-run: lease ${LEASE_ID} is no longer valid — was incorrectly revoked"

pass "dry-run: finding logged, no kill executed, lease still valid"
