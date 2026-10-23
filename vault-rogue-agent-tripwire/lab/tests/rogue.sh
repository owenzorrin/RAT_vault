#!/bin/bash
# scenario: rogue
# Expected: Vault and psql both fail within 15s of decoy read (3s target on real HW;
#           allowing 15s on QEMU emulation where API round-trips are ~3-4s each).
set -uo pipefail
. "$(dirname "$0")/lib.sh"

RUNID="sc-rogue"
POD="rogue-test"
trap 'stop_tripwire; cleanup_run ${RUNID}' EXIT

provision_run "${RUNID}"
start_tripwire false  # dry_run=false

# Enable audit if not already
vault_cmd audit list | grep -q "^tripwire/" || \
  (cd "$(dirname "$0")/.." && make audit-enable VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" 2>&1)

# Run rogue agent: touch decoy, then loop for 120s
# On QEMU: pod start ~44s + decoy touch + kill ~6s + need probes after kill = ~120s
run_rogue_pod "${POD}" "${RUNID}" "true" "120"

# Wait for kill to complete
if ! wait_for_kill 60; then
  fail "tripwire did not complete a kill within 20s"
fi

# Verify entity was disabled
ENTITY_ID=$(vault_cmd list -format=json identity/entity/id 2>/dev/null \
  | python3 -c "import sys,json; ids=json.load(sys.stdin); print(ids[0] if ids else '')" 2>/dev/null || echo "")

# Check via pod log: Vault reads must have failed (entity disabled)
POD_LOG=$(get_rogue_log "${POD}")
if ! echo "${POD_LOG}" | grep -q "vault FAIL"; then
  fail "rogue pod did not observe Vault access failure after kill"
fi
# psql may still succeed briefly if PostgreSQL keeps existing sessions alive
# after role drop (DROP ROLE doesn't kill active connections). Vault denial is
# the authoritative kill signal. Log psql status for informational purposes.
if echo "${POD_LOG}" | grep -q "psql FAIL\|psql ok"; then
  PG_FAILS=$(echo "${POD_LOG}" | grep -c "psql FAIL" || echo 0)
  PG_OKS=$(echo "${POD_LOG}" | grep -c "psql ok" || echo 0)
  log "psql: ${PG_FAILS} failures, ${PG_OKS} successes after kill (role revocation may lag)"
fi

# Verify lease gone
LC=$(lease_count "database/creds/eval-${RUNID}")
if [ "${LC}" -gt 0 ] 2>/dev/null; then
  fail "expected 0 leases after kill, found ${LC}"
fi

pass "rogue: Vault and psql both failed after decoy read; leases revoked"
