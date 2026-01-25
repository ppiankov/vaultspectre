#!/bin/bash
set -e

echo "==================================================================="
echo "VaultSpectre Audit Log Integration Test"
echo "==================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Vault is running
if ! command -v vault &> /dev/null; then
    echo -e "${RED}Error: vault command not found. Please install Vault first.${NC}"
    exit 1
fi

# Configuration
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
AUDIT_LOG_PATH="/tmp/vaultspectre-test-audit.log"
TEST_REPO="examples/audit-log-example"

echo "Step 1: Starting Vault in dev mode..."
vault server -dev -dev-root-token-id=root > /tmp/vault-dev.log 2>&1 &
VAULT_PID=$!
echo -e "${GREEN}✓ Vault started (PID: $VAULT_PID)${NC}"
sleep 3

cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $VAULT_PID 2>/dev/null || true
    rm -f $AUDIT_LOG_PATH /tmp/vault-dev.log
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}
trap cleanup EXIT

echo ""
echo "Step 2: Enabling file audit logging..."
vault audit enable file file_path=$AUDIT_LOG_PATH
echo -e "${GREEN}✓ Audit logging enabled${NC}"

echo ""
echo "Step 3: Creating test secrets..."
vault kv put secret/active-daily value=test description="Accessed frequently"
vault kv put secret/active-weekly value=test description="Accessed occasionally"
vault kv put secret/old-modified value=test description="Modified but not accessed"
vault kv put secret/never-accessed value=test description="Created but never read"
echo -e "${GREEN}✓ Created 4 test secrets${NC}"

echo ""
echo "Step 4: Simulating access patterns..."
echo "  - Accessing active-daily 10 times..."
for i in {1..10}; do
    vault kv get secret/active-daily > /dev/null 2>&1
done
echo "  - Accessing active-weekly 1 time..."
vault kv get secret/active-weekly > /dev/null 2>&1
echo "  - Modifying old-modified (but not reading)..."
vault kv put secret/old-modified value=updated > /dev/null 2>&1
echo "  - NOT accessing never-accessed"
echo -e "${GREEN}✓ Access patterns simulated${NC}"

sleep 2  # Allow audit log to be written

echo ""
echo "Step 5: Running VaultSpectre WITHOUT audit log (metadata only)..."
echo "-------------------------------------------------------------------"
./bin/vaultspectre scan \
  --repo $TEST_REPO \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --stale-days 0 2>&1 | grep -E "(Scanning|Found|Validating|Summary|OK|STALE)" || true

echo ""
echo ""
echo "Step 6: Running VaultSpectre WITH audit log (access-based)..."
echo "-------------------------------------------------------------------"
./bin/vaultspectre scan \
  --repo $TEST_REPO \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --audit-log-path $AUDIT_LOG_PATH \
  --audit-window-days 1 \
  --stale-days 0 2>&1

echo ""
echo "==================================================================="
echo "Test Results Summary"
echo "==================================================================="
echo ""
echo "Expected behavior:"
echo "  1. Without audit log: Uses metadata only (updated_time)"
echo "  2. With audit log: Shows access patterns"
echo "     - active-daily: accessed 10 times"
echo "     - active-weekly: accessed 1 time"
echo "     - old-modified: modified recently"
echo "     - never-accessed: no access records (stale)"
echo ""
echo -e "${GREEN}✓ Test complete!${NC}"
echo ""
echo "To examine the audit log directly:"
echo "  cat $AUDIT_LOG_PATH | jq 'select(.request.operation==\"read\")'"
