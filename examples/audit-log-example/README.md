# Audit Log Integration Example

This example demonstrates VaultSpectre's audit log integration for accurate staleness detection.

## Setup

1. Start Vault in dev mode:

```bash
vault server -dev &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
```

2. Enable file audit logging:

```bash
vault audit enable file file_path=/tmp/vault-audit.log
```

3. Create test secrets:

```bash
# Create several secrets
vault kv put secret/active-daily value=test
vault kv put secret/active-weekly value=test
vault kv put secret/old-modified value=test
vault kv put secret/never-accessed value=test
```

4. Simulate access patterns:

```bash
# Access active-daily frequently
for i in {1..10}; do vault kv get secret/active-daily; done

# Access active-weekly once
vault kv get secret/active-weekly

# Modify old-modified but don't access it
vault kv put secret/old-modified value=updated

# never-accessed was created but never read
```

5. Wait for audit log to be written:

```bash
sleep 2
```

## Run VaultSpectre

### Without Audit Logs (Metadata Only)

```bash
../../bin/vaultspectre scan \
  --repo . \
  --vault-addr http://127.0.0.1:8200 \
  --token root \
  --stale-days 0
```

**Result**: All secrets appear "stale" because they were just created and `updated_time` is very recent.

### With Audit Logs (Access-Based)

```bash
../../bin/vaultspectre scan \
  --repo . \
  --vault-addr http://127.0.0.1:8200 \
  --token root \
  --audit-log-path /tmp/vault-audit.log \
  --audit-window-days 1 \
  --stale-days 0
```

**Result**: Shows which secrets were actually accessed:
- `active-daily`: NOT stale (accessed 10 times)
- `active-weekly`: NOT stale (accessed 1 time)
- `old-modified`: Stale or shows "modified" activity
- `never-accessed`: Stale (no access in audit log)

## Expected Output

```
═══════════════════════════════════════════════════════════════
  VaultSpectre Report
═══════════════════════════════════════════════════════════════

Configuration:
  Vault:       http://127.0.0.1:8200
  Repository:  .
  Scan Time:   2026-01-23 15:00:00

Summary:
  Total References:  4
  ├─ OK:             4
  ├─ Missing:        0
  ├─ Access Denied:  0
  └─ Errors:         0

  Stale Secrets:     1 (>0 days)

  Health Score:      GOOD

───────────────────────────────────────────────────────────────
Stale Secrets (1)
───────────────────────────────────────────────────────────────

  [STALE] secret/data/never-accessed
    Activity: 2026-01-23T14:30:00Z (modified, 0 days ago)
    Referenced in 1 location(s):
      - config.yml:4 (yaml_config)

═══════════════════════════════════════════════════════════════
  Part of the SpectreOps family
═══════════════════════════════════════════════════════════════
```

Note: `never-accessed` shows as stale because it has no access records in the audit log, even though it was recently created.

## Cleanup

```bash
# Stop Vault
pkill vault

# Remove audit log
rm /tmp/vault-audit.log
```

## Key Insights

This example demonstrates:

1. **Metadata alone is insufficient**: A secret modified recently but never accessed appears "fresh"
2. **Access patterns matter**: Frequently accessed secrets are clearly identified
3. **True staleness**: Secrets that exist but are never read are truly unused
4. **Graceful degradation**: Without audit logs, VaultSpectre still works with metadata
