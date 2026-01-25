# VaultSpectre Quick Start Guide

## 5-Minute Demo

This guide will get you from zero to your first VaultSpectre scan in 5 minutes.

### Prerequisites

- Go 1.21+ (for building from source)
- HashiCorp Vault installed (for testing)
- Basic familiarity with Vault concepts

### Step 1: Build VaultSpectre

```bash
# Clone repository
git clone https://github.com/ppiankov/vaultspectre.git
cd vaultspectre

# Build binary
make build

# Verify
./bin/vaultspectre version
```

Expected output:
```
VaultSpectre v0.1.0
Part of the SpectreOps family
```

### Step 2: Start Vault in Dev Mode

```bash
# In a separate terminal
vault server -dev
```

This starts Vault at `http://127.0.0.1:8200` with root token `root`.

### Step 3: Create Test Secrets

```bash
# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Create some test secrets
vault kv put secret/prod/database/password value=secret123
vault kv put secret/prod/api/key value=apikey456
vault kv put secret/prod/deploy/token value=token789
vault kv put secret/staging/api/credentials username=user password=pass
```

### Step 4: Scan Example Repository

VaultSpectre includes an example repository with sample configurations:

```bash
cd examples

# Run scan
../bin/vaultspectre scan \
  --repo ./test-repo \
  --vault-addr http://127.0.0.1:8200 \
  --token root
```

### Expected Output

```
═══════════════════════════════════════════════════════════════
  VaultSpectre Report
═══════════════════════════════════════════════════════════════

Configuration:
  Vault:       http://127.0.0.1:8200
  Repository:  ./test-repo
  Scan Time:   2026-01-23 14:30:00

Summary:
  Total References:  8
  ├─ OK:             4
  ├─ Missing:        4
  ├─ Access Denied:  0
  └─ Errors:         0

  Health Score:      CRITICAL ⚠⚠

───────────────────────────────────────────────────────────────
Missing Secrets (4)
───────────────────────────────────────────────────────────────

  [MISSING] secret/data/prod/missing/secret
    Referenced in 1 location(s):
      - ansible/playbook.yml:14 (ansible_lookup)

  [MISSING] secret/data/prod/database/credentials
    Referenced in 1 location(s):
      - config/application.yml:5 (yaml_config)

  [MISSING] secret/data/prod/api/token
    Referenced in 1 location(s):
      - config/application.yml:7 (yaml_config)

  [MISSING] secret/data/prod/redis/password
    Referenced in 1 location(s):
      - config/application.yml:9 (yaml_config)
```

### Step 5: Create Missing Secrets

Now create the missing secrets:

```bash
vault kv put secret/prod/missing/secret value=test
vault kv put secret/prod/database/credentials username=db password=dbpass
vault kv put secret/prod/api/token value=apitoken
vault kv put secret/prod/redis/password value=redispass
```

### Step 6: Re-scan

```bash
../bin/vaultspectre scan \
  --repo ./test-repo \
  --vault-addr http://127.0.0.1:8200 \
  --token root
```

Now all secrets should show as `[OK]`:

```
Summary:
  Total References:  8
  ├─ OK:             8
  ├─ Missing:        0

  Health Score:      EXCELLENT ✓
```

### Step 7: Try JSON Output

```bash
../bin/vaultspectre scan \
  --repo ./test-repo \
  --vault-addr http://127.0.0.1:8200 \
  --token root \
  --output json > report.json

# View formatted JSON
cat report.json | jq .
```

### Step 8: Test Fail-on-Missing

Delete a secret and try the fail flag:

```bash
vault kv delete secret/prod/api/token

../bin/vaultspectre scan \
  --repo ./test-repo \
  --vault-addr http://127.0.0.1:8200 \
  --token root \
  --fail-on-missing

echo "Exit code: $?"
```

This should exit with code 1 and display the missing secret.

## Common Workflows

### Scan Your Own Repository

```bash
vaultspectre scan \
  --repo /path/to/your/repo \
  --vault-addr https://vault.yourcompany.com \
  --token $VAULT_TOKEN
```

### Detect Stale Secrets

```bash
vaultspectre scan \
  --repo . \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --stale-days 30
```

### Detect Stale Secrets with Audit Logs

For accurate access-based staleness detection:

```bash
# First, enable file audit logging in Vault (if not already enabled)
vault audit enable file file_path=/tmp/vault-audit.log

# Access some secrets to generate audit data
vault kv get secret/active

# Run scan with audit log
vaultspectre scan \
  --repo . \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --audit-log-path /tmp/vault-audit.log \
  --audit-window-days 90 \
  --stale-days 60
```

This will show which secrets are truly unused (not accessed in 60 days) versus just not modified.

### CI/CD Integration

Add to your `.gitlab-ci.yml` or `.github/workflows/ci.yml`:

```yaml
vault-audit:
  script:
    - |
      vaultspectre scan \
        --vault-addr $VAULT_ADDR \
        --token $VAULT_TOKEN \
        --fail-on-missing
```

### Generate Report for SpectreHub

```bash
vaultspectre scan \
  --repo . \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --output json > .spectre/vaultspectre-$(date -Iseconds).json
```

## Understanding the Output

### Status Codes

- **[OK]**: Secret exists and is accessible
- **[MISSING]**: Referenced in code but doesn't exist in Vault
- **[ACCESS_DENIED]**: Exists but your token lacks permission
- **[INVALID]**: Path is malformed
- **[STALE]**: Exists but hasn't been updated in N days

### Health Scores

- **EXCELLENT**: No issues found
- **GOOD**: <5% issues
- **WARNING**: 5-15% issues
- **CRITICAL**: 15-30% issues
- **SEVERE**: >30% issues

### Reference Types

- `ansible_lookup`: Ansible `lookup('hashi_vault', ...)`
- `ansible_module`: Ansible `vault_kv2_get` module
- `yaml_config`: YAML config file with vault_path/secret_path
- `terraform`: Terraform Vault data source
- `bash_script`: Shell script `vault read` command
- `python_code`: Python HVAC client call
- `k8s_annotation`: Kubernetes Vault injector annotation
- `generic`: Generic pattern match

## Troubleshooting

### "connection refused" error

Vault is not running or wrong address. Check:
```bash
vault status -address=$VAULT_ADDR
```

### "permission denied" errors

Token lacks read permission. Verify:
```bash
vault token lookup
vault policy list
```

### No references found

Check that your repository contains supported file types:
- `.yml`, `.yaml` - YAML configs
- `.py`, `.sh`, `.tf` - Scripts and IaC
- Check `docs/ARCHITECTURE.md` for full list

### False positives

VaultSpectre tries to filter out:
- Template variables: `${VAR}`, `{{ var }}`
- URLs: `http://`, `https://`
- Very short or very long paths

If you still get false positives, use JSON output and filter post-scan.

## Next Steps

1. **Read the Architecture**: `docs/ARCHITECTURE.md`
2. **Contribute**: `CONTRIBUTING.md`
3. **Join SpectreHub**: Integrate with other Spectre tools
4. **Automate**: Add to your CI/CD pipelines
5. **Share**: Star the repo, spread the word

## Getting Help

- **Issues**: https://github.com/ppiankov/vaultspectre/issues
- **Documentation**: `docs/` directory
- **Examples**: `examples/` directory

Welcome to the infrastructure archaeology team!
