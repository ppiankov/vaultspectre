# VaultSpectre - Complete MVP Specification

## Executive Summary

VaultSpectre is a Go-based static + runtime auditor for HashiCorp Vault secret usage. It bridges the gap between code and infrastructure by scanning repositories for secret references and validating them against live Vault instances.

**Problem**: Organizations lose track of which secrets exist in Vault, which are referenced in code, and which are stale. This leads to broken deployments, security gaps, and credential sprawl.

**Solution**: VaultSpectre automatically discovers all Vault secret references in your codebase, validates them, and identifies missing, stale, or broken paths before they cause production issues.

## Core Value Propositions

1. **Prevent Deployment Failures**: Catch missing secrets before they break production
2. **Security Hygiene**: Identify stale secrets that should be rotated or removed
3. **Compliance**: Maintain audit trails of secret usage across services
4. **Cost Reduction**: Clean up unused secrets and reduce Vault overhead
5. **CI/CD Integration**: Block merges that reference non-existent secrets

## Architecture

VaultSpectre follows the Spectre family pattern established by KafkaSpectre and ClickSpectre:

- **Language**: Go 1.21+
- **CLI Framework**: Cobra
- **Report Format**: JSON (SpectreHub compatible) + Human-readable text
- **Deployment**: Single static binary, multi-platform

### Pipeline Flow

```
Repository Scan → Reference Extraction → Vault Validation → Analysis → Reporting
```

## Features (MVP v0.1)

### 1. Multi-Format Repository Scanner

Scans for Vault secret paths in:

#### Ansible
```yaml
# Lookups
secret: "{{ lookup('hashi_vault', 'secret/data/prod/api/key') }}"

# Modules
- vault_kv2_get:
    path: secret/data/prod/database/password

- vault_read:
    path: secret/data/staging/credentials
```

#### YAML Configurations
```yaml
application:
  vault_path: secret/data/prod/config
  database:
    secret_path: secret/data/prod/db/password
```

#### Terraform/HCL
```hcl
data "vault_generic_secret" "api_key" {
  path = "secret/data/prod/api/token"
}

data "vault_kv_secret_v2" "db" {
  mount = "secret"
  name  = "prod/database/credentials"
}
```

#### Python (HVAC)
```python
import hvac

client = hvac.Client(url='http://vault:8200')
secret = client.secrets.kv.v2.read_secret(path='prod/api/key')
data = client.read('secret/data/prod/database/password')
```

#### Shell Scripts
```bash
vault kv read secret/data/prod/deploy/token
vault read secret/data/staging/api/credentials
export TOKEN=$(vault kv get -field=value secret/data/prod/token)

curl $VAULT_ADDR/v1/secret/data/prod/api/key
```

#### Kubernetes (Vault Injector)
```yaml
annotations:
  vault.hashicorp.com/agent-inject-secret-db: "secret/data/prod/database/password"
  vault.hashicorp.com/agent-inject-secret-api: "secret/data/prod/api/token"
```

#### Go Code
```go
secret, err := client.Logical().Read("secret/data/prod/api/key")
```

#### Generic Patterns
- Jinja templates: `{{ vault('secret/data/prod/key') }}`
- Environment files: `VAULT_PATH=secret/data/prod/config`
- Configuration files with standard patterns

### 2. Vault Path Validator

Connects to Vault and validates each discovered path:

**Validation Logic**:
```go
// Attempt to read secret
secret, err := vaultClient.Read(path)

if err != nil {
    if err.Contains("permission denied") || err.Contains("403") {
        return "access_denied"
    }
    return "error"
}

if secret == nil {
    return "missing"
}

return "ok"
```

**Status Categories**:
- **OK**: Secret exists and is accessible with current token
- **MISSING**: Referenced in code but doesn't exist in Vault
- **ACCESS_DENIED**: Likely exists but token lacks permission
- **INVALID**: Path is malformed or cannot be resolved
- **DYNAMIC**: Contains variables/templates (can't validate statically)
- **ERROR**: Validation failed for other reasons

**KV Version Support**:
- KV v2 (primary): `secret/data/path/to/secret`
- KV v1 (fallback): `secret/path/to/secret`
- Auto-detection based on mount metadata

### 3. Staleness Detection

Uses Vault metadata to identify unused secrets:

**For KV v2**:
```go
metadata := vaultClient.GetMetadata(mount, path)
updatedTime := metadata.Data["updated_time"]

daysSinceUpdate := time.Since(updatedTime).Days()
if daysSinceUpdate > threshold {
    return "stale"
}
```

**Staleness Indicators**:
- Last updated > N days (configurable, default 90)
- Not referenced in scanned repositories
- No recent access (via audit logs in v0.2)

**Use Cases**:
- Find secrets from decommissioned services
- Identify candidates for rotation
- Clean up "just in case" secrets from 2019

### 4. Dual Report Format

#### Text Report (Human-Readable)

```
═══════════════════════════════════════════════════════════════
  VaultSpectre Report
═══════════════════════════════════════════════════════════════

Configuration:
  Vault:       https://vault.example.com
  Repository:  /path/to/repo
  Scan Time:   2026-01-23 14:30:00

Summary:
  Total References:  42
  ├─ OK:             35
  ├─ Missing:        5
  ├─ Access Denied:  1
  └─ Errors:         1
  Stale Secrets:     3 (>90 days)

  Health Score:      WARNING ⚠

───────────────────────────────────────────────────────────────
Missing Secrets (5)
───────────────────────────────────────────────────────────────

  [MISSING] secret/data/prod/api/backup_key
    Referenced in 3 location(s):
      - ansible/backup.yml:15 (ansible_lookup)
      - scripts/backup.sh:8 (bash_script)
      - config/backup.yaml:12 (yaml_config)

  [MISSING] secret/data/staging/old-service/token
    Referenced in 1 location(s):
      - terraform/staging.tf:45 (terraform)

───────────────────────────────────────────────────────────────
Stale Secrets (3)
───────────────────────────────────────────────────────────────

  [STALE] secret/data/prod/deprecated-api/key
    Last accessed: 2024-03-15T10:30:00Z
    Referenced in 1 location(s):
      - legacy/old-deploy.yml:22 (ansible_lookup)
```

#### JSON Report (SpectreHub Compatible)

```json
{
  "tool": "vaultspectre",
  "version": "0.1.0",
  "timestamp": "2026-01-23T14:30:00Z",
  "config": {
    "vault_addr": "https://vault.example.com",
    "repo_path": "/path/to/repo",
    "stale_threshold_days": 90
  },
  "summary": {
    "total_references": 42,
    "status_ok": 35,
    "status_missing": 5,
    "status_access_denied": 1,
    "status_invalid": 0,
    "status_error": 1,
    "stale_secrets": 3,
    "health_score": "warning"
  },
  "secrets": {
    "secret/data/prod/api/backup_key": {
      "path": "secret/data/prod/api/backup_key",
      "status": "missing",
      "references": [
        {
          "file": "ansible/backup.yml",
          "line": 15,
          "type": "ansible_lookup"
        },
        {
          "file": "scripts/backup.sh",
          "line": 8,
          "type": "bash_script"
        }
      ]
    }
  }
}
```

### 5. CI/CD Integration

**Fail on Missing Secrets**:
```bash
vaultspectre scan \
  --repo . \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --fail-on-missing \
  --output json > vaultspectre-report.json

# Exit code 1 if missing secrets found
```

**GitHub Actions Example**:
```yaml
- name: Audit Vault Secrets
  run: |
    vaultspectre scan \
      --repo . \
      --vault-addr ${{ secrets.VAULT_ADDR }} \
      --token ${{ secrets.VAULT_TOKEN }} \
      --fail-on-missing
```

**GitLab CI Example**:
```yaml
vault_audit:
  script:
    - vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json
  artifacts:
    reports:
      vaultspectre: vaultspectre-report.json
```

## Installation & Usage

### Binary Installation

```bash
# Download latest release
curl -LO https://github.com/ppiankov/vaultspectre/releases/latest/download/vaultspectre-linux-amd64

# Make executable
chmod +x vaultspectre-linux-amd64
sudo mv vaultspectre-linux-amd64 /usr/local/bin/vaultspectre

# Verify
vaultspectre version
```

### Build from Source

```bash
git clone https://github.com/ppiankov/vaultspectre.git
cd vaultspectre
make build
./bin/vaultspectre version
```

### Basic Usage

```bash
# Scan current directory
vaultspectre scan \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN

# Scan specific repository
vaultspectre scan \
  --repo /path/to/repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN

# JSON output
vaultspectre scan --output json > report.json

# Detect stale secrets (not accessed in 60 days)
vaultspectre scan --stale-days 60

# Fail pipeline on issues
vaultspectre scan --fail-on-missing

# Vault Enterprise with namespace
vaultspectre scan \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN \
  --namespace production
```

## SpectreHub Integration

VaultSpectre outputs conform to the SpectreHub JSON schema for centralized aggregation:

```json
{
  "tool": "vaultspectre",
  "timestamp": "2026-01-23T14:30:00Z",
  "version": "0.1.0",
  "items": [...]
}
```

SpectreHub can aggregate reports from:
- VaultSpectre (secrets)
- KafkaSpectre (topics)
- ClickSpectre (tables)
- PgSpectre (databases)
- MongoSpectre (collections)
- S3Spectre (buckets)

Combined view enables cross-system analysis:
```
SUMMARY across all Spectres:
- Vault secrets missing: 5
- Kafka topics unused: 12
- ClickHouse tables stale: 8
- S3 buckets orphaned: 3
```

## Health Score Algorithm

```go
func calculateHealthScore(summary Summary) string {
    if summary.TotalReferences == 0 {
        return "unknown"
    }

    // Hard issues: missing, invalid, errors
    issues := summary.StatusMissing + summary.StatusInvalid + summary.StatusError
    issuePercent := float64(issues) / float64(summary.TotalReferences) * 100

    // Soft issues: stale secrets (50% weight)
    stalePercent := float64(summary.StaleSecrets) / float64(summary.TotalReferences) * 100
    totalIssuePercent := issuePercent + (stalePercent * 0.5)

    if totalIssuePercent == 0 {
        return "excellent"     // 0% issues
    } else if totalIssuePercent < 5 {
        return "good"          // <5% issues
    } else if totalIssuePercent < 15 {
        return "warning"       // 5-15% issues
    } else if totalIssuePercent < 30 {
        return "critical"      // 15-30% issues
    }
    return "severe"            // >30% issues
}
```

## Real-World Use Cases

### Use Case 1: Pre-Deployment Validation

**Problem**: Dev team deploys to staging, deployment fails because `secret/data/staging/new-api/key` doesn't exist.

**Solution**:
```bash
# In CI pipeline before deploy
vaultspectre scan \
  --repo . \
  --vault-addr $STAGING_VAULT \
  --token $CI_VAULT_TOKEN \
  --fail-on-missing

# Pipeline fails, reports:
# [MISSING] secret/data/staging/new-api/key
#   Referenced in: kubernetes/deployment.yaml:45
```

### Use Case 2: Secret Cleanup

**Problem**: Vault contains 500+ secrets, many from decomm services. Which can be safely deleted?

**Solution**:
```bash
vaultspectre scan \
  --repo /all-repos \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --stale-days 180 \
  --output json > cleanup-candidates.json

# Analyze report to find:
# - Secrets not referenced anywhere
# - Secrets >180 days old
# - Safe deletion candidates
```

### Use Case 3: Migration Validation

**Problem**: Migrating from `secret/` to `kv/` mount. Need to verify all refs updated.

**Solution**:
```bash
# Before migration
vaultspectre scan --output json > before.json

# Update code to reference kv/ instead of secret/
# After migration
vaultspectre scan --output json > after.json

# Compare reports
# All secret/* paths should be missing (good)
# All kv/* paths should be ok (good)
```

### Use Case 4: Security Audit

**Problem**: Security team needs list of all Vault secrets referenced by production services.

**Solution**:
```bash
vaultspectre scan \
  --repo /prod-repos \
  --vault-addr $PROD_VAULT \
  --token $AUDIT_TOKEN \
  --output json > prod-audit.json

# Report provides:
# - Complete inventory of referenced secrets
# - Which services use which secrets
# - Access denied paths (permission gaps)
```

## Roadmap

### v0.2 - Enhanced Detection
- Audit log integration for access patterns
- Concurrent Vault API calls with rate limiting
- Config file support (`.vaultspectre.yaml`)
- Exclude patterns for false positives
- Custom pattern injection

### v0.3 - Advanced Features
- Secret ownership mapping (service → secrets)
- Usage dependency graph
- Multi-Vault support
- Namespace hierarchy support
- Dynamic template expansion (limited)
- Diff mode (compare scans)

### v1.0 - Production Ready
- Secret rotation recommendations
- Policy violation detection
- Automated remediation suggestions
- Historical trend analysis
- Web UI (optional)
- Prometheus metrics export

## Comparison with Alternatives

| Feature | VaultSpectre | Manual Audit | Vault CLI | Other Tools |
|---------|--------------|--------------|-----------|-------------|
| Auto-discovery | ✅ | ❌ | ❌ | ⚠️ |
| Multi-format | ✅ | ⚠️ | ❌ | ⚠️ |
| Staleness detection | ✅ | ❌ | ⚠️ | ❌ |
| CI/CD integration | ✅ | ❌ | ⚠️ | ⚠️ |
| SpectreHub compatible | ✅ | ❌ | ❌ | ❌ |
| Zero dependencies | ✅ | - | ❌ | ❌ |
| Go performance | ✅ | - | ✅ | ⚠️ |

## Limitations (MVP)

1. **No Dynamic Expansion**: Paths with variables (`secret/data/${ENV}/key`) marked as "dynamic", not validated
2. **Sequential Validation**: Vault API calls are sequential (future: concurrent)
3. **KV v2 Focus**: KV v1 and other engines have limited support
4. **No Audit Logs**: Staleness based on metadata only (future: audit log analysis)
5. **In-Memory Processing**: Large repos (100k+ files) may use significant memory
6. **Single Vault**: One Vault instance per scan (future: multi-Vault)

## FAQ

**Q: Does VaultSpectre read secret values?**
A: No. It only validates path existence and metadata. Secret values never leave Vault.

**Q: What permissions does the token need?**
A: Read access to the secret paths being validated. Metadata read for staleness detection.

**Q: Can it handle templated paths like `${ENVIRONMENT}/api/key`?**
A: MVP marks these as "dynamic" and skips validation. v0.3 will support limited expansion.

**Q: Does it work with Vault namespaces (Enterprise)?**
A: Yes, use `--namespace` flag. v0.3 will support hierarchy.

**Q: How fast is it?**
A: Scanning: ~1000 files/sec. Validation: ~10-50 paths/sec (Vault API dependent).

**Q: Can I exclude certain paths or patterns?**
A: v0.2 will add exclude patterns. MVP: filter JSON report post-scan.

**Q: Does it support non-KV engines (PKI, Transit, etc.)?**
A: MVP focuses on KV secrets. Other engines are on the roadmap.

## Conclusion

VaultSpectre fills a critical gap in Vault operations: **automated secret reference auditing**. It prevents deployment failures, enables safe cleanup, and provides visibility into secret usage across your entire codebase.

As part of the Spectre family, it integrates with SpectreHub for holistic infrastructure cleanup intelligence.

**Get started**:
```bash
git clone https://github.com/ppiankov/vaultspectre.git
cd vaultspectre
make build
./bin/vaultspectre scan --vault-addr $VAULT_ADDR --token $VAULT_TOKEN
```

Welcome to the infrastructure archaeology team. Grab a broom. The secrets are waiting.
