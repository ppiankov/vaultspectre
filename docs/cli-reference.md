# CLI Reference

## `vaultspectre scan`

Scan a repository and validate against Vault.

```bash
vaultspectre scan \
  --repo ./my-repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN
```

### Flags

| Flag | Description |
|------|-------------|
| `--repo` | Repository path to scan (default `.`) |
| `--vault-addr` | Vault server address (or `VAULT_ADDR` env) |
| `--token` | Vault authentication token (or `VAULT_TOKEN` env) |
| `--namespace` | Vault namespace, Enterprise only (or `VAULT_NAMESPACE` env) |
| `--format` | Output format: `text`, `json`, `sarif`, `spectrehub` (default `text`) |
| `--exclude` | Comma-separated glob patterns to skip (e.g. `vendor/**,testdata/**`) |
| `--fail-on-missing` | Exit 6 if missing secrets found (CI/CD) |
| `--stale-days` | Flag secrets not accessed in N days (default 90, 0 to disable) |
| `--audit-log-path` | Path to Vault audit log for access-based staleness |
| `--audit-window-days` | Lookback window for audit log analysis (default 90) |
| `--var` | Variable substitution `key=value` (repeatable) |
| `--var-file` | YAML file containing variable values |
| `--detect-vars` | Auto-detect variables from Ansible inventory |
| `--baseline` | Path to baseline file for suppressing known findings |
| `--update-baseline` | Save current findings as new baseline |
| `--timeout` | Vault API timeout in seconds (default 30) |
| `--verbose` | Show detailed variable resolution and path info |

### Examples

```bash
# JSON output
vaultspectre scan --repo . --format json

# Fail on missing (CI/CD)
vaultspectre scan --repo . --fail-on-missing

# Exclude vendor and test files
vaultspectre scan --repo . --exclude "vendor/**,testdata/**,*_test.go"

# Stale secret detection with audit logs
vaultspectre scan --repo . --stale-days 60 \
  --audit-log-path /var/log/vault/audit.log

# SARIF for GitHub Security tab
vaultspectre scan --repo . --format sarif > results.sarif
```

## `vaultspectre watch`

Continuous drift detection with delta reporting.

```bash
vaultspectre watch --interval 5m --repo . \
  --vault-addr $VAULT_ADDR --token $VAULT_TOKEN
```

### Flags

All `scan` flags apply, plus:

| Flag | Description |
|------|-------------|
| `--interval` | Scan interval (default `5m`, e.g. `1m`, `1h`) |
| `--slack-webhook` | Slack webhook URL for notifications |

### Examples

```bash
# Watch every minute with Slack alerts
vaultspectre watch --interval 1m --slack-webhook $SLACK_URL

# Watch with JSON delta output
vaultspectre watch --interval 5m --format json
```

## `vaultspectre init`

Generate a starter `.vaultspectre.yaml` config file.

```bash
vaultspectre init
vaultspectre init --force  # overwrite existing
```

## `vaultspectre version`

Print version and commit hash.

```bash
vaultspectre version
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Internal error |
| 2 | Invalid arguments or config error |
| 5 | Network/connectivity error (Vault unreachable) |
| 6 | Findings detected (missing/stale/invalid secrets) |

## Configuration

### Environment variables

- `VAULT_ADDR` — Vault server address
- `VAULT_TOKEN` — Vault authentication token
- `VAULT_NAMESPACE` — Vault namespace (Enterprise)

### Config file

`.vaultspectre.yaml` in current directory or home directory. Generate with `vaultspectre init`.

CLI flags override config file values.

## Scanner coverage

Finds Vault paths in:
- Ansible playbooks (`hashi_vault`, `vault_kv2_get`)
- YAML configurations
- Jinja templates
- Python / Bash scripts
- Terraform / Helm / Kustomize
- Go source code
- Kubernetes manifests
- Environment files

## Status classifications

| Status | Meaning |
|--------|---------|
| `ok` | Exists and accessible |
| `missing` | Referenced in code but not in Vault |
| `access_denied` | Likely exists, no permission |
| `invalid` | Malformed or not resolvable |
| `needs_resolution` | Contains variables, not verifiable without values |
| `skipped_policy` | Skipped (policy wildcard path) |
| `stale` | Exists but not accessed within threshold |

## Installation

### Homebrew

```bash
brew install ppiankov/tap/vaultspectre
```

### Docker

```bash
docker run ghcr.io/ppiankov/vaultspectre scan --repo /repo --vault-addr $VAULT_ADDR --token $VAULT_TOKEN
```

### GitHub Action

```yaml
- uses: ppiankov/vaultspectre-action@v1
  with:
    vault-addr: ${{ secrets.VAULT_ADDR }}
    token: ${{ secrets.VAULT_TOKEN }}
    format: sarif
    upload-sarif: 'true'
```
