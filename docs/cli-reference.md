# CLI Reference

## `vaultspectre scan`

Scan a repository and validate against Vault.

```bash
vaultspectre scan \
  --repo ./my-repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN
```

### Key flags

| Flag | Description |
|------|-------------|
| `--repo` | Repository path to scan |
| `--vault-addr` | Vault server address |
| `--token` | Vault authentication token |
| `--output` | Output format (`text`, `json`) |
| `--fail-on-missing` | Exit non-zero if missing secrets found (CI/CD) |
| `--stale-days` | Flag secrets not accessed in N days |
| `--audit-log-path` | Path to Vault audit log for access-based staleness |
| `--audit-window-days` | Lookback window for audit log analysis |
| `--var` | Variable substitution (repeatable) |
| `--var-file` | Variable file for substitutions |
| `--detect-vars` | Auto-detect variable patterns |

### Usage examples

```bash
# JSON output
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json

# Fail on missing (CI/CD)
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --fail-on-missing

# Stale secret detection
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --stale-days 90

# With audit logs
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN \
  --audit-log-path /var/log/vault/audit.log --audit-window-days 90 --stale-days 60
```

## Configuration

### Environment variables

- `VAULT_ADDR` — Vault server address
- `VAULT_TOKEN` — Vault authentication token
- `VAULT_NAMESPACE` — Vault namespace (Enterprise)

### Config file

`.vaultspectre.yaml` in current or home directory.

## Scanner coverage

Finds Vault paths in:
- Ansible playbooks (`hashi_vault`, `vault_kv2_get`)
- YAML configurations
- Jinja templates
- Python / Bash scripts
- Terraform / Helm / Kustomize
- Environment files
- Arbitrary text files (regex fallback)

## Status classifications

| Status | Meaning |
|--------|---------|
| `OK` | Exists and accessible |
| `MISSING` | Referenced in repo but not in Vault |
| `ACCESS_DENIED` | Likely exists, no permission |
| `INVALID` | Malformed or not resolvable |
| `DYNAMIC` | Templated/variable-based (not verifiable) |

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
