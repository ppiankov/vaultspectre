---
name: vaultspectre
description: HashiCorp Vault secret auditor — finds missing, stale, and unused secrets by correlating code references with live Vault
user-invocable: false
metadata: {"requires":{"bins":["vaultspectre"]}}
---

# vaultspectre — Vault Secret Auditor

You have access to `vaultspectre`, a tool that scans codebases for Vault secret references, validates them against a live Vault instance, and detects missing, stale, and unused secrets.

## Install

```bash
go install github.com/ppiankov/vaultspectre/cmd/vaultspectre@latest
```

## Commands

| Command | What it does |
|---------|-------------|
| `vaultspectre scan --repo <path> --vault-addr <url>` | Scan code and validate against Vault |
| `vaultspectre version` | Print version |

## Key Flags

| Flag | Env Var | Description |
|------|---------|-------------|
| `--repo` | | Path to code repository to scan |
| `--vault-addr` | `VAULT_ADDR` | Vault server address |
| `--token` | `VAULT_TOKEN` | Vault authentication token |
| `--output` | | Output format: text (default), json |
| `--fail-on-missing` | | Exit 1 if MISSING secrets found (for CI) |
| `--stale-days` | | Flag secrets not touched in N days |
| `--audit-log-path` | | Path to Vault audit log file (JSON lines) |
| `--audit-window-days` | | Days of audit log to analyze (default 90) |

## Secret Statuses

| Status | Meaning |
|--------|---------|
| `OK` | Secret exists and is accessible |
| `MISSING` | Referenced in code, not present in Vault |
| `ACCESS_DENIED` | Likely exists, but token lacks permission |
| `INVALID` | Malformed or structurally broken path |
| `DYNAMIC` | Templated/variable-based, not statically verifiable |

## Supported File Types

The scanner detects Vault path references in:

- **Ansible** — `hashi_vault`, `vault_kv2_get` lookups
- **YAML** — configuration files with Vault paths
- **Jinja** — templates with Vault lookups
- **Python/Bash** — scripts with Vault CLI or API calls
- **Terraform** — `vault_generic_secret`, `vault_kv_secret_v2`
- **Helm/Kustomize** — chart values and overlays
- **Environment files** — `.env` with Vault references
- **Any text file** — regex fallback for `secret/` paths

## Agent Usage Pattern

```bash
# Basic scan with text output
vaultspectre scan --repo ./my-app --vault-addr https://vault.example.com --token $VAULT_TOKEN

# JSON output for parsing
vaultspectre scan --repo ./my-app --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json

# CI gate — fail if missing secrets
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --fail-on-missing

# Detect stale secrets (not touched in 90 days)
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --stale-days 90

# Enhanced staleness with audit log
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN \
  --audit-log-path /var/log/vault/audit.log --audit-window-days 90 --stale-days 60
```

### JSON Output Structure

SpectreHub-compatible output:

```json
{
  "tool": "vaultspectre",
  "version": "0.1.0",
  "timestamp": "2026-02-22T12:00:00Z",
  "config": {
    "vault_addr": "https://vault.example.com",
    "repo_path": "./my-repo",
    "stale_threshold_days": 90
  },
  "summary": {
    "total_references": 150,
    "status_ok": 120,
    "status_missing": 15,
    "status_access_denied": 5,
    "status_invalid": 3,
    "status_dynamic": 7,
    "stale_secrets": 8,
    "health_score": "warning"
  },
  "secrets": [
    {
      "path": "secret/data/prod/api/token",
      "status": "ok",
      "references": [
        {
          "file": "ansible/deploy.yml",
          "line": 42,
          "type": "ansible_lookup"
        }
      ]
    },
    {
      "path": "secret/data/prod/api/backup_key",
      "status": "missing",
      "references": [
        {
          "file": "scripts/backup.sh",
          "line": 15,
          "type": "env_var"
        }
      ]
    }
  ]
}
```

### Parsing Examples

```bash
# List missing secrets
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json | \
  jq '.secrets[] | select(.status == "missing") | .path'

# Count secrets by status
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json | \
  jq '.summary'

# Find stale secrets with file locations
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --stale-days 90 --output json | \
  jq '.secrets[] | select(.stale == true) | {path: .path, files: [.references[].file]}'
```

## Cross-Tool Integration

vaultspectre outputs SpectreHub-compatible JSON for aggregation with other spectre tools via [spectrehub](https://github.com/ppiankov/spectrehub).

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No issues or informational only |
| `1` | Missing secrets found (with --fail-on-missing) or error |

## What vaultspectre Does NOT Do

- Does not modify or delete Vault secrets — read-only validation
- Does not store Vault tokens — uses provided token only for the scan duration
- Does not require Vault admin access — works with read-only secret policies
- Does not use ML — deterministic pattern matching and validation
- Does not replace Vault audit logging — complements it with code correlation
