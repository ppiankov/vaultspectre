# vaultspectre

HashiCorp Vault secrets security auditor.

## Install

```
brew install ppiankov/tap/vaultspectre
```

Or via Go:

```
go install github.com/ppiankov/vaultspectre/cmd/vaultspectre@latest
```

## Commands

### vaultspectre audit

SpectreHub-compatible entry point. Equivalent to `scan` with spectrehub output format and SpectreHub exit code conventions. This is what SpectreHub invokes.

**Exit codes (SpectreHub convention):**
- 0: success (no findings)
- 1: findings detected
- 2: invalid arguments
- 3: runtime error

Accepts all `scan` flags. Default format: spectrehub.

### vaultspectre scan

Scans code for Vault secret references and validates against live Vault.

**Flags:**
- `--format json` — output as JSON (spectre/v1 envelope)
- `--format sarif` — SARIF format for CI integration
- `--format spectrehub` — SpectreHub aggregator format
- `--exclude pattern` — comma-separated glob patterns to skip (e.g. `vendor/**,testdata/**`)
- `--baseline path` — suppress known findings
- `--fail-on-missing` — exit 6 if missing secrets found
- `--detect-vars` — auto-detect variables from Ansible inventory
- `--var key=value` — set variable for path resolution
- `--stale-days N` — stale secret threshold (default 90)
- `--timeout N` — Vault API timeout in seconds (default 30)

**Policy enforcement:**
- `--policy policy.yaml` — evaluate scan results against policy rules

**Policy file format (YAML):**
```yaml
max_findings:
  missing: 0
  error: 0
required_path_prefixes:
  - "kv/projects/"
forbidden_path_prefixes:
  - "kv/deprecated/"
max_stale_percent: 10
```

Generate with: `vaultspectre init --with-policy`

**Authentication flags (all commands that connect to Vault):**
- `--auth-method token` — use static token (default)
- `--auth-method approle --role-id ID --secret-id ID` — AppRole auth
- `--auth-method kubernetes --k8s-role ROLE` — Kubernetes ServiceAccount auth

**Exit codes:**
- 0: scan complete, no findings
- 1: internal error
- 2: invalid arguments or config error
- 5: network/connectivity error (Vault unreachable)
- 6: findings detected (missing/stale/invalid secrets)

### vaultspectre watch

Continuous drift detection with delta reporting.

**Flags:**
- `--interval duration` — scan interval (default 5m)
- `--slack-webhook url` — Slack webhook URL for notifications
- All `scan` flags also apply (--repo, --vault-addr, --token, --format, --exclude, etc.)

**Exit codes:**
- 0: clean shutdown, no findings ever detected
- 6: findings were detected during at least one run

### vaultspectre init

Generate a starter `.vaultspectre.yaml` config file.

**Flags:**
- `--force` — overwrite existing config

**Exit codes:**
- 0: config created
- 1: config already exists or error

### vaultspectre ls

List Vault secret paths recursively. No secret data is read.

**Flags:**
- `--path kv/projects/` — Vault path to list (also accepts positional arg)
- `--depth N` — max recursion depth (0 = unlimited)
- `--tree` — indented tree hierarchy output
- `--count` — secret count per subtree (like `du -sh`)
- `--format json` — structured JSON output

**Exit codes:**
- 0: paths found
- 3: empty tree
- 5: Vault unreachable

Output is one path per line (pipeable to `grep --stdin`).

### vaultspectre diff

Compare two scan reports and show changes (added, removed, status changes).

**Flags:**
- `--old path` — path to old/baseline scan report (JSON, required)
- `--new path` — path to new/current scan report (JSON, required)
- `--format json` — structured JSON output

**Exit codes:**
- 0: no new findings
- 6: new findings detected (added or worsened)
- 2: invalid arguments or malformed input

**JSON output:**
```json
{
  "added": [{"path": "kv/app/new", "change": "added", "new_status": "missing"}],
  "removed": [{"path": "kv/app/old", "change": "removed", "old_status": "ok"}],
  "changed": [{"path": "kv/app/db", "change": "changed", "old_status": "ok", "new_status": "missing"}],
  "summary": {"total_added": 1, "total_removed": 1, "total_changed": 1}
}
```

### vaultspectre grep

Search Vault secrets by key or value pattern. Recursively walks a KV tree.

**Flags:**
- `--path kv/projects/` — Vault path to search (default: `kv`)
- `--key-pattern "CLICKHOUSE_*"` — comma-separated glob patterns for key names
- `--value-pattern "10.200.4.206"` — comma-separated patterns for value content
- `--show-values` — show secret values in plaintext (with warning)
- `--depth N` — max recursion depth (0 = unlimited)
- `--workers N` — concurrent Vault readers (default 10)
- `--dry-run` — list paths without reading secrets
- `--format json` — structured JSON output
- `--case-sensitive` — case-sensitive matching

**Exit codes:**
- 0: matches found
- 3: no matches found
- 5: Vault unreachable
- 1: internal error
- 2: invalid arguments

**JSON output:**
```json
{
  "matches": [
    {
      "path": "kv/projects/ads/int/ads-stat",
      "keys": [
        {"name": "CLICKHOUSE_HOST", "type": "string"},
        {"name": "CLICKHOUSE_PASSWORD", "type": "string"}
      ]
    }
  ],
  "total_scanned": 847,
  "total_skipped": 11,
  "match_count": 3
}
```

### vaultspectre doctor

Check configuration, connectivity, and readiness.

**Flags:**
- `--format json` — structured JSON output
- `--vault-addr` — Vault server address
- `--token` — Vault authentication token
- `--timeout N` — timeout in seconds (default 30)

**Checks:**
- `config_file` — validates `.vaultspectre.yaml` if present
- `vault_address` — ensures VAULT_ADDR is set
- `vault_token` — ensures VAULT_TOKEN is set
- `vault_connectivity` — attempts token lookup to verify connection
- `token_permissions` — verifies token policies

**Exit codes:**
- 0: all checks pass
- 1: one or more checks failed

**JSON output:**
```json
{
  "checks": [
    {"name": "config_file", "status": "pass", "message": "loaded .vaultspectre.yaml"},
    {"name": "vault_address", "status": "pass", "message": "https://vault.example.com"},
    {"name": "vault_connectivity", "status": "pass", "message": "connected (42ms)"}
  ],
  "ready": true
}
```

### vaultspectre who

Find which codebases reference a Vault secret path (inverse of scan).

**Flags:**
- `--repos path1,path2` — comma-separated repo paths, or `@repos.txt` for file
- `--stdin` — read target Vault paths from stdin
- `--format json` — structured JSON output

**Exit codes:**
- 0: consumers found
- 3: no references found
- 2: invalid arguments

Answers the rotation-readiness question: "who will break if I rotate this secret?"

### vaultspectre correlate

Correlate Vault secrets with ClickHouse user activity. Uses `--from-file` mode (no live connections).

**Flags:**
- `--vault-file path` — vaultspectre grep JSON output (required)
- `--ch-file path` — clickspectre user activity JSON (required)
- `--key-field CLICKHOUSE_USER` — secret key name containing CH username
- `--format json` — structured JSON output

**Classifications:**
- `active_with_vault` — queries + Vault path (healthy)
- `active_no_vault` — queries but no Vault path (hardcoded creds?)
- `inactive_with_vault` — Vault path, zero queries (cleanup candidate)
- `inactive_no_vault` — no queries, no Vault path (orphan)
- `vault_only` — in Vault but absent from CH (stale path)

**Exit codes:**
- 0: all users active or no findings
- 6: inactive/stale users found

### vaultspectre ci-init

Generate a ready-to-paste CI pipeline snippet.

**Flags:**
- `--format gitlab` — GitLab CI YAML (default)
- `--format github` — GitHub Actions YAML
- `--auth-method token|approle|kubernetes` — auth method for generated config
- `--stage validate` — CI stage name

**Exit codes:**
- 0: snippet printed
- 2: invalid format

### vaultspectre serve

Start an MCP (Model Context Protocol) server over stdio. Exposes vaultspectre capabilities as typed tools for AI agents.

**Tools exposed:**
- `vaultspectre_ls` — list Vault paths recursively
- `vaultspectre_grep` — search secrets by key/value pattern (values always redacted)
- `vaultspectre_count` — count secrets in a tree
- `vaultspectre_doctor` — check connectivity and config
- `vaultspectre_eso` — audit ExternalSecret manifests (args: eso_dir, vault_addr, token, format, env, helm_values[], manifests[]); returns findings with class/severity/source/remediation fields; rule IDs in vaultspectre/ESO_* namespace; exit 6 on error findings when fail_on_findings=true

**Flags:**
- `--vault-addr` — Vault server address
- `--token` — Vault authentication token
- `--timeout N` — Vault API timeout in seconds

All tool responses have secret values structurally redacted.

**Claude Code config:**
```json
{
  "mcpServers": {
    "vaultspectre": {
      "command": "vaultspectre",
      "args": ["serve"],
      "env": {"VAULT_ADDR": "...", "VAULT_TOKEN": "..."}
    }
  }
}
```

### vaultspectre version

Print version, commit, Go version, and platform.

**Flags:**
- `--format json` — structured JSON output

**JSON output (version):**
```json
{
  "tool": "vaultspectre",
  "version": "0.4.0",
  "commit": "abc1234",
  "go_version": "go1.25.0",
  "platform": "darwin/arm64"
}
```

**JSON output (scan):**
```json
{
  "version": "spectre/v1",
  "scanner": "vaultspectre",
  "target": "Vault secrets engine",
  "findings": [
    {
      "id": "FIND-001",
      "severity": "high",
      "title": "finding description",
      "resource": "resource identifier",
      "detail": "detailed explanation"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

## Handoffs

- Output: spectre/v1 JSON envelope. Next: spectrehub for aggregation across scanners.
- Output: SARIF. Next: CI security gates.
- Output: Slack webhook. Next: ops team triage.
- Refused questions: how to fix findings, whether to remediate, risk acceptance decisions.

## What this does NOT do

- Does not remediate or modify Vault secrets engine — scan is read-only
- Does not store findings or manage a findings database
- Does not replace dedicated Vault secrets engine monitoring — point-in-time security audit only

## Failure Modes

- Authentication failure: returns exit code 2. Distrust: all findings fields. Safe fallback: report scan failure, do not cache.
- Network timeout: returns exit code 5. Distrust: completeness of findings. Safe fallback: partial results with warning.
- Rate limiting: returns partial findings with truncation warning. Distrust: summary counts.

## Parsing examples

```bash
vaultspectre scan --format json | jq '.summary'
vaultspectre scan --format json | jq '.findings[] | select(.severity == "critical")'
vaultspectre grep --path kv/ --key-pattern "CLICKHOUSE_*" --format json | jq '.matches[].path'
vaultspectre grep --path kv/ --key-pattern "*" --value-pattern "10.200.4.206" --format json | jq '.match_count'
vaultspectre diff --old baseline.json --new current.json --format json | jq '.added[].path'
```

## Deprecated

| Command | Flag | Replacement | Removal |
|---------|------|-------------|---------|
| `scan`, `watch` | `--output` | `--format` | v1.0.0 |

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
