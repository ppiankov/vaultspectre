# CLI Reference

## `vaultspectre ls`

List Vault secret paths recursively. No secret data is read.

```bash
vaultspectre ls kv/projects/ --depth 2
vaultspectre ls kv/ --tree
vaultspectre ls kv/ --count
vaultspectre ls kv/ --with-keys --format json > snapshot.json
```

| Flag | Description |
|------|-------------|
| `--path` | Vault path to list (also positional arg, default `kv`) |
| `--depth` | Max recursion depth (0 = unlimited) |
| `--tree` | Indented tree hierarchy |
| `--count` | Secret count per subtree |
| `--with-keys` | Include key names (reads secrets, never values) |
| `--stdin` | Read base paths from stdin |
| `--format` | Output format: `text`, `json` |

## `vaultspectre scan`

Scan a repository and validate against Vault.

```bash
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN
```

| Flag | Description |
|------|-------------|
| `--repo` | Repository path (default `.`) |
| `--vault-addr` | Vault address (or `VAULT_ADDR` env) |
| `--token` | Vault token (or `VAULT_TOKEN` env) |
| `--namespace` | Vault namespace, Enterprise only |
| `--format` | Output: `text`, `json`, `sarif`, `spectrehub` |
| `--exclude` | Comma-separated glob patterns to skip |
| `--fail-on-missing` | Exit 6 if missing secrets found |
| `--stale-days` | Stale threshold in days (default 90, 0 to disable) |
| `--audit-log-path` | Vault audit log for access-based staleness |
| `--var` | Variable `key=value` (repeatable) |
| `--var-file` | YAML variable file |
| `--detect-vars` | Auto-detect from Ansible inventory |
| `--baseline` | Baseline file for suppressing known findings |
| `--update-baseline` | Save current findings as baseline |
| `--policy` | Policy YAML for enforcement |
| `--scan-timeout` | Global scan timeout in minutes (default 10) |
| `--timeout` | Vault API timeout in seconds (default 30) |
| `--auth-method` | `token`, `approle`, `kubernetes` |
| `--role-id` | AppRole role ID |
| `--secret-id` | AppRole secret ID |
| `--k8s-role` | Kubernetes auth role |
| `--verbose` | Detailed output |

## `vaultspectre audit`

SpectreHub-compatible scan. Default format: spectrehub. Exit codes mapped to SpectreHub convention.

```bash
vaultspectre audit --format json
```

Accepts all `scan` flags. SpectreHub invokes this as `vaultspectre audit --format json`.

| Exit | SpectreHub meaning |
|------|-------------------|
| 0 | Success |
| 1 | Findings detected |
| 2 | Invalid arguments |
| 3 | Runtime error |

## `vaultspectre who`

Find which codebases reference a Vault path (rotation readiness).

```bash
vaultspectre who kv/payments/db --repos ~/dev/svc-a,~/dev/svc-b
vaultspectre who kv/payments/db --repos @repos.txt
vaultspectre ls kv/payments/ | vaultspectre who --stdin --repos ~/dev/svc-a
```

| Flag | Description |
|------|-------------|
| `--repos` | Comma-separated repo paths, or `@file` |
| `--stdin` | Read target paths from stdin |
| `--format` | Output: `text`, `json` |

## `vaultspectre grep`

Search Vault secrets by key or value pattern.

```bash
vaultspectre grep --path kv/projects/ --key-pattern "CLICKHOUSE_*"
vaultspectre grep --path kv/ --key-pattern "*" --value-pattern "10.200.4.206"
vaultspectre ls kv/ | vaultspectre grep --stdin --key-pattern PASSWORD
vaultspectre grep --from-file snapshot.json --key-pattern PASSWORD
```

| Flag | Description |
|------|-------------|
| `--path` | Vault path to search (default `kv`) |
| `--key-pattern` | Comma-separated glob patterns for key names |
| `--value-pattern` | Pattern for value content |
| `--show-values` | Show values (redacted by default) |
| `--no-redact` | Raw values (TTY only, errors on pipe/JSON) |
| `--depth` | Max recursion depth |
| `--workers` | Concurrent readers (default 10) |
| `--dry-run` | List paths without reading |
| `--stdin` | Read paths from stdin |
| `--from-file` | Grep offline from snapshot JSON |
| `--verify-format` | Check credential value formats (default on) |
| `--case-sensitive` | Case-sensitive matching |
| `--format` | Output: `text`, `json` |

## `vaultspectre diff`

Compare two scan reports and show changes.

```bash
vaultspectre diff --old baseline.json --new current.json
vaultspectre diff --old baseline.json --new current.json --format json
```

| Flag | Description |
|------|-------------|
| `--old` | Old/baseline report JSON (required) |
| `--new` | New/current report JSON (required) |
| `--format` | Output: `text`, `json` |

## `vaultspectre count`

Count secrets in a Vault tree. No secret data is read.

```bash
vaultspectre count kv/
vaultspectre count kv/ --by-depth
vaultspectre count kv/ --by-prefix 3
```

| Flag | Description |
|------|-------------|
| `--path` | Vault path (also positional arg) |
| `--depth` | Max recursion depth |
| `--by-depth` | Group by depth level |
| `--by-prefix` | Group by first N path segments |
| `--format` | Output: `text`, `json` |

## `vaultspectre watch`

Continuous drift detection with delta reporting.

```bash
vaultspectre watch --interval 5m --slack-webhook $SLACK_URL
```

All `scan` flags apply, plus:

| Flag | Description |
|------|-------------|
| `--interval` | Scan interval (default `5m`) |
| `--slack-webhook` | Slack webhook URL |

## `vaultspectre correlate`

Cross-tool CH user to Vault secret mapping (offline, no live connections).

```bash
vaultspectre grep --path kv/ --key-pattern "CLICKHOUSE_USER" --show-values --format json > vault.json
clickspectre analyze --by-user --format json > ch.json
vaultspectre correlate --vault-file vault.json --ch-file ch.json
```

| Flag | Description |
|------|-------------|
| `--vault-file` | Vaultspectre grep JSON (required) |
| `--ch-file` | Clickspectre user activity JSON (required) |
| `--key-field` | Secret key containing CH username (default `CLICKHOUSE_USER`) |
| `--format` | Output: `text`, `json` |

## `vaultspectre init`

Generate config and policy files.

```bash
vaultspectre init
vaultspectre init --with-policy
vaultspectre init --force
```

## `vaultspectre doctor`

Check config, connectivity, and readiness (ANCC schema).

```bash
vaultspectre doctor
vaultspectre doctor --format json
```

JSON output matches ANCC doctor schema: status, version, revision, source.repo, readiness.

## `vaultspectre ci-init`

Generate CI pipeline snippet.

```bash
vaultspectre ci-init --format gitlab
vaultspectre ci-init --format github --auth-method approle
```

| Flag | Description |
|------|-------------|
| `--format` | `gitlab` (default), `github` |
| `--auth-method` | `token`, `approle`, `kubernetes` |
| `--stage` | CI stage name (default `validate`) |

## `vaultspectre serve`

MCP server for AI agent integration (stdio transport).

```bash
vaultspectre serve
```

Tools: `vaultspectre_ls`, `vaultspectre_grep`, `vaultspectre_count`, `vaultspectre_doctor`. All responses redacted.

## `vaultspectre version`

```bash
vaultspectre version
vaultspectre version --format json
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Internal error |
| 2 | Invalid arguments or config |
| 3 | No matches (grep/who/ls) |
| 5 | Network error (Vault unreachable) |
| 6 | Findings detected |

## Authentication

| Method | Flags |
|--------|-------|
| Token (default) | `--token` or `VAULT_TOKEN` |
| AppRole | `--auth-method approle --role-id ID --secret-id ID` |
| Kubernetes | `--auth-method kubernetes --k8s-role ROLE` |

## Configuration

Environment: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`

Config file: `.vaultspectre.yaml` (generate with `vaultspectre init`). CLI flags override.

## Installation

```bash
brew install ppiankov/tap/vaultspectre
# or
go install github.com/ppiankov/vaultspectre/cmd/vaultspectre@latest
# or
docker run ghcr.io/ppiankov/vaultspectre scan --repo /repo
```
