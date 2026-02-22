# VaultSpectre

Find Vault secret references in code, verify they exist in Vault, and flag unused/stale paths before they break deployments.
Part of the Spectre family of infrastructure cleanup tools.

## Project Status

**Status: Beta** · **v0.3.0** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| Multi-format repo scanner (Ansible, YAML, Terraform, Python, Bash, Go, K8s) | Complete |
| Vault path validator (KV v1/v2) | Complete |
| Unused/stale secret detection (metadata + audit logs) | Complete |
| Variable resolution (--var, --var-file, --detect-vars) | Complete |
| Multiple output modes (verbose, list-paths, summary, group-by-role) | Complete |
| JSON + text reports (SpectreHub-compatible) | Complete |
| CI pipeline (test/lint/security) | Complete |
| Homebrew distribution | Complete |
| Test coverage >60% | Pending |
| API stability guarantees | Partial |
| v1.0 release | Planned |

Pre-1.0: CLI flags and config schemas may change between minor versions. JSON output structure is stable.

## Why VaultSpectre Exists

HashiCorp Vault tells you what secrets exist.
Your codebase tells you what secrets are referenced.
Neither tells you which secrets are **actually still needed**.

VaultSpectre bridges that gap by correlating:
- secret references found in code and configuration
- live validation of secret paths in Vault
- optional audit log analysis to detect real usage

It is designed for teams who inherit Vault instances, want to clean them up safely, and would prefer not to cause a production incident in the process.

## Features (MVP)

### 1. Repository Scanner (Static Secret Path Discovery)

Finds Vault paths referenced in:
- Ansible playbooks (`hashi_vault`, `vault_kv2_get`, etc.)
- YAML configurations
- Jinja templates
- Python / Bash scripts
- Terraform / Helm / Kustomize
- Environment files
- Any arbitrary text file (regex fallback)

Extracts:
- Secret path (mount + path)
- Optional field
- Location (file + line)
- Reference type (lookup, env var, template, etc.)

### 2. Vault Path Validator

Supports KV v2 (primary) and KV v1.

Checks each discovered path via Vault API:
- Does the secret exist?
- Does the current token have permission?
- Is the mount correct (kv1 vs kv2)?
- Is the path valid or structurally broken?

Classifies each path as:
- `OK` — exists and accessible
- `MISSING` — referenced in repo but not present in Vault
- `ACCESS_DENIED` — likely exists, but no permission
- `INVALID` — malformed or not resolvable
- `DYNAMIC` — templated or variable-based (not statically verifiable)

### 3. Unused Secret Detection (Lightweight MVP)

Uses:
- Vault metadata timestamps (KV2 `created_time`/`updated_time`)
- Audit log presence (if enabled)

To flag:
- Secrets not referenced in repo anymore
- Secrets that haven't been touched in N days
- Stale entries from deprecated services

### 4. Reporting

Outputs human-readable summary and JSON report for CI/CD automation.

Can fail the build if new missing/invalid paths appear.

## Installation

### Homebrew (recommended)

```bash
brew install ppiankov/tap/vaultspectre
```

### From Source

```bash
git clone https://github.com/ppiankov/vaultspectre.git
cd vaultspectre
make build
```

The binary will be in `./bin/vaultspectre`.

## Usage

### Basic Scan

Scan a repository and validate against Vault:

```bash
vaultspectre scan \
  --repo ./my-repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN
```

### JSON Output

```bash
vaultspectre scan \
  --repo ./my-repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN \
  --output json > vaultspectre-report.json
```

### Fail on Missing Secrets

Useful for CI/CD pipelines:

```bash
vaultspectre scan \
  --repo . \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN \
  --fail-on-missing
```

### Detect Stale Secrets

Flag secrets not accessed in 90 days:

```bash
vaultspectre scan \
  --repo . \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN \
  --stale-days 90
```

### Using Audit Logs for Access-Based Staleness

For more accurate "unused secret" detection, provide Vault audit log:

```bash
vaultspectre scan \
  --repo . \
  --vault-addr $VAULT_ADDR \
  --token $VAULT_TOKEN \
  --audit-log-path /var/log/vault/audit.log \
  --audit-window-days 90 \
  --stale-days 60
```

This will:
- Check KV v2 metadata for last modified time
- Parse audit log for last access (read) time
- Use the most recent of either as the activity timestamp
- Flag secrets with no activity (modified OR accessed) in 60 days

**Audit log format**: VaultSpectre supports file-based audit logs (JSON lines).

Enable audit logging in Vault:
```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

**Without audit logs**: VaultSpectre falls back to metadata-only staleness detection.

## Configuration

VaultSpectre can be configured via:
1. Command-line flags
2. Environment variables
3. Config file (`.vaultspectre.yaml`)

### Environment Variables

- `VAULT_ADDR` - Vault server address
- `VAULT_TOKEN` - Vault authentication token
- `VAULT_NAMESPACE` - Vault namespace (Enterprise)

## Report Format

### SpectreHub Compatible JSON

```json
{
  "tool": "vaultspectre",
  "version": "0.1.0",
  "timestamp": "2026-01-23T12:00:00Z",
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

## Project Structure

```
vaultspectre/
├── cmd/vaultspectre/      # CLI entry point
│   └── main.go
├── internal/              # Core implementation
│   ├── scanner/          # Code scanning logic
│   │   ├── scanner.go
│   │   ├── patterns.go
│   │   └── reference.go
│   ├── vault/            # Vault client
│   │   ├── client.go
│   │   └── validator.go
│   ├── audit/            # Audit log parsing
│   │   ├── types.go
│   │   ├── parser.go
│   │   └── analyzer.go
│   ├── analyzer/         # Analysis logic
│   │   └── analyzer.go
│   └── report/           # Report generation
│       ├── text.go
│       └── json.go
├── go.mod
├── Makefile
└── README.md
```

## Roadmap

### v0.1 — MVP (Current)
- CLI: `vaultspectre scan`
- Static repo scanner (regex + YAML parsing)
- KV2 metadata existence checks
- JSON + text reports
- SpectreHub compatible output

### v0.2
- ✅ Audit log integration (optional, pluggable)
- ✅ Enhanced stale-secret detection
- CI rule presets
- Config file support

### v0.3
- Ownership mapping
- Secret usage graphing
- Vault namespace support
- Multiple mount support

## Contributing

Issues, feature requests, and PRs are welcome.
Especially contributions to:
- Additional scanners for different file types
- False-positive reduction
- Vault engine support
- Test suites

## License

MIT License - see [LICENSE](LICENSE)

## About

Part of the SpectreOps family — tools for uncovering and maintaining forgotten or undocumented infrastructure.
