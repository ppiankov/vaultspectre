# VaultSpectre

[![CI](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/vaultspectre)](https://goreportcard.com/report/github.com/ppiankov/vaultspectre)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

Find Vault secret references in code, verify they exist in Vault, and flag unused/stale paths before they break deployments. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## Why this exists

HashiCorp Vault tells you what secrets exist. Your codebase tells you what secrets are referenced. Neither tells you which secrets are **actually still needed**.

VaultSpectre bridges that gap — correlating secret references in code with live Vault state and audit logs. It is designed for teams who inherit Vault instances, want to clean them up safely, and would prefer not to cause a production incident in the process.

## What it is

- Scans codebases for Vault secret references across Ansible, YAML, Terraform, Python, Bash, Go, and Kubernetes manifests
- Validates that referenced paths exist in Vault (KV v1/v2)
- Detects unused and stale secrets via metadata and audit logs
- Supports variable resolution from files, CLI flags, and Ansible auto-detection
- Continuous drift monitoring with delta reporting via `watch` command
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a Vault management tool — never writes, rotates, or deletes secrets
- Not a secret scanner — finds references, not leaked credentials
- Not a replacement for Vault audit logs — complements them

## Quick start

```bash
# Install
brew install ppiankov/tap/vaultspectre

# Generate config
vaultspectre init

# Scan a repository
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN

# JSON output for CI/CD
vaultspectre scan --repo . --format json --fail-on-missing

# Continuous monitoring
vaultspectre watch --interval 5m --repo . --slack-webhook $SLACK_URL
```

## CLI commands

| Command | Description |
|---------|-------------|
| `vaultspectre scan` | Scan code for Vault references, validate against live Vault |
| `vaultspectre watch` | Continuous drift detection with delta reporting |
| `vaultspectre init` | Generate starter `.vaultspectre.yaml` config |
| `vaultspectre version` | Print version |

Key flags: `--format json\|sarif\|spectrehub`, `--exclude vendor/**,testdata/**`, `--fail-on-missing`, `--detect-vars`, `--baseline`, `--slack-webhook`

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Internal error |
| 2 | Invalid arguments or config |
| 5 | Network error (Vault unreachable) |
| 6 | Findings detected |

## Agent integration

Single binary, deterministic output, structured JSON, bounded scans.

Agents: read [`docs/SKILL.md`](docs/SKILL.md) for commands, JSON parsing patterns, and workflow examples.

## SpectreHub integration

```sh
spectrehub collect --tool vaultspectre
```

## Safety

vaultspectre operates in **read-only mode** — never writes, rotates, or deletes your secrets.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
