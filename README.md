# VaultSpectre

[![CI](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/vaultspectre)](https://goreportcard.com/report/github.com/ppiankov/vaultspectre)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

Find Vault secret references in code, verify they exist in Vault, and flag unused/stale paths before they break deployments. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans codebases for Vault secret references across Ansible, YAML, Terraform, Python, Bash, Go, and Kubernetes manifests
- Validates that referenced paths exist in Vault (KV v1/v2)
- Detects unused and stale secrets via metadata and audit logs
- Supports variable resolution from files, CLI flags, and Ansible auto-detection
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a Vault management tool — never writes, rotates, or deletes secrets
- Not a secret scanner — finds references, not leaked credentials
- Not a monitoring tool — point-in-time scanner
- Not a replacement for Vault audit logs — complements them

## Quick start

```bash
# Install
brew install ppiankov/tap/vaultspectre

# Scan a repository
vaultspectre scan \
  --repo ./my-repo \
  --vault-addr https://vault.example.com \
  --token $VAULT_TOKEN

# JSON output for CI/CD
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --output json

# Fail on missing secrets
vaultspectre scan --repo . --vault-addr $VAULT_ADDR --token $VAULT_TOKEN --fail-on-missing
```

## Agent integration

Single binary, deterministic output, structured JSON, bounded scans.

Agents: read [`SKILL.md`](SKILL.md) for commands, JSON parsing patterns, and workflow examples.

Key pattern: `vaultspectre scan --output json` returns SpectreHub-compatible JSON with status classifications and health scores.

## SpectreHub integration

```sh
spectrehub collect --tool vaultspectre
```

## Safety

vaultspectre operates in **read-only mode** — never writes, rotates, or deletes your secrets.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | All flags, config, scanner coverage, status classifications, installation |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
