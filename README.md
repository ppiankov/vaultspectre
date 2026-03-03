# vaultspectre

[![CI](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/vaultspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/vaultspectre)](https://goreportcard.com/report/github.com/ppiankov/vaultspectre)

**vaultspectre** — Vault secret reference scanner and drift detector. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans codebases for Vault secret references across Ansible, YAML, Terraform, Python, Bash, Go, and Kubernetes manifests
- Validates that referenced paths exist in Vault (KV v1/v2)
- Detects unused and stale secrets via metadata and audit logs
- Supports variable resolution from files, CLI flags, and Ansible auto-detection
- Outputs text, JSON, and SpectreHub formats

## What it is NOT

- Not a Vault management tool — never writes, rotates, or deletes secrets
- Not a secret scanner — finds references, not leaked credentials
- Not a monitoring tool — point-in-time scanner
- Not a replacement for Vault audit logs — complements them

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install vaultspectre
```

### From source

```sh
git clone https://github.com/ppiankov/vaultspectre.git
cd vaultspectre
make build
```

### Usage

```sh
vaultspectre scan --repo . --vault-addr https://vault.example.com
```

## CLI commands

| Command | Description |
|---------|-------------|
| `vaultspectre scan` | Scan code for Vault references and validate against live Vault |
| `vaultspectre version` | Print version |

## SpectreHub integration

vaultspectre feeds Vault drift findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool vaultspectre
```

## Safety

vaultspectre operates in **read-only mode**. It inspects and reports — never writes, rotates, or deletes your secrets.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://github.com/ppiankov)
