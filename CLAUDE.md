# vaultspectre

Vault secret usage auditor. Scans code for Vault references, validates against Vault API, flags missing/unused/stale paths.

## Build & Test

```bash
make build    # produces bin/vaultspectre (with LDFLAGS)
make test     # go test -race -cover ./...
make lint     # golangci-lint run ./...
```

## Architecture

- `cmd/vaultspectre/main.go` — entry point, delegates to `internal/commands`
- `internal/commands/` — Cobra commands (scan, version)
- `internal/scanner/` — multi-format repo scanner (Ansible, YAML, Terraform, Python, Bash, Go, K8s)
- `internal/vault/` — Vault API client, path validator (KV v1/v2)
- `internal/analyzer/` — result analysis, finding classification, health score
- `internal/audit/` — Vault audit log parser, staleness detection
- `internal/report/` — text and JSON formatters (SpectreHub-compatible)

## Conventions

- Go 1.25+, no CGO
- LDFLAGS: `-X .../internal/commands.Version=$(VERSION_NUM)` — VERSION_NUM has no `v` prefix
- Sources use `internal/scanner.Reference` struct with json tags
- JSON output includes `tool`, `version`, `timestamp` for SpectreHub integration
- Tests mandatory, -race flag

## Work Orders

See `docs/work-orders.md` for pending WOs.
