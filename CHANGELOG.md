# Changelog

All notable changes to VaultSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.3
- Concurrent Vault API calls with rate limiting
- Configuration file support (`.vaultspectre.yaml`)
- Exclude patterns for false positive filtering
- Custom pattern injection
- Diff mode (compare scans over time)
- Secret ownership mapping
- Usage dependency graphing
- Multi-Vault support
- Vault namespace hierarchy support
- Limited dynamic template expansion
- Secret rotation recommendations

## [0.2.1] - 2026-02-05

### Fixed
- **Critical scanner bug**: Fixed scanner skipping all files when run from current directory (".")
  - Scanner treated "." as a hidden directory and skipped everything
  - Now properly excludes only actual hidden directories (.git, .github, etc.)
- **Linter errors**: Resolved golangci-lint failures blocking CI
  - Fixed errcheck: removed MarkFlagRequired calls, added manual validation with clear error messages
  - Fixed unused: removed checkMetadataTimestamp function that was never called
- **Environment variable handling**: vault-addr and token flags now work correctly with environment variables
  - Removed cobra's MarkFlagRequired which prevented env vars from being used as defaults
  - Added runtime validation with helpful error messages

### Added
- **Ansible community collection support**: Added pattern for `community.hashi_vault.hashi_vault` lookup format
  - Detects modern Ansible roles using the community.hashi_vault collection
  - Supports `secret=<path>:<key>` parameter syntax
  - Properly marks templated paths (e.g., `{{ vault_secret_path }}/backup`) as dynamic

### Changed
- Improved error messages for missing vault address and token configuration
- Better handling of Ansible Jinja2 template variables in vault paths

## [0.2.0] - 2026-01-25

### Added
- **Audit log integration for true unused secret detection**
  - New `internal/audit` package for parsing Vault audit logs
  - Support for file-based audit device (JSON lines format)
  - Access pattern analysis (last access time, access count, unique clients)
  - Enhanced staleness detection combining metadata + access patterns
  - New CLI flags:
    - `--audit-log-path` - Path to Vault audit log file
    - `--audit-window-days` - Days to look back in audit logs (default 90)
  - Graceful degradation: falls back to metadata-only if audit log unavailable
  - Enhanced report output showing:
    - Activity type (accessed vs modified)
    - Access frequency and recency
    - Days since last activity
- Comprehensive test suite for audit log parsing
- Example demonstrating audit log integration (`examples/audit-log-example/`)
- Updated documentation with audit log usage examples

## [0.1.0] - 2026-01-23

### Added
- Initial MVP release
- Multi-format repository scanner supporting:
  - Ansible (lookups and modules)
  - YAML configuration files
  - Terraform/HCL
  - Python (HVAC client)
  - Bash/Shell scripts
  - Kubernetes Vault injector annotations
  - Go code
  - Generic regex patterns
- Vault path validator with KV v1/v2 support
- Status classification (ok, missing, access_denied, invalid, dynamic, error)
- Staleness detection using KV v2 metadata
- Health score calculation
- Dual report format:
  - Human-readable text output
  - SpectreHub-compatible JSON
- CLI commands:
  - `scan` - Main scanning command
  - `version` - Version information
- Command-line flags:
  - `--repo` - Repository path
  - `--vault-addr` - Vault server address
  - `--token` - Vault token
  - `--namespace` - Vault namespace (Enterprise)
  - `--output` - Output format (text/json)
  - `--fail-on-missing` - Exit with error on missing secrets
  - `--stale-days` - Staleness threshold
- Environment variable support:
  - `VAULT_ADDR`
  - `VAULT_TOKEN`
  - `VAULT_NAMESPACE`
- Example test repository
- Comprehensive documentation:
  - README with usage examples
  - ARCHITECTURE.md
  - QUICKSTART.md
  - CONTRIBUTING.md
- GitHub Actions workflows:
  - CI (test and build)
  - Release (multi-platform binaries)
- Makefile with common tasks:
  - `build` - Build binary
  - `test` - Run tests
  - `fmt` - Format code
  - `vet` - Vet code
  - `clean` - Clean build artifacts

### Security
- Never logs or stores Vault tokens
- Only validates path existence, never reads secret values
- Filters out template variables to prevent false validation

## [0.0.0] - 2026-01-23

### Added
- Project initialization
- Repository structure
- License (MIT)
- Basic project scaffolding

[Unreleased]: https://github.com/ppiankov/vaultspectre/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.1
[0.2.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.0
[0.1.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.1.0
[0.0.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.0.0
