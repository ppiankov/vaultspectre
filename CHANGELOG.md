# Changelog

All notable changes to VaultSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-22

### Added
- Homebrew distribution (`brew install ppiankov/tap/vaultspectre`)
- Build-time version injection via LDFLAGS
- Homebrew formula template (Formula/vaultspectre.rb)
- Release workflow with tar.gz archives, checksums, and auto-tap update
- Trivy security scanning in CI
- Module tidy check in CI
- Project status section in README
- docs/context.txt for agent context
- golangci-lint configuration (.golangci.yml)
- Test suite: scanner (94.5%), analyzer (100%), report (96.2%), audit (81%), commands (29.9%), vault (19.5%) — 66.9% total
- Agent Integration section in README
- Structured logging via log/slog (`internal/logging` package)
  - `--verbose` maps to slog.LevelDebug, default is slog.LevelWarn
  - Structured fields: path count, secret count, stale count, scan duration, health score
  - No output without `--verbose` except warnings and errors
- SARIF 2.1.0 output format (`--output sarif`) for GitHub Security tab
  - Rule IDs: MISSING_SECRET, STALE_SECRET, ACCESS_DENIED, INVALID_PATH, ERROR
  - Severity mapping: missing/invalid → error, access_denied/stale → warning
  - Location tracking with file and line number
- GoReleaser configuration for automated multi-platform releases
  - Builds linux/darwin × amd64/arm64 with LDFLAGS
  - tar.gz archives with checksums
  - Conventional commit changelog generation
- Docker image (`ghcr.io/ppiankov/vaultspectre`) via GoReleaser
  - Multi-arch (amd64, arm64) with distroless base
  - Standalone `Dockerfile` for local builds
- Homebrew formula auto-published via GoReleaser brews section
- Baseline mode for tracking new vs known findings (`internal/baseline` package)
  - `--baseline` flag loads existing baseline, filters known findings
  - `--update-baseline` saves current findings as new baseline
  - SHA-256 fingerprints from finding status + path
  - Suppressed count logged when baseline applied
- Config file support (`.vaultspectre.yaml` in CWD or `~/.vaultspectre.yaml`)
  - Fields: vault_addr, vault_namespace, output, stale_days, timeout, exclude_patterns, detect_vars, fail_on_missing
  - CLI flags take precedence over config file values
- Connection resilience for Vault API calls (`internal/vault/retry.go`)
  - Exponential backoff with max 3 retries for transient errors (429, 5xx, network)
  - Auth errors (401, 403, permission denied) fail immediately
  - New `--timeout` flag to cap total retry window (default 30s)

### Changed
- Release workflow replaced with GoReleaser (goreleaser-action@v6)
- Go version bumped from 1.21 to 1.25
- CI updated: Go 1.25, golangci-lint-action@v7, Trivy
- Makefile: added LDFLAGS, -race -cover on tests, lint target
- Release: 4 platforms (dropped Windows), tar.gz (not flat binaries)
- Version output format: `vaultspectre 0.3.0 (abc1234)`

### Fixed
- 9 lint errors (unchecked error returns, unused function, De Morgan's law)

### Removed
- Loose development docs from project root
- spectre-doc/ planning directory
- Historical MVP docs from docs/
- Windows builds from release matrix

## [0.2.3] - 2026-02-06

### Added
- **New output modes for automation and usability**
  - `--verbose` - Show detailed variable sources and resolved path mappings
  - `--list-paths` - Output clean list of resolved paths (one per line) for scripts/documentation
  - `--summary-only` - Show only summary for fast CI/CD health checks
  - `--group-by-role` - Group secrets by Ansible role/component for better organization

### Improved
- Variable detection now tracks sources (shows which file each variable came from)
- Report shows template → resolved path mapping in verbose mode
- Better visibility into variable resolution process

## [0.2.2] - 2026-02-06

### Added
- **Variable resolution system (RootOps-aligned)**
  - New `--var` flag for setting variable values: `--var vault_secret_path=secret/data/prod`
  - New `--var-file` flag for loading variables from YAML files
  - New `--detect-vars` flag for auto-detection from Ansible inventory (fully implemented)
    - Scans inventory/*/group_vars/*.yml, group_vars/*.yml, host_vars/*.yml
    - Parses YAML files and extracts string variables
    - Skips example/sample files and Jinja2 template variables
  - Proper Ansible variable interpolation: `{{ varname }}` detection and resolution
  - Variable loading priority: CLI flags > var-file > auto-detection
- **Enhanced status classification**
  - `needs_resolution` - Paths with unresolved variables (requires explicit values)
  - `skipped_policy` - Vault policy wildcards (cannot be validated)
  - `pending_validation` - Resolved paths ready to validate
- **Improved reporting**
  - Shows validated vs skipped paths separately
  - Displays variable requirements when variables are missing
  - Clear instructions for providing variable values
  - Unresolved paths section with variable usage details
- **New output modes**
  - `--verbose` - Show detailed variable sources and resolved paths
  - `--list-paths` - Output simple list of resolved paths (one per line, for scripts)
  - `--summary-only` - Show only summary, skip detailed results (fast CI/CD checks)
  - `--group-by-role` - Group secrets by Ansible role/component

### Fixed
- **CRITICAL: Vault validation bug** - All paths were incorrectly reported as "ok"
  - Vault API returns non-nil secret with empty data for nonexistent paths
  - Validator now checks `secret.Data != nil && len(secret.Data) > 0`
  - False negatives eliminated: missing secrets now correctly detected
- **KV v2 path handling** - Automatic /data/ insertion for KV v2 paths
  - Paths like `secret/production/app` now try both direct and `secret/data/production/app`
  - Handles both KV v1 and KV v2 mounts automatically
  - System paths (sys/, auth/, etc.) excluded from /data/ insertion
- **False positives from variable definitions**
  - Scanner now excludes YAML variable definitions (e.g., `vault_secret_path: "secret/data/..."`)
  - Only extracts actual Vault references (lookups, reads, etc.)
  - Prevents double-extraction of paths from variable assignments
- **Health score calculation**
  - Now only counts validated paths (was incorrectly including skipped paths)
  - Skipped/unresolved paths are not failures, just unvalidatable
  - More accurate health assessment: EXCELLENT/GOOD/WARNING/CRITICAL/SEVERE

### Changed
- **RootOps principle enforcement**
  - Refuses to validate paths with unresolved variables (no guessing)
  - Requires explicit variable values via CLI flags or file
  - Clear error messages when variables are missing
  - Honest reporting: only validated paths affect health score
- Report format now distinguishes between validation failures and unvalidatable paths
- Scanner validates resolved paths instead of skipping dynamic paths

### Documentation
- Added `IMPLEMENTATION_SUMMARY.md` documenting variable resolution design
- Added `VARIABLE_RESOLUTION.md` explaining the resolution approach
- Added `ROOTOPS_ALIGNMENT.md` documenting RootOps principles application

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

[Unreleased]: https://github.com/ppiankov/vaultspectre/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.3
[0.2.2]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.2
[0.2.1]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.1
[0.2.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.2.0
[0.1.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.1.0
[0.0.0]: https://github.com/ppiankov/vaultspectre/releases/tag/v0.0.0
