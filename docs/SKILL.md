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
```

## Deprecated

| Command | Flag | Replacement | Removal |
|---------|------|-------------|---------|
| `scan`, `watch` | `--output` | `--format` | v1.0.0 |

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
