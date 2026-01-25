# VaultSpectre Architecture

## Overview

VaultSpectre is a static + runtime auditor for HashiCorp Vault secret usage. It follows a pipeline architecture that scans, validates, analyzes, and reports on Vault secret references found in code repositories.

## Architecture Diagram

```
┌──────────────────┐
│  Repository      │
│  (Code/Config)   │
└────────┬─────────┘
         │
         v
┌──────────────────────────────────────┐
│         Scanner Module               │
│  ┌────────────────────────────────┐  │
│  │  Pattern-based Scanners:      │  │
│  │  - Ansible                    │  │
│  │  - YAML/Jinja                 │  │
│  │  - Terraform/HCL              │  │
│  │  - Python/Bash/Go             │  │
│  │  - Generic regex              │  │
│  └────────────────────────────────┘  │
└────────┬─────────────────────────────┘
         │
         v
┌──────────────────────────────────────┐
│     Reference Collection             │
│  [path, file, line, type]            │
└────────┬─────────────────────────────┘
         │
         v
┌──────────────────────────────────────┐
│      Vault Validator                 │
│  ┌────────────────────────────────┐  │
│  │  - Connect to Vault API        │  │
│  │  - Validate each path          │  │
│  │  - Check metadata              │  │
│  │  - Determine staleness         │  │
│  └────────────────────────────────┘  │
└────────┬─────────────────────────────┘
         │
         v
┌──────────────────────────────────────┐
│         Analyzer                     │
│  - Group by status                   │
│  - Calculate health score            │
│  - Identify issues                   │
└────────┬─────────────────────────────┘
         │
         v
┌──────────────────────────────────────┐
│      Report Generator                │
│  ┌──────────┬──────────────────────┐ │
│  │   Text   │   JSON (SpectreHub)  │ │
│  └──────────┴──────────────────────┘ │
└──────────────────────────────────────┘
```

## Component Details

### 1. Scanner Module

**Location**: `internal/scanner/`

**Responsibilities**:
- Recursively walk repository directories
- Apply pattern matching to files
- Extract secret path references
- Deduplicate findings

**Key Files**:
- `scanner.go` - Main scanning logic
- `patterns.go` - Regex patterns for different file types
- `reference.go` - Reference data structure

**Pattern Types**:
- Ansible lookups and modules
- YAML configuration files
- Terraform/HCL data sources
- Python HVAC client calls
- Shell script vault commands
- Kubernetes vault injector annotations
- Generic secret path patterns

**File Type Support**:
- `.yml`, `.yaml` - YAML configs
- `.py` - Python scripts
- `.sh`, `.bash` - Shell scripts
- `.tf`, `.hcl` - Terraform
- `.j2`, `.jinja` - Jinja templates
- `.env`, `.conf`, `.cfg` - Config files
- `.go`, `.rb`, `.java`, `.js`, `.ts` - Source code

### 2. Vault Client & Validator

**Location**: `internal/vault/`

**Responsibilities**:
- Establish connection to Vault
- Authenticate with token
- Read secret paths
- Fetch metadata
- Validate path existence and accessibility

**Key Files**:
- `client.go` - Vault API client wrapper
- `validator.go` - Path validation logic

**Validation Statuses**:
- `ok` - Secret exists and is accessible
- `missing` - Referenced but doesn't exist in Vault
- `access_denied` - Exists but no permission
- `invalid` - Malformed or unresolvable path
- `dynamic` - Contains templates/variables (not statically verifiable)
- `error` - Validation error occurred

### 3. Staleness Detection

**Multi-Source Approach**:

VaultSpectre uses both Vault metadata and audit logs for comprehensive staleness detection:

1. **KV v2 Metadata** (`updated_time`):
   - Shows when secret was last modified
   - Fast and always available for KV v2 secrets
   - Limitation: Doesn't show read access

2. **Audit Logs** (`operation: "read"`):
   - Shows every time secret was accessed (read)
   - Includes timestamp, access count, source IPs
   - Limitation: Requires audit logging enabled, file access

**Staleness Algorithm**:
```go
lastActivity = max(metadata.updated_time, audit.last_read_time)
isStale = (days_since(lastActivity) > threshold)
```

**Data Collected**:
- Last modified time (from KV v2 metadata)
- Last accessed time (from audit logs)
- Access count in window (from audit logs)
- Days since activity
- Activity type ("modified" vs "accessed")

**Example Output**:
```
[STALE] secret/data/old-service/key
  Activity: 2024-06-15T10:00:00Z (accessed 3 times, last 214 days ago)
  Referenced in: old-service/config.yml:42

[NOT STALE] secret/data/active-api/token
  Activity: 2026-01-20T14:30:00Z (accessed 1,247 times, last 3 days ago)
  Referenced in: api/deployment.yml:15
```

**Audit Log Parsing**:
- Reads file-based Vault audit logs (JSON lines)
- Filters for `"operation": "read"` entries
- Builds access map: path → timestamps
- Optional time window (--audit-window-days)

**Fallback Behavior**:
- If audit log not provided: Uses metadata only
- If metadata unavailable (KV v1): Uses audit log only
- If both unavailable: Secret marked as "unknown staleness"

**Original Staleness Detection**:

### 4. Audit Log Parser & Analyzer

**Location**: `internal/audit/`

**Responsibilities**:
- Parse Vault audit log files (JSON lines)
- Extract read operations for secret paths
- Build access timeline and frequency data
- Provide staleness information based on access patterns

**Key Files**:
- `types.go` - Audit entry data structures
- `parser.go` - JSON audit log parsing
- `analyzer.go` - Access pattern analysis

**Supported Audit Format**:
- File-based audit device (JSON lines)
- Each line is a complete JSON object
- Filters for `type: "request"` and `operation: "read"`

**Access Information Provided**:
- Last access timestamp
- First access timestamp (in window)
- Total access count
- Unique client count
- Source IP addresses
- Days since last access

### 5. Analyzer

**Location**: `internal/analyzer/`

**Responsibilities**:
- Aggregate validation results
- Group secrets by path
- Calculate summary statistics
- Compute health scores

**Health Score Calculation**:
```
excellent: 0% issues
good:      < 5% issues
warning:   5-15% issues
critical:  15-30% issues
severe:    > 30% issues
```

Issues include: missing, invalid, errors, and 50% weight for stale secrets.

### 6. Report Generator

**Location**: `internal/report/`

**Responsibilities**:
- Format results for humans (text)
- Format results for machines (JSON)
- SpectreHub compatibility

**Key Files**:
- `types.go` - Shared data structures
- `text.go` - Human-readable output
- `json.go` - JSON output

**SpectreHub JSON Schema**:
```json
{
  "tool": "vaultspectre",
  "version": "0.1.0",
  "timestamp": "2026-01-23T...",
  "config": { ... },
  "summary": {
    "total_references": N,
    "status_ok": N,
    "status_missing": N,
    "health_score": "warning"
  },
  "secrets": [...]
}
```

### 7. CLI Commands

**Location**: `internal/commands/`

**Command Structure**:
- `root.go` - Root command and global config
- `scan.go` - Main scan command
- `version.go` - Version information

**Scan Command Flow**:
1. Parse command-line flags
2. Initialize scanner with repo path
3. Scan repository for references
4. Initialize Vault client
5. Parse audit log (if provided)
6. Initialize validator with audit analyzer
7. Validate each reference
8. Check staleness using metadata + audit logs
9. Analyze results
10. Generate report
11. Exit with appropriate code

## Data Flow

```
File Content → Pattern Match → Reference → Vault API → Status → Analysis → Report
```

### Example Reference Flow

1. **Input**: `ansible/deploy.yml` contains:
   ```yaml
   secret: "{{ lookup('hashi_vault', 'secret/data/prod/api/key') }}"
   ```

2. **Scanner** extracts:
   ```go
   Reference{
     Path: "secret/data/prod/api/key",
     File: "ansible/deploy.yml",
     Line: 15,
     Type: "ansible_lookup"
   }
   ```

3. **Validator** checks Vault:
   ```go
   status, err := client.Read("secret/data/prod/api/key")
   // Returns: "ok", "missing", "access_denied", etc.
   ```

4. **Analyzer** groups:
   ```go
   SecretInfo{
     Path: "secret/data/prod/api/key",
     Status: "ok",
     References: [Reference{...}]
   }
   ```

5. **Reporter** outputs:
   ```
   [OK] secret/data/prod/api/key
     Referenced in 1 location(s):
       - ansible/deploy.yml:15 (ansible_lookup)
   ```

## Extension Points

### Adding New Scanners

1. Add pattern to `internal/scanner/patterns.go`
2. Update `shouldScanFile()` for new extensions
3. Test with sample files

### Adding New Validators

1. Extend `Validator` in `internal/vault/validator.go`
2. Add new validation methods
3. Update status constants

### Adding New Report Formats

1. Implement `Reporter` interface
2. Add to `internal/report/`
3. Wire into scan command

## Performance Considerations

### Scanning
- Skips hidden directories (`.git`, `.vscode`, etc.)
- Ignores large files (> 10MB)
- Only scans text files with known extensions
- Uses buffered file reading

### Validation
- Sequential Vault API calls (MVP)
- Future: Concurrent validation with rate limiting
- Future: Caching for repeated paths

### Memory
- Streaming file reads
- Deduplication during scan
- In-memory result aggregation (acceptable for MVP)

## Security Considerations

### Token Handling
- Never logs tokens
- Accepts via env var or flag
- No token storage

### Path Validation
- Filters out obvious false positives
- Excludes template variables
- Validates path structure

### Secret Content
- Never reads or stores secret values
- Only validates existence and metadata
- Reports contain paths only, not values

## Testing Strategy

### Unit Tests
- Pattern matching accuracy
- Path parsing logic
- Status calculation
- Health score algorithm

### Integration Tests
- End-to-end with Vault dev mode
- Multiple file types
- Various secret statuses

### Example-based Testing
- `examples/test-repo/` for manual validation
- Known good/bad paths
- Reference counting verification

## Future Enhancements

### v0.2
- ✅ Audit log integration
- ✅ Enhanced staleness detection (metadata + access patterns)
- Concurrent validation
- Config file support

### v0.3
- Ownership mapping
- Usage graphing
- Vault namespace support
- Multiple mount points
- Dynamic template expansion

### v1.0
- Web UI
- Historical trend analysis
- Automated cleanup suggestions
- Secret rotation recommendations
- Policy violation detection
