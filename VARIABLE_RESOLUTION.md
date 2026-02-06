# Variable Resolution - The Correct Approach

## The Real Problem

VaultSpectre tries to validate `{{ vault_secret_path }}/users/admin` literally against Vault.

This fails because:
1. Vault doesn't have a secret at literal path `{{ vault_secret_path }}/users/admin`
2. The variables need to be resolved first
3. But VaultSpectre doesn't know what values to use

## Wrong Solution (Current Approach)

**Skip dynamic paths entirely** and mark them as "cannot validate".

This means:
- 23 paths marked "skipped_dynamic"
- Health score says "GOOD" but actually **no validation happened**
- False sense of security

## Wrong Solution #2 (Hallucination)

**Guess what the variables might be** and try those values.

This means:
- VaultSpectre invents values for `{{ vault_secret_path }}`
- Validates against wrong paths
- Reports false positives/negatives
- Violates RootOps principle: don't guess

## Correct Solution (RootOps)

**Refuse to validate without explicit variable values**.

Make the user provide variable resolution explicitly:

```bash
# Option 1: Provide variable values via CLI
vaultspectre scan . \
  --var vault_secret_path=secret/data/production/clickhouse/cdrapi \
  --var cluster_name=cdrapi

# Option 2: Provide variable file
vaultspectre scan . \
  --var-file vars.yaml

# vars.yaml
variables:
  vault_secret_path: secret/data/production/clickhouse/cdrapi
  cluster_name: cdrapi
  environment: production
```

Now VaultSpectre can:
1. Extract `{{ vault_secret_path }}/users/admin`
2. Resolve: `secret/data/production/clickhouse/cdrapi/users/admin`
3. Validate the **actual path** against Vault

## Implementation

### Stage 1: Extract with Variables

```go
type Reference struct {
    RawPath      string   // Original: "{{ vault_secret_path }}/users/admin"
    ResolvedPath string   // After resolution: "secret/data/production/clickhouse/cdrapi/users/admin"
    Variables    []string // ["vault_secret_path"]
    Status       string   // "pending_resolution" or "pending_validation"
}
```

### Stage 2: Resolution (Required)

```go
type Resolver struct {
    variables map[string]string
}

func (r *Resolver) Resolve(ref Reference) (Reference, error) {
    if len(ref.Variables) == 0 {
        // Static path, no resolution needed
        ref.ResolvedPath = ref.RawPath
        ref.Status = "pending_validation"
        return ref, nil
    }

    // Try to resolve
    resolved := ref.RawPath
    missingVars := []string{}

    for _, varName := range ref.Variables {
        value, exists := r.variables[varName]
        if !exists {
            missingVars = append(missingVars, varName)
            continue
        }

        // Replace {{ varName }} with value
        placeholder := "{{ " + varName + " }}"
        resolved = strings.ReplaceAll(resolved, placeholder, value)
    }

    if len(missingVars) > 0 {
        // ROOTOPS: Refuse to proceed without all variables
        return ref, fmt.Errorf("cannot resolve path - missing variables: %v", missingVars)
    }

    ref.ResolvedPath = resolved
    ref.Status = "pending_validation"
    return ref, nil
}
```

### Stage 3: Validate Resolved Paths Only

```go
func (v *Validator) Validate(refs []Reference) []ValidationResult {
    results := []ValidationResult{}

    for _, ref := range refs {
        // ROOTOPS: Only validate if resolved
        if ref.Status != "pending_validation" {
            results = append(results, ValidationResult{
                Reference: ref,
                Status:    StatusUnresolved,
                Message:   fmt.Sprintf("Path contains unresolved variables: %v", ref.Variables),
            })
            continue
        }

        // Validate the resolved path
        result := v.checkVault(ref.ResolvedPath)
        results = append(results, result)
    }

    return results
}
```

## User Experience

### Without Variables (Current Broken State)

```bash
$ vaultspectre scan .
ERROR: Found 19 paths with unresolved variables

Cannot validate:
  - {{ vault_secret_path }}/users/admin (missing: vault_secret_path)
  - {{ vault_secret_path }}/users/readonly (missing: vault_secret_path)

Please provide variable values:
  vaultspectre scan . --var vault_secret_path=secret/data/production/clickhouse/cdrapi

Or provide a variable file:
  vaultspectre scan . --var-file vars.yaml
```

### With Variables (Proper Validation)

```bash
$ vaultspectre scan . --var vault_secret_path=secret/data/production/clickhouse/cdrapi
Resolving variables...
  ✓ Resolved 19 paths with variable vault_secret_path

Validating against Vault...

Summary:
  Total References:     24
  ├─ Validated:         23
  │  ├─ OK:            21
  │  └─ Missing:        2  ← REAL missing secrets
  ├─ Skipped:           1
  │  └─ Policy:         1  (HCL file)

  Validation Health:    WARNING ⚠ (2 secrets missing)

Missing Secrets:
  [MISSING] secret/data/production/clickhouse/cdrapi/users/newuser
    Resolved from: {{ vault_secret_path }}/users/newuser
    Referenced in: inventory/production/group_vars/cdrapi_servers.yml:45
```

## Auto-Detection of Variables

VaultSpectre can **suggest** variables to provide by analyzing Ansible inventory:

```bash
$ vaultspectre scan . --detect-vars
Detected Ansible variables in inventory/production/group_vars/all.yml:
  - vault_secret_path: "secret/data/production/clickhouse/cdrapi"
  - environment: "production"
  - cluster_name: "cdrapi"

Automatically resolving using detected values...
```

But this is **opt-in** - VaultSpectre never guesses without explicit permission.

## RootOps Alignment

This approach:
1. ✅ **Refuses to validate without resolution** (no guessing)
2. ✅ **Makes variable requirements explicit** (user must provide values)
3. ✅ **Validates actual paths** (real Vault paths, not templates)
4. ✅ **Honest reporting** (missing = actually missing, not unresolved)
5. ✅ **Can auto-detect** (but only with opt-in)

## Example: Multiple Environments

```yaml
# vars-production.yaml
variables:
  vault_secret_path: secret/data/production/clickhouse
  cluster_name: cdrapi

# vars-staging.yaml
variables:
  vault_secret_path: secret/data/staging/clickhouse
  cluster_name: cdrapi-staging
```

```bash
# Validate production
vaultspectre scan . --var-file vars-production.yaml

# Validate staging
vaultspectre scan . --var-file vars-staging.yaml
```

Now VaultSpectre validates **real paths** in each environment, not template paths.

## Implementation Plan

1. Add `--var` and `--var-file` CLI flags
2. Add variable resolution stage between extraction and validation
3. Add auto-detection with `--detect-vars` (opt-in)
4. Update health score to only count resolved+validated paths
5. Clear error messages when variables are missing

## Philosophy

**Principiis obsta** — resist the beginnings.

The failure point is not validation - it's **attempting validation without resolution**.

VaultSpectre should refuse to validate unresolved templates, not skip them or guess values.

Resolution must be explicit, never implicit.
