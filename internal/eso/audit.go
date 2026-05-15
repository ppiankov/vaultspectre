package eso

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/vault"
)

// FindingClass identifies the type of ESO misconfiguration.
type FindingClass string

// Severity indicates how critical a finding is.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"

	// Finding classes — 8 original (WO-64)
	ESOVaultPathMissing            FindingClass = "ESO_VAULT_PATH_MISSING"
	ESOVaultPropertyMissing        FindingClass = "ESO_VAULT_PROPERTY_MISSING"
	ESOVaultOrphanedProperty       FindingClass = "ESO_VAULT_ORPHANED_PROPERTY"
	ESOK8sKeyUnused                FindingClass = "ESO_K8S_KEY_UNUSED"
	ESOK8sKeyMissing               FindingClass = "ESO_K8S_KEY_MISSING"
	ESOTargetNameMissing           FindingClass = "ESO_TARGET_NAME_MISSING"
	ESODuplicateKey                FindingClass = "ESO_DUPLICATE_KEY"
	ESOEnvPlaceholderUnsubstituted FindingClass = "ESO_ENV_PLACEHOLDER_UNSUBSTITUTED"

	// Finding classes — 3 additional from docflow audit (WO-66)
	ESOReloaderTargetMissing     FindingClass = "ESO_RELOADER_TARGET_MISSING"
	ESORefreshIntervalAggressive FindingClass = "ESO_REFRESH_INTERVAL_AGGRESSIVE"
	ESOVaultDuplicateSource      FindingClass = "ESO_VAULT_DUPLICATE_SOURCE"
)

// SourceLocation identifies the file and line where a misconfiguration was declared.
type SourceLocation struct {
	File string
	Line int
}

// Finding is a single ESO misconfiguration detected by Audit.
type Finding struct {
	Class       FindingClass
	Severity    Severity
	Message     string
	Path        string // Vault path (when applicable)
	Property    string // Vault property (when applicable)
	SecretName  string // K8s Secret name (when applicable)
	SecretKey   string // K8s Secret key (when applicable)
	Source      SourceLocation
	Remediation string
}

// AuditInput bundles the three parsed source inputs and configuration for Audit.
type AuditInput struct {
	ExternalSecrets []*ExternalSecret
	Consumers       *ConsumerScanResult // nil skips K8s consumer cross-checks
	Validator       *vault.Validator    // nil skips all Vault-dependent checks
	VaultListMount  string              // non-empty enables ESO_VAULT_ORPHANED_PROPERTY
	EnvPlaceholder  string              // configurable placeholder; defaults to "<ENV>"
	// MaxRefreshIntervalSeconds: WO-66 extension point, unused here
	MaxRefreshIntervalSeconds int
}

// Audit cross-references ExternalSecrets, Vault state, and K8s consumers and returns findings.
func Audit(ctx context.Context, in AuditInput) ([]Finding, error) {
	placeholder := in.EnvPlaceholder
	if placeholder == "" {
		placeholder = "<ENV>"
	}

	var findings []Finding

	// --- ESO_TARGET_NAME_MISSING ---
	for _, es := range in.ExternalSecrets {
		if es.TargetNameMissing {
			findings = append(findings, Finding{
				Class:       ESOTargetNameMissing,
				Severity:    SeverityWarning,
				Message:     fmt.Sprintf("ExternalSecret %q has no spec.target.name; ESO defaults K8s Secret name to %q", es.Name, es.Name),
				SecretName:  es.Name,
				Source:      SourceLocation{File: es.SourceFile},
				Remediation: fmt.Sprintf("Set spec.target.name explicitly in ExternalSecret %q to avoid relying on the default", es.Name),
			})
		}
	}

	// --- ESO_REFRESH_INTERVAL_AGGRESSIVE ---
	if in.MaxRefreshIntervalSeconds > 0 {
		threshold := time.Duration(in.MaxRefreshIntervalSeconds) * time.Second
		for _, es := range in.ExternalSecrets {
			if es.RefreshInterval == "" {
				continue
			}
			d, err := time.ParseDuration(es.RefreshInterval)
			if err != nil {
				continue
			}
			if d > 0 && d < threshold {
				findings = append(findings, Finding{
					Class:       ESORefreshIntervalAggressive,
					Severity:    SeverityWarning,
					Message:     fmt.Sprintf("ExternalSecret %q has refreshInterval %q (%v) which is below threshold of %v", es.Name, es.RefreshInterval, d, threshold),
					SecretName:  es.TargetName,
					Source:      SourceLocation{File: es.SourceFile},
					Remediation: fmt.Sprintf("Set refreshInterval to at least %v in ExternalSecret %q to reduce Vault API load", threshold, es.Name),
				})
			}
		}
	}

	// --- ESO_ENV_PLACEHOLDER_UNSUBSTITUTED ---
	for _, es := range in.ExternalSecrets {
		for _, d := range es.Data {
			if strings.Contains(d.RemoteRefKey, placeholder) {
				findings = append(findings, Finding{
					Class:       ESOEnvPlaceholderUnsubstituted,
					Severity:    SeverityError,
					Message:     fmt.Sprintf("ExternalSecret %q: remoteRef.key %q contains unsubstituted placeholder %q", es.Name, d.RemoteRefKey, placeholder),
					Path:        d.RemoteRefKey,
					SecretKey:   d.SecretKey,
					Source:      SourceLocation{File: es.SourceFile, Line: d.SourceLine},
					Remediation: fmt.Sprintf("Replace %q in remoteRef.key with the actual environment name", placeholder),
				})
			}
		}
		for _, df := range es.DataFrom {
			if strings.Contains(df.RemoteRefKey, placeholder) {
				findings = append(findings, Finding{
					Class:       ESOEnvPlaceholderUnsubstituted,
					Severity:    SeverityError,
					Message:     fmt.Sprintf("ExternalSecret %q: dataFrom key %q contains unsubstituted placeholder %q", es.Name, df.RemoteRefKey, placeholder),
					Path:        df.RemoteRefKey,
					Source:      SourceLocation{File: es.SourceFile, Line: df.SourceLine},
					Remediation: fmt.Sprintf("Replace %q in dataFrom key with the actual environment name", placeholder),
				})
			}
		}
	}

	// --- ESO_DUPLICATE_KEY ---
	// Track (effectiveTargetName, secretKey) → [producer ExternalSecret names + their sources]
	type keyRef struct{ target, key string }
	type keyProducer struct {
		esName string
		source SourceLocation
	}
	producedBy := make(map[keyRef][]keyProducer)
	effectiveTargetFor := make(map[string]string) // es.Name → effectiveTarget

	for _, es := range in.ExternalSecrets {
		effective := es.TargetName
		if effective == "" {
			effective = es.Name
		}
		effectiveTargetFor[es.Name] = effective
		for _, d := range es.Data {
			ref := keyRef{effective, d.SecretKey}
			producedBy[ref] = append(producedBy[ref], keyProducer{
				esName: es.Name,
				source: SourceLocation{File: es.SourceFile, Line: d.SourceLine},
			})
		}
	}
	for ref, producers := range producedBy {
		if len(producers) > 1 {
			names := make([]string, len(producers))
			for i, p := range producers {
				names[i] = p.esName
			}
			findings = append(findings, Finding{
				Class:       ESODuplicateKey,
				Severity:    SeverityWarning,
				Message:     fmt.Sprintf("secretKey %q in K8s Secret %q is produced by multiple ExternalSecrets: %s", ref.key, ref.target, strings.Join(names, ", ")),
				SecretName:  ref.target,
				SecretKey:   ref.key,
				Source:      producers[0].source,
				Remediation: fmt.Sprintf("Remove the duplicate secretKey %q definition from all but one ExternalSecret", ref.key),
			})
		}
	}

	// --- ESO_VAULT_DUPLICATE_SOURCE ---
	// Detect the same (Vault path, property) pulled into multiple distinct K8s target Secrets.
	type vaultSource struct{ path, property string }
	dupSourceTargets := make(map[vaultSource]map[string]bool) // source → set of target Secret names
	dupSourceESNames := make(map[vaultSource][]string)        // source → ES names in encounter order

	for _, es := range in.ExternalSecrets {
		effective := effectiveTargetFor[es.Name]
		for _, d := range es.Data {
			if strings.Contains(d.RemoteRefKey, placeholder) {
				continue
			}
			src := vaultSource{d.RemoteRefKey, d.RemoteRefProperty}
			if dupSourceTargets[src] == nil {
				dupSourceTargets[src] = make(map[string]bool)
			}
			if !dupSourceTargets[src][effective] {
				dupSourceTargets[src][effective] = true
				dupSourceESNames[src] = append(dupSourceESNames[src], es.Name)
			}
		}
	}
	for src, targets := range dupSourceTargets {
		if len(targets) <= 1 {
			continue
		}
		esNames := dupSourceESNames[src]
		sort.Strings(esNames)
		propDesc := src.property
		if propDesc == "" {
			propDesc = "(all)"
		}
		findings = append(findings, Finding{
			Class:       ESOVaultDuplicateSource,
			Severity:    SeverityWarning,
			Message:     fmt.Sprintf("Vault source %q property %q is pulled into %d K8s Secrets by: %s", src.path, propDesc, len(targets), strings.Join(esNames, ", ")),
			Path:        src.path,
			Property:    src.property,
			Remediation: fmt.Sprintf("Consolidate the %d ExternalSecrets pulling Vault path %q into a single source of truth", len(targets), src.path),
		})
	}

	// --- Vault-dependent checks ---
	if in.Validator != nil {
		vf, err := runVaultChecks(ctx, in, placeholder)
		if err != nil {
			return findings, err
		}
		findings = append(findings, vf...)
	}

	// --- K8s consumer cross-checks ---
	if in.Consumers != nil {
		findings = append(findings, runK8sChecks(in, effectiveTargetFor)...)

		// --- ESO_RELOADER_TARGET_MISSING ---
		producedTargets := make(map[string]bool)
		for _, es := range in.ExternalSecrets {
			producedTargets[effectiveTargetFor[es.Name]] = true
		}
		for _, ref := range in.Consumers.ReloaderReferences {
			if !producedTargets[ref.SecretName] {
				findings = append(findings, Finding{
					Class:       ESOReloaderTargetMissing,
					Severity:    SeverityWarning,
					Message:     fmt.Sprintf("Reloader annotation references K8s Secret %q but no ExternalSecret produces that target", ref.SecretName),
					SecretName:  ref.SecretName,
					Source:      SourceLocation{File: ref.SourceFile, Line: ref.SourceLine},
					Remediation: fmt.Sprintf("Remove %q from the reloader annotation or add an ExternalSecret that targets it", ref.SecretName),
				})
			}
		}
	}

	return findings, nil
}

// runVaultChecks emits ESO_VAULT_PATH_MISSING, ESO_VAULT_PROPERTY_MISSING, and
// ESO_VAULT_ORPHANED_PROPERTY findings using the supplied Validator.
func runVaultChecks(ctx context.Context, in AuditInput, placeholder string) ([]Finding, error) {
	var findings []Finding

	// Deduplicate path+property pairs to avoid redundant Vault calls.
	type pathProp struct{ path, property string }
	checked := make(map[pathProp]vault.PropertyStatus)

	for _, es := range in.ExternalSecrets {
		for _, d := range es.Data {
			if strings.Contains(d.RemoteRefKey, placeholder) {
				continue // placeholder unsubstituted; skip vault check
			}

			pp := pathProp{d.RemoteRefKey, d.RemoteRefProperty}
			status, seen := checked[pp]
			if !seen {
				if ctx.Err() != nil {
					return findings, ctx.Err()
				}
				status = in.Validator.ValidatePathProperty(ctx, d.RemoteRefKey, d.RemoteRefProperty)
				checked[pp] = status
			}

			switch status {
			case vault.PropertyPathMissing:
				findings = append(findings, Finding{
					Class:       ESOVaultPathMissing,
					Severity:    SeverityError,
					Message:     fmt.Sprintf("ExternalSecret %q: Vault path %q does not exist", es.Name, d.RemoteRefKey),
					Path:        d.RemoteRefKey,
					SecretKey:   d.SecretKey,
					Source:      SourceLocation{File: es.SourceFile, Line: d.SourceLine},
					Remediation: fmt.Sprintf("Create the Vault secret at path %q or update remoteRef.key", d.RemoteRefKey),
				})
			case vault.PropertyMissing:
				findings = append(findings, Finding{
					Class:       ESOVaultPropertyMissing,
					Severity:    SeverityError,
					Message:     fmt.Sprintf("ExternalSecret %q: property %q not found at Vault path %q", es.Name, d.RemoteRefProperty, d.RemoteRefKey),
					Path:        d.RemoteRefKey,
					Property:    d.RemoteRefProperty,
					SecretKey:   d.SecretKey,
					Source:      SourceLocation{File: es.SourceFile, Line: d.SourceLine},
					Remediation: fmt.Sprintf("Add property %q to Vault path %q", d.RemoteRefProperty, d.RemoteRefKey),
				})
			case vault.PropertyNetworkError:
				return findings, fmt.Errorf("vault network error checking %q: retry exhausted", d.RemoteRefKey)
			}
		}

		for _, df := range es.DataFrom {
			if strings.Contains(df.RemoteRefKey, placeholder) {
				continue
			}
			pp := pathProp{df.RemoteRefKey, ""}
			if _, seen := checked[pp]; seen {
				continue
			}
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			// DataFrom only needs path existence check.
			status, err := in.Validator.ValidatePath(df.RemoteRefKey)
			checked[pp] = vault.PropertyStatus(status)
			if err != nil {
				return findings, fmt.Errorf("vault error checking %q: %w", df.RemoteRefKey, err)
			}
			if status == "missing" {
				findings = append(findings, Finding{
					Class:       ESOVaultPathMissing,
					Severity:    SeverityError,
					Message:     fmt.Sprintf("ExternalSecret %q: dataFrom Vault path %q does not exist", es.Name, df.RemoteRefKey),
					Path:        df.RemoteRefKey,
					Source:      SourceLocation{File: es.SourceFile, Line: df.SourceLine},
					Remediation: fmt.Sprintf("Create the Vault secret at path %q or remove the dataFrom entry", df.RemoteRefKey),
				})
			}
		}
	}

	// --- ESO_VAULT_ORPHANED_PROPERTY ---
	if in.VaultListMount == "" {
		return findings, nil
	}
	// Build map of pulled properties per path.
	pulledProps := make(map[string]map[string]bool) // path → set of pulled property names
	for _, es := range in.ExternalSecrets {
		for _, d := range es.Data {
			if d.RemoteRefProperty == "" {
				continue
			}
			if pulledProps[d.RemoteRefKey] == nil {
				pulledProps[d.RemoteRefKey] = make(map[string]bool)
			}
			pulledProps[d.RemoteRefKey][d.RemoteRefProperty] = true
		}
	}
	for path, pulled := range pulledProps {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		allProps, err := in.Validator.ListProperties(path)
		if err != nil {
			return findings, fmt.Errorf("vault error listing properties at %q: %w", path, err)
		}
		for _, prop := range allProps {
			if !pulled[prop] {
				findings = append(findings, Finding{
					Class:       ESOVaultOrphanedProperty,
					Severity:    SeverityInfo,
					Message:     fmt.Sprintf("Vault property %q at path %q is not referenced by any ExternalSecret", prop, path),
					Path:        path,
					Property:    prop,
					Remediation: fmt.Sprintf("Remove unused property %q from Vault path %q, or add a spec.data entry to pull it", prop, path),
				})
			}
		}
	}

	return findings, nil
}

// runK8sChecks emits ESO_K8S_KEY_UNUSED and ESO_K8S_KEY_MISSING findings.
func runK8sChecks(in AuditInput, effectiveTargetFor map[string]string) []Finding {
	var findings []Finding

	// Build produced set: (targetSecret, secretKey) → source
	type secretKeyPair struct{ secret, key string }
	type production struct {
		esName string
		source SourceLocation
	}
	produced := make(map[secretKeyPair]production)
	dataFromSecrets := make(map[string]bool) // target Secrets covered by a DataFrom (PullAll)

	for _, es := range in.ExternalSecrets {
		effective := effectiveTargetFor[es.Name]
		for _, d := range es.Data {
			pair := secretKeyPair{effective, d.SecretKey}
			if _, exists := produced[pair]; !exists {
				produced[pair] = production{
					esName: es.Name,
					source: SourceLocation{File: es.SourceFile, Line: d.SourceLine},
				}
			}
		}
		if len(es.DataFrom) > 0 {
			dataFromSecrets[effective] = true
		}
	}

	// Build consumed set: (secretName, key) → source
	type consumption struct {
		consumerKind string
		source       SourceLocation
	}
	consumed := make(map[secretKeyPair]consumption)
	pullAllConsumed := make(map[string]bool) // Secret names consumed wholesale (envFrom / volume)

	for _, c := range in.Consumers.Consumers {
		if c.PullAll {
			pullAllConsumed[c.SecretName] = true
		} else {
			pair := secretKeyPair{c.SecretName, c.Key}
			if _, exists := consumed[pair]; !exists {
				consumed[pair] = consumption{
					consumerKind: c.ConsumerKind,
					source:       SourceLocation{File: c.SourceFile, Line: c.SourceLine},
				}
			}
		}
	}

	// ESO_K8S_KEY_UNUSED: produced but not consumed
	for pair, prod := range produced {
		if pullAllConsumed[pair.secret] {
			continue // whole Secret is consumed; no individual key is unused
		}
		if _, ok := consumed[pair]; !ok {
			findings = append(findings, Finding{
				Class:       ESOK8sKeyUnused,
				Severity:    SeverityInfo,
				Message:     fmt.Sprintf("ExternalSecret %q produces secretKey %q into K8s Secret %q but no consumer references it", prod.esName, pair.key, pair.secret),
				SecretName:  pair.secret,
				SecretKey:   pair.key,
				Source:      prod.source,
				Remediation: fmt.Sprintf("Remove secretKey %q from ExternalSecret %q or add a consumer for it", pair.key, prod.esName),
			})
		}
	}

	// ESO_K8S_KEY_MISSING: consumed but not produced
	for pair, cons := range consumed {
		if dataFromSecrets[pair.secret] {
			continue // DataFrom covers all keys in this Secret; can't verify individual keys
		}
		if _, ok := produced[pair]; !ok {
			findings = append(findings, Finding{
				Class:       ESOK8sKeyMissing,
				Severity:    SeverityError,
				Message:     fmt.Sprintf("Consumer references secretKeyRef{name:%q, key:%q} but no ExternalSecret produces it", pair.secret, pair.key),
				SecretName:  pair.secret,
				SecretKey:   pair.key,
				Source:      cons.source,
				Remediation: fmt.Sprintf("Add a spec.data entry in the ExternalSecret targeting %q to produce key %q", pair.secret, pair.key),
			})
		}
	}

	return findings
}
