package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/ppiankov/vaultspectre/internal/audit"
)

// PropertyStatus is the result of a path+property validation check.
type PropertyStatus string

const (
	PropertyOK           PropertyStatus = "OK"
	PropertyPathMissing  PropertyStatus = "PATH_MISSING"
	PropertyMissing      PropertyStatus = "PROPERTY_MISSING"
	PropertyAccessDenied PropertyStatus = "ACCESS_DENIED"
	PropertyNetworkError PropertyStatus = "NETWORK_ERROR"
)

// Validator validates Vault secret paths
type Validator struct {
	client        *Client
	auditAnalyzer *audit.Analyzer // Optional, can be nil
}

// NewValidator creates a validator without audit log support
func NewValidator(client *Client) *Validator {
	return &Validator{
		client:        client,
		auditAnalyzer: nil,
	}
}

// NewValidatorWithAudit creates a validator with audit log support
func NewValidatorWithAudit(client *Client, analyzer *audit.Analyzer) *Validator {
	return &Validator{
		client:        client,
		auditAnalyzer: analyzer,
	}
}

// ValidatePath validates a Vault secret path and returns its status
// Handles both KV v1 and KV v2 paths automatically
func (v *Validator) ValidatePath(path string) (string, error) {
	// Try to read the secret as-is first
	secret, err := v.client.Read(path)

	if err != nil {
		// Check if it's a permission error
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "403") {
			return "access_denied", nil
		}
		return "error", err
	}

	// If secret exists with data, return ok
	// Note: Vault API returns non-nil secret with empty data for nonexistent paths
	if secret != nil && secret.Data != nil && len(secret.Data) > 0 {
		return "ok", nil
	}

	// Secret doesn't exist at this path - try KV v2 path (add /data/)
	kvv2Path := convertToKVv2Path(path)
	if kvv2Path != path {
		secret, err = v.client.Read(kvv2Path)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") ||
				strings.Contains(err.Error(), "403") {
				return "access_denied", nil
			}
			return "error", err
		}
		if secret != nil && secret.Data != nil && len(secret.Data) > 0 {
			return "ok", nil
		}
	}

	// Tried both paths, secret doesn't exist
	return "missing", nil
}

// convertToKVv2Path converts a KV v1 style path to KV v2 by inserting /data/
// e.g., "secret/production/app" -> "secret/data/production/app"
// Only checks the second segment for the KV v2 marker to avoid false positives
// when a path segment deeper in the tree happens to be named "data"
func convertToKVv2Path(path string) string {
	// System paths (sys/, auth/, etc.) shouldn't be modified
	if strings.HasPrefix(path, "sys/") || strings.HasPrefix(path, "auth/") ||
		strings.HasPrefix(path, "cubbyhole/") || strings.HasPrefix(path, "identity/") {
		return path
	}

	// Split into mount / remainder
	parts := strings.SplitN(path, "/", 3)

	// Single segment or mount-only — nothing to convert
	if len(parts) < 2 || parts[1] == "" {
		return path
	}

	// If the second segment is already "data" or "metadata", this is already a KV v2 path
	if parts[1] == "data" || parts[1] == "metadata" {
		return path
	}

	// Insert /data/ after the mount point (first segment)
	return parts[0] + "/data/" + strings.Join(parts[1:], "/")
}

// CheckStaleness checks if a secret is stale using BOTH metadata and audit logs
// Returns: (isStale, lastAccessTime, error)
func (v *Validator) CheckStaleness(path string, thresholdDays int) (bool, string, error) {
	var metadataTime time.Time
	var auditTime time.Time
	var accessCount int

	// Try to get KV v2 metadata
	mount, secretPath := parseKVv2Path(path)
	if mount != "" && secretPath != "" {
		metadata, err := v.client.GetMetadata(mount, secretPath)
		if err == nil && metadata != nil && metadata.Data != nil {
			if updatedTimeRaw, ok := metadata.Data["updated_time"].(string); ok {
				metadataTime, _ = time.Parse(time.RFC3339, updatedTimeRaw)
			}
		}
	}

	// Try to get audit log access time (if analyzer available)
	if v.auditAnalyzer != nil {
		if lastAccess, count, found := v.auditAnalyzer.GetLastAccess(path); found {
			auditTime = lastAccess
			accessCount = count
		}
	}

	// Determine most recent activity (modified OR accessed)
	var lastActivity time.Time
	var activitySource string

	if !metadataTime.IsZero() && !auditTime.IsZero() {
		if auditTime.After(metadataTime) {
			lastActivity = auditTime
			activitySource = "accessed"
		} else {
			lastActivity = metadataTime
			activitySource = "modified"
		}
	} else if !metadataTime.IsZero() {
		lastActivity = metadataTime
		activitySource = "modified"
	} else if !auditTime.IsZero() {
		lastActivity = auditTime
		activitySource = "accessed"
	} else {
		// No data available from either source
		return false, "", fmt.Errorf("no staleness data available")
	}

	daysSinceActivity := int(time.Since(lastActivity).Hours() / 24)
	isStale := daysSinceActivity > thresholdDays

	// Format last access time with activity source and count
	var timeStr string
	if activitySource == "accessed" && accessCount > 0 {
		timeStr = fmt.Sprintf("%s (%s %d times, last %d days ago)",
			lastActivity.Format(time.RFC3339), activitySource, accessCount, daysSinceActivity)
	} else {
		timeStr = fmt.Sprintf("%s (%s, %d days ago)",
			lastActivity.Format(time.RFC3339), activitySource, daysSinceActivity)
	}

	return isStale, timeStr, nil
}

// parseKVv2Path attempts to parse a KV v2 path into mount and secret path
// e.g., "secret/data/prod/api/key" -> ("secret", "prod/api/key")
// Only the second segment is treated as the KV v2 marker to avoid false
// positives when deeper path segments happen to be named "data"
func parseKVv2Path(fullPath string) (string, string) {
	parts := strings.Split(fullPath, "/")

	// KV v2 paths have format: mount/data/path/to/secret (minimum 3 segments)
	if len(parts) < 3 {
		return "", ""
	}

	// Only the second segment (index 1) is the KV v2 data marker
	if parts[1] == "data" {
		mount := parts[0]
		secretPath := strings.Join(parts[2:], "/")
		return mount, secretPath
	}

	return "", ""
}

// ValidatePathProperty checks whether a specific property exists within a Vault path.
// Handles both KV v1 (property in secret.Data) and KV v2 (property under secret.Data["data"]).
// Returns PropertyNetworkError if ctx is already cancelled before making any request.
func (v *Validator) ValidatePathProperty(ctx context.Context, path, property string) PropertyStatus {
	if ctx.Err() != nil {
		return PropertyNetworkError
	}

	secret, err := v.client.Read(path)
	if err != nil {
		if isPermissionError(err) {
			return PropertyAccessDenied
		}
		return PropertyNetworkError
	}

	if secret != nil && secret.Data != nil && len(secret.Data) > 0 {
		return checkProperty(secret, property)
	}

	// Path returned no data — try KV v2 path format
	kvv2Path := convertToKVv2Path(path)
	if kvv2Path == path {
		return PropertyPathMissing
	}

	if ctx.Err() != nil {
		return PropertyNetworkError
	}

	secret, err = v.client.Read(kvv2Path)
	if err != nil {
		if isPermissionError(err) {
			return PropertyAccessDenied
		}
		return PropertyNetworkError
	}

	if secret == nil || secret.Data == nil || len(secret.Data) == 0 {
		return PropertyPathMissing
	}
	return checkProperty(secret, property)
}

// checkProperty returns OK if property exists in the secret, PROPERTY_MISSING otherwise.
func checkProperty(secret *vaultapi.Secret, property string) PropertyStatus {
	props := extractProperties(secret)
	if props == nil {
		return PropertyPathMissing
	}
	if _, ok := props[property]; ok {
		return PropertyOK
	}
	return PropertyMissing
}

// extractProperties returns the property map from a Vault secret response.
// KV v2 nests properties under data.data; KV v1 exposes them directly in data.
func extractProperties(secret *vaultapi.Secret) map[string]interface{} {
	if secret == nil || secret.Data == nil {
		return nil
	}
	if nested, ok := secret.Data["data"].(map[string]interface{}); ok {
		return nested
	}
	return secret.Data
}

// ListProperties returns the property names present at path (handles KV v1 and v2).
// Returns nil, nil when the path does not exist or is permission-denied (not an error).
func (v *Validator) ListProperties(path string) ([]string, error) {
	secret, err := v.client.Read(path)
	if err != nil {
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, err
	}

	if secret == nil || secret.Data == nil || len(secret.Data) == 0 {
		kvv2Path := convertToKVv2Path(path)
		if kvv2Path == path {
			return nil, nil
		}
		secret, err = v.client.Read(kvv2Path)
		if err != nil {
			if isPermissionError(err) {
				return nil, nil
			}
			return nil, err
		}
		if secret == nil || secret.Data == nil {
			return nil, nil
		}
	}

	props := extractProperties(secret)
	if props == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	return keys, nil
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "403")
}
