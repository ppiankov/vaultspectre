package vault

import (
	"fmt"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/audit"
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
