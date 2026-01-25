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
func (v *Validator) ValidatePath(path string) (string, error) {
	// Try to read the secret
	secret, err := v.client.Read(path)

	if err != nil {
		// Check if it's a permission error
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "403") {
			return "access_denied", nil
		}
		return "error", err
	}

	// If secret is nil, it doesn't exist
	if secret == nil {
		return "missing", nil
	}

	// Secret exists and is accessible
	return "ok", nil
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
func parseKVv2Path(fullPath string) (string, string) {
	parts := strings.Split(fullPath, "/")

	// KV v2 paths typically have format: mount/data/path/to/secret
	if len(parts) < 3 {
		return "", ""
	}

	// Look for "/data/" segment which indicates KV v2
	for i, part := range parts {
		if part == "data" && i > 0 && i < len(parts)-1 {
			mount := strings.Join(parts[:i], "/")
			secretPath := strings.Join(parts[i+1:], "/")
			return mount, secretPath
		}
	}

	return "", ""
}
