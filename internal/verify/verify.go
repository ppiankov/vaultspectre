package verify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Status represents the result of a verification check.
type Status string

const (
	StatusOK          Status = "ok"
	StatusFailed      Status = "failed"
	StatusSkipped     Status = "skipped"
	StatusUnsupported Status = "unsupported"
	StatusTimeout     Status = "timeout"
	StatusFormatError Status = "format_error"
)

// Result holds the outcome of verifying a single secret.
type Result struct {
	Path    string `json:"path"`
	Status  Status `json:"status"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
	Details string `json:"details,omitempty"` // e.g. "json_blob stored as string"
}

// Verifier checks credentials for liveness.
type Verifier interface {
	// Verify checks the given secret data and returns a result.
	Verify(path string, data map[string]interface{}, timeout time.Duration) Result
}

// FormatVerifier checks secret value formats without live connections.
type FormatVerifier struct{}

// NewFormatVerifier creates a format verifier.
func NewFormatVerifier() *FormatVerifier {
	return &FormatVerifier{}
}

// Verify checks format correctness of secret values.
func (v *FormatVerifier) Verify(path string, data map[string]interface{}, _ time.Duration) Result {
	var issues []string

	for key, val := range data {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		keyLower := strings.ToLower(key)

		// Check json_blob fields: value should be a JSON object, not a bare string
		if keyLower == "clickhouse" || keyLower == "postgres" || keyLower == "redis" || keyLower == "mongodb" {
			trimmed := strings.TrimSpace(strVal)
			if trimmed == "" {
				issues = append(issues, fmt.Sprintf("%s: empty value", key))
				continue
			}
			if !strings.HasPrefix(trimmed, "{") {
				issues = append(issues, fmt.Sprintf("%s: value is string, expected JSON object", key))
				continue
			}
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(strVal), &obj); err != nil {
				issues = append(issues, fmt.Sprintf("%s: invalid JSON: %v", key, err))
			}
		}

		// Check URI-like fields
		if strings.HasSuffix(keyLower, "_url") || strings.HasSuffix(keyLower, "_uri") || strings.HasSuffix(keyLower, "_endpoint") {
			if _, err := url.Parse(strVal); err != nil {
				issues = append(issues, fmt.Sprintf("%s: invalid URI: %v", key, err))
			} else if strVal != "" && !strings.Contains(strVal, "://") {
				issues = append(issues, fmt.Sprintf("%s: URI missing scheme", key))
			}
		}
	}

	if len(issues) > 0 {
		return Result{
			Path:    path,
			Status:  StatusFormatError,
			Details: strings.Join(issues, "; "),
		}
	}

	return Result{
		Path:   path,
		Status: StatusOK,
	}
}

// DetectCredentialType inspects secret keys and returns the detected type.
func DetectCredentialType(data map[string]interface{}) string {
	keys := make(map[string]bool)
	for k := range data {
		keys[strings.ToUpper(k)] = true
	}

	// ClickHouse detection
	if keys["CLICKHOUSE_HOST"] && keys["CLICKHOUSE_PASSWORD"] {
		return "clickhouse"
	}
	if keys["STAT_CLICKHOUSE_HOST"] && keys["STAT_CLICKHOUSE_PASSWORD"] {
		return "clickhouse_stat"
	}
	if _, ok := data["clickhouse"]; ok {
		return "clickhouse_blob"
	}

	// PostgreSQL detection
	if keys["POSTGRES_HOST"] && keys["POSTGRES_PASSWORD"] {
		return "postgresql"
	}
	if keys["DATABASE_URL"] {
		return "postgresql_url"
	}

	// Generic HTTP
	for k := range keys {
		if (strings.HasSuffix(k, "_URL") || strings.HasSuffix(k, "_ENDPOINT")) &&
			(keys[strings.TrimSuffix(k, "_URL")+"_TOKEN"] || keys[strings.TrimSuffix(k, "_ENDPOINT")+"_TOKEN"] || keys["TOKEN"] || keys["API_KEY"]) {
			return "http_api"
		}
	}

	return "unknown"
}
