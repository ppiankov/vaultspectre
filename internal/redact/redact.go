package redact

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Redactor masks sensitive values.
type Redactor interface {
	Redact(value string) string
}

// New returns a PastewatchRedactor if pastewatch-cli is available,
// otherwise falls back to FallbackRedactor.
func New() Redactor {
	if path, err := exec.LookPath("pastewatch-cli"); err == nil && path != "" {
		return &PastewatchRedactor{binPath: path}
	}
	return &FallbackRedactor{}
}

// IsTTY returns true if stdout is a terminal (not a pipe or redirect).
func IsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// --- Pastewatch integration ---

// PastewatchRedactor uses pastewatch-cli for redaction.
type PastewatchRedactor struct {
	binPath string
}

// pastewatchResult is the JSON output from pastewatch-cli scan.
type pastewatchResult struct {
	Redacted string `json:"redacted"`
	Findings int    `json:"findings"`
}

func (r *PastewatchRedactor) Redact(value string) string {
	if value == "" {
		return value
	}

	cmd := exec.Command(r.binPath, "scan", "--format", "json", "--input", value)
	out, err := cmd.Output()
	if err != nil {
		// Pastewatch failed — fall back to built-in
		fb := &FallbackRedactor{}
		return fb.Redact(value)
	}

	var result pastewatchResult
	if err := json.Unmarshal(out, &result); err != nil {
		fb := &FallbackRedactor{}
		return fb.Redact(value)
	}

	if result.Findings > 0 && result.Redacted != "" {
		return result.Redacted
	}

	// Pastewatch found nothing sensitive — still run fallback for safety
	fb := &FallbackRedactor{}
	return fb.Redact(value)
}

// --- Built-in fallback ---

// FallbackRedactor uses regex patterns for redaction when pastewatch is unavailable.
type FallbackRedactor struct{}

// Sensitive key name patterns (case-insensitive).
var sensitiveKeyPatterns = []string{
	"PASSWORD", "PASSWD", "PASS",
	"TOKEN", "SECRET", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY",
	"CREDENTIAL", "AUTH",
}

// Value patterns that indicate sensitive data regardless of key name.
var sensitiveValuePatterns = []*regexp.Regexp{
	// Vault tokens
	regexp.MustCompile(`^hvs\.[a-zA-Z0-9_-]{20,}$`),
	// JWT tokens
	regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}$`),
	// AWS access keys
	regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`),
	// DSN with credentials (scheme://user:pass@host)
	regexp.MustCompile(`://[^:]+:[^@]+@`),
	// Long base64-like strings (likely keys/tokens)
	regexp.MustCompile(`^[A-Za-z0-9+/=]{40,}$`),
}

func (r *FallbackRedactor) Redact(value string) string {
	if value == "" {
		return value
	}

	// Check value patterns
	for _, pattern := range sensitiveValuePatterns {
		if pattern.MatchString(value) {
			return mask(value)
		}
	}

	return value
}

// RedactByKeyName redacts a value based on whether the key name is sensitive.
func RedactByKeyName(key, value string) string {
	if IsSensitiveKey(key) {
		return mask(value)
	}
	return value
}

// IsSensitiveKey returns true if the key name suggests it contains a secret.
func IsSensitiveKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, pattern := range sensitiveKeyPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

// mask returns the first 4 chars + *** for identification, or just *** for short values.
func mask(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:4] + "***"
}

// MaskToken masks a token for display (first 4 + ... + last 4).
func MaskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
