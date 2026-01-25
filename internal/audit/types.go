package audit

import "time"

// AuditEntry represents a single Vault audit log entry
type AuditEntry struct {
	Time    time.Time     `json:"time"`
	Type    string        `json:"type"` // "request" or "response"
	Request *AuditRequest `json:"request"`
}

// AuditRequest contains request details from audit log
type AuditRequest struct {
	ID            string `json:"id"`
	Operation     string `json:"operation"` // "read", "write", "list", "delete"
	Path          string `json:"path"`
	RemoteAddress string `json:"remote_address"`
	ClientToken   string `json:"client_token"` // HMAC-hashed
}

// AccessInfo contains analyzed access information for a secret path
type AccessInfo struct {
	Path            string
	LastAccessTime  time.Time
	FirstAccessTime time.Time
	AccessCount     int
	DaysSinceAccess int
	UniqueClients   int
	SourceIPs       []string
}

// AccessMap maps secret paths to their access information
type AccessMap map[string]*AccessInfo
