package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// LocalEvent is a single access event for the local audit trail.
// Never contains secret values.
type LocalEvent struct {
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Path      string `json:"path"`
	Redacted  bool   `json:"redacted"`
}

// LocalAuditLog writes access events to a JSON-lines file.
type LocalAuditLog struct {
	file *os.File
	mu   sync.Mutex
}

// NewLocalAuditLog opens or creates an audit log file (append-only).
// Returns nil (no-op) if path is empty.
func NewLocalAuditLog(path string) (*LocalAuditLog, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	return &LocalAuditLog{file: f}, nil
}

// Log writes an access event. Safe for concurrent use.
func (l *LocalAuditLog) Log(command, path string, redacted bool) {
	if l == nil {
		return
	}

	event := LocalEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Command:   command,
		Path:      path,
		Redacted:  redacted,
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.file.Write(append(data, '\n'))
}

// Close closes the audit log file.
func (l *LocalAuditLog) Close() {
	if l == nil {
		return
	}
	_ = l.file.Close()
}
