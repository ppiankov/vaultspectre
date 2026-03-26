package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalAuditLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	log, err := NewLocalAuditLog(path)
	if err != nil {
		t.Fatalf("NewLocalAuditLog: %v", err)
	}
	defer log.Close()

	log.Log("grep", "kv/projects/ads/int/config", true)
	log.Log("grep", "kv/projects/rnd/int/reco-go", false)
	log.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var event LocalEvent
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if event.Command != "grep" {
		t.Errorf("command = %q, want grep", event.Command)
	}
	if event.Path != "kv/projects/ads/int/config" {
		t.Errorf("path = %q", event.Path)
	}
	if !event.Redacted {
		t.Error("first event should be redacted=true")
	}
	if event.Timestamp == "" {
		t.Error("timestamp should be set")
	}

	// Verify no secret values in output
	if strings.Contains(string(data), "password") || strings.Contains(string(data), "secret") {
		t.Error("audit log should never contain secret values")
	}
}

func TestLocalAuditLogNil(t *testing.T) {
	log, err := NewLocalAuditLog("")
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if log != nil {
		t.Error("empty path should return nil")
	}
	// Verify nil log doesn't panic
	log.Log("grep", "kv/test", true)
	log.Close()
}
