package audit

import (
	"os"
	"testing"
	"time"
)

func TestParser_Parse(t *testing.T) {
	// Create a temporary audit log file
	tmpFile, err := os.CreateTemp("", "vault-audit-*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write sample audit log entries
	auditLog := `{"time":"2026-01-23T10:00:00Z","type":"request","request":{"id":"123","operation":"read","path":"secret/data/test1","remote_address":"127.0.0.1","client_token":"hmac-123"}}
{"time":"2026-01-23T11:00:00Z","type":"request","request":{"id":"124","operation":"read","path":"secret/data/test1","remote_address":"127.0.0.1","client_token":"hmac-123"}}
{"time":"2026-01-23T12:00:00Z","type":"request","request":{"id":"125","operation":"write","path":"secret/data/test2","remote_address":"127.0.0.1","client_token":"hmac-123"}}
{"time":"2026-01-23T13:00:00Z","type":"request","request":{"id":"126","operation":"read","path":"secret/data/test2","remote_address":"192.168.1.1","client_token":"hmac-456"}}
{"time":"2026-01-23T14:00:00Z","type":"response","request":null}
`

	if _, err := tmpFile.WriteString(auditLog); err != nil {
		t.Fatalf("Failed to write audit log: %v", err)
	}
	tmpFile.Close()

	// Parse the audit log
	parser := NewParser(tmpFile.Name())
	accessMap, err := parser.Parse(0) // 0 = all time
	if err != nil {
		t.Fatalf("Failed to parse audit log: %v", err)
	}

	// Verify results
	if len(accessMap) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(accessMap))
	}

	// Check test1 (2 read operations)
	if info, ok := accessMap["secret/data/test1"]; ok {
		if info.AccessCount != 2 {
			t.Errorf("Expected 2 accesses for test1, got %d", info.AccessCount)
		}
		expectedTime, _ := time.Parse(time.RFC3339, "2026-01-23T11:00:00Z")
		if !info.LastAccessTime.Equal(expectedTime) {
			t.Errorf("Expected last access time %v, got %v", expectedTime, info.LastAccessTime)
		}
	} else {
		t.Error("test1 not found in access map")
	}

	// Check test2 (1 read operation, write should be ignored)
	if info, ok := accessMap["secret/data/test2"]; ok {
		if info.AccessCount != 1 {
			t.Errorf("Expected 1 access for test2, got %d", info.AccessCount)
		}
		if info.UniqueClients != 1 {
			t.Errorf("Expected 1 unique client for test2, got %d", info.UniqueClients)
		}
	} else {
		t.Error("test2 not found in access map")
	}
}

func TestAnalyzer_GetLastAccess(t *testing.T) {
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)

	accessMap := AccessMap{
		"secret/data/test": &AccessInfo{
			Path:            "secret/data/test",
			LastAccessTime:  yesterday,
			FirstAccessTime: yesterday,
			AccessCount:     5,
			DaysSinceAccess: 1,
			UniqueClients:   2,
			SourceIPs:       []string{"127.0.0.1", "192.168.1.1"},
		},
	}

	analyzer := NewAnalyzer(accessMap)

	// Test existing path
	lastAccess, count, found := analyzer.GetLastAccess("secret/data/test")
	if !found {
		t.Error("Expected to find secret/data/test")
	}
	if count != 5 {
		t.Errorf("Expected access count 5, got %d", count)
	}
	if !lastAccess.Equal(yesterday) {
		t.Errorf("Expected last access %v, got %v", yesterday, lastAccess)
	}

	// Test non-existing path
	_, _, found = analyzer.GetLastAccess("secret/data/missing")
	if found {
		t.Error("Expected not to find secret/data/missing")
	}
}

func TestAnalyzer_IsStale(t *testing.T) {
	now := time.Now()
	old := now.AddDate(0, 0, -100)

	accessMap := AccessMap{
		"secret/data/active": &AccessInfo{
			Path:            "secret/data/active",
			LastAccessTime:  now,
			DaysSinceAccess: 0,
		},
		"secret/data/stale": &AccessInfo{
			Path:            "secret/data/stale",
			LastAccessTime:  old,
			DaysSinceAccess: 100,
		},
	}

	analyzer := NewAnalyzer(accessMap)

	// Test active secret
	isStale, days := analyzer.IsStale("secret/data/active", 90)
	if isStale {
		t.Error("Expected secret/data/active to not be stale")
	}
	if days != 0 {
		t.Errorf("Expected 0 days since access, got %d", days)
	}

	// Test stale secret
	isStale, days = analyzer.IsStale("secret/data/stale", 90)
	if !isStale {
		t.Error("Expected secret/data/stale to be stale")
	}
	if days != 100 {
		t.Errorf("Expected 100 days since access, got %d", days)
	}

	// Test missing secret
	isStale, days = analyzer.IsStale("secret/data/missing", 90)
	if !isStale {
		t.Error("Expected missing secret to be considered stale")
	}
	if days != -1 {
		t.Errorf("Expected -1 days for missing secret, got %d", days)
	}
}
