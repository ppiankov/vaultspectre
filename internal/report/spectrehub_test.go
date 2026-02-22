package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestSpectreHubReporter_Generate(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
		},
		Summary: analyzer.Summary{
			TotalReferences:    5,
			StatusOK:           2,
			StatusMissing:      1,
			StatusAccessDenied: 1,
			StatusInvalid:      1,
			HealthScore:        "warning",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/db/pass": {
				Path:   "secret/data/db/pass",
				Status: "ok",
				References: []scanner.Reference{
					{Path: "secret/data/db/pass", File: "deploy.yml", Line: 10, Status: "ok"},
				},
			},
			"secret/data/api/key": {
				Path:   "secret/data/api/key",
				Status: "missing",
				References: []scanner.Reference{
					{Path: "secret/data/api/key", File: "tasks.yml", Line: 5, Status: "missing"},
				},
			},
			"secret/data/tls/cert": {
				Path:   "secret/data/tls/cert",
				Status: "access_denied",
				References: []scanner.Reference{
					{Path: "secret/data/tls/cert", File: "tls.yml", Line: 3, Status: "access_denied"},
				},
			},
			"secret/data/bad/path": {
				Path:   "secret/data/bad/path",
				Status: "invalid",
				References: []scanner.Reference{
					{Path: "secret/data/bad/path", File: "broken.yml", Line: 1, Status: "invalid"},
				},
			},
			"secret/data/stale/old": {
				Path:    "secret/data/stale/old",
				Status:  "ok",
				IsStale: true,
				References: []scanner.Reference{
					{Path: "secret/data/stale/old", File: "old.yml", Line: 1, Status: "ok"},
				},
			},
		},
	}

	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Schema
	if envelope.Schema != "spectre/v1" {
		t.Errorf("schema = %q, want spectre/v1", envelope.Schema)
	}

	// Tool metadata
	if envelope.Tool != "vaultspectre" {
		t.Errorf("tool = %q, want vaultspectre", envelope.Tool)
	}
	if envelope.Version != "0.3.0" {
		t.Errorf("version = %q, want 0.3.0", envelope.Version)
	}
	if envelope.Timestamp != "2026-02-22T12:00:00Z" {
		t.Errorf("timestamp = %q, want 2026-02-22T12:00:00Z", envelope.Timestamp)
	}

	// Target
	if envelope.Target.Type != "vault" {
		t.Errorf("target.type = %q, want vault", envelope.Target.Type)
	}
	if envelope.Target.URIHash == "" {
		t.Error("target.uri_hash is empty")
	}

	// Findings: should have 4 (missing=1, access_denied=1, invalid=1, stale=1), skip 2 OK
	if len(envelope.Findings) != 4 {
		t.Errorf("findings count = %d, want 4", len(envelope.Findings))
	}

	// Summary counts
	if envelope.Summary.Total != 4 {
		t.Errorf("summary.total = %d, want 4", envelope.Summary.Total)
	}
	if envelope.Summary.High != 1 {
		t.Errorf("summary.high = %d, want 1", envelope.Summary.High)
	}
	if envelope.Summary.Medium != 2 {
		t.Errorf("summary.medium = %d, want 2 (access_denied + invalid)", envelope.Summary.Medium)
	}
	if envelope.Summary.Low != 1 {
		t.Errorf("summary.low = %d, want 1 (stale)", envelope.Summary.Low)
	}

	// Verify finding IDs exist
	findingIDs := make(map[string]bool)
	for _, f := range envelope.Findings {
		findingIDs[f.ID] = true
	}
	for _, expected := range []string{"MISSING_SECRET", "ACCESS_DENIED", "INVALID_PATH", "STALE_SECRET"} {
		if !findingIDs[expected] {
			t.Errorf("missing finding ID %q", expected)
		}
	}
}

func TestSpectreHubReporter_Generate_Empty(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
		},
		Summary: analyzer.Summary{
			HealthScore: "unknown",
		},
		Secrets: map[string]*analyzer.SecretInfo{},
	}

	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if envelope.Schema != "spectre/v1" {
		t.Errorf("schema = %q, want spectre/v1", envelope.Schema)
	}
	if len(envelope.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(envelope.Findings))
	}
	if envelope.Summary.Total != 0 {
		t.Errorf("summary.total = %d, want 0", envelope.Summary.Total)
	}
}

func TestSpectreHubReporter_Generate_AllOK(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
		},
		Summary: analyzer.Summary{
			TotalReferences: 3,
			StatusOK:        3,
			HealthScore:     "excellent",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/a": {Path: "secret/data/a", Status: "ok"},
			"secret/data/b": {Path: "secret/data/b", Status: "ok"},
			"secret/data/c": {Path: "secret/data/c", Status: "ok"},
		},
	}

	var buf bytes.Buffer
	r := NewSpectreHubReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var envelope spectreEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if len(envelope.Findings) != 0 {
		t.Errorf("findings count = %d, want 0 (all OK should be skipped)", len(envelope.Findings))
	}
}

func TestMapStatusToFinding(t *testing.T) {
	tests := []struct {
		status   string
		wantSev  string
		wantID   string
		wantSkip bool
	}{
		{"missing", "high", "MISSING_SECRET", false},
		{"access_denied", "medium", "ACCESS_DENIED", false},
		{"invalid", "medium", "INVALID_PATH", false},
		{"error", "medium", "ERROR", false},
		{"dynamic", "info", "DYNAMIC_PATH", false},
		{"ok", "", "", true},
		{"needs_resolution", "", "", true},
		{"skipped_policy", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			sev, id := mapStatusToFinding(tt.status)
			if tt.wantSkip {
				if sev != "" || id != "" {
					t.Errorf("status %q should be skipped, got severity=%q id=%q", tt.status, sev, id)
				}
				return
			}
			if sev != tt.wantSev {
				t.Errorf("severity = %q, want %q", sev, tt.wantSev)
			}
			if id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
		})
	}
}

func TestFindingMessage(t *testing.T) {
	tests := []struct {
		id   string
		path string
		want string
	}{
		{"MISSING_SECRET", "secret/data/x", "Secret referenced in code but not found in Vault: secret/data/x"},
		{"ACCESS_DENIED", "secret/data/y", "Secret exists but current token lacks permission: secret/data/y"},
		{"STALE_SECRET", "secret/data/z", "Secret has not been accessed recently: secret/data/z"},
		{"INVALID_PATH", "bad", "Malformed or invalid Vault path: bad"},
		{"DYNAMIC_PATH", "secret/{{ x }}", "Dynamic path cannot be validated statically: secret/{{ x }}"},
		{"ERROR", "secret/err", "Error validating secret path: secret/err"},
		{"UNKNOWN", "path", "path"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := findingMessage(tt.id, tt.path)
			if got != tt.want {
				t.Errorf("findingMessage(%q, %q) = %q, want %q", tt.id, tt.path, got, tt.want)
			}
		})
	}
}
