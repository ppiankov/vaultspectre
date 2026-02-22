package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestSARIFReporter_Generate(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewSARIFReporter(&buf)

	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config:    Config{VaultAddr: "https://vault.example.com", RepoPath: "."},
		Summary:   analyzer.Summary{TotalReferences: 4},
		References: []scanner.Reference{
			{Path: "secret/data/prod/api", File: "deploy.yml", Line: 42, Status: "ok"},
			{Path: "secret/data/prod/missing", File: "app.yml", Line: 10, Status: "missing"},
			{Path: "secret/data/prod/denied", File: "roles/db.yml", Line: 5, Status: "access_denied"},
			{Path: "secret/data/prod/bad", File: "main.go", Line: 88, Status: "invalid"},
		},
	}

	if err := reporter.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Parse output as JSON
	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Check schema and version
	if sarif.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", sarif.Version)
	}
	if sarif.Schema == "" {
		t.Error("$schema should not be empty")
	}

	// Check runs
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]

	// Check tool
	if run.Tool.Driver.Name != "vaultspectre" {
		t.Errorf("tool name = %q, want vaultspectre", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.3.0" {
		t.Errorf("tool version = %q, want 0.3.0", run.Tool.Driver.Version)
	}

	// Check rules
	if len(run.Tool.Driver.Rules) != 5 {
		t.Errorf("expected 5 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Should have 3 results (ok is skipped)
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results (ok skipped), got %d", len(run.Results))
	}

	// Check missing result
	found := false
	for _, r := range run.Results {
		if r.RuleID == "vaultspectre/MISSING_SECRET" {
			found = true
			if r.Level != "error" {
				t.Errorf("MISSING_SECRET level = %q, want error", r.Level)
			}
			if len(r.Locations) != 1 {
				t.Fatalf("expected 1 location, got %d", len(r.Locations))
			}
			if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "app.yml" {
				t.Errorf("location URI = %q, want app.yml", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
			}
			if r.Locations[0].PhysicalLocation.Region.StartLine != 10 {
				t.Errorf("startLine = %d, want 10", r.Locations[0].PhysicalLocation.Region.StartLine)
			}
		}
	}
	if !found {
		t.Error("missing MISSING_SECRET result")
	}
}

func TestSARIFReporter_StaleSecrets(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewSARIFReporter(&buf)

	data := Data{
		Tool:    "vaultspectre",
		Version: "0.3.0",
		References: []scanner.Reference{
			{
				Path:         "secret/data/old/key",
				File:         "deploy.yml",
				Line:         20,
				Status:       "ok",
				IsStale:      true,
				LastAccessed: "2025-01-01T00:00:00Z (modified, 417 days ago)",
			},
		},
	}

	if err := reporter.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Stale secret should appear as a STALE_SECRET result
	if len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result for stale secret, got %d", len(sarif.Runs[0].Results))
	}
	r := sarif.Runs[0].Results[0]
	if r.RuleID != "vaultspectre/STALE_SECRET" {
		t.Errorf("ruleId = %q, want vaultspectre/STALE_SECRET", r.RuleID)
	}
	if r.Level != "warning" {
		t.Errorf("level = %q, want warning", r.Level)
	}
}

func TestSARIFReporter_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewSARIFReporter(&buf)

	data := Data{
		Tool:       "vaultspectre",
		Version:    "0.3.0",
		References: []scanner.Reference{},
	}

	if err := reporter.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if sarif.Runs[0].Results != nil {
		t.Errorf("expected nil results for empty scan, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSARIFReporter_ErrorWithMessage(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewSARIFReporter(&buf)

	data := Data{
		Tool:    "vaultspectre",
		Version: "0.3.0",
		References: []scanner.Reference{
			{Path: "secret/data/broken", File: "cfg.yml", Line: 3, Status: "error", ErrorMsg: "connection timeout"},
		},
	}

	if err := reporter.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(sarif.Runs[0].Results))
	}
	r := sarif.Runs[0].Results[0]
	if r.RuleID != "vaultspectre/ERROR" {
		t.Errorf("ruleId = %q, want vaultspectre/ERROR", r.RuleID)
	}
	if r.Message.Text != "Error validating secret/data/broken: connection timeout" {
		t.Errorf("message = %q", r.Message.Text)
	}
}

func TestStatusToRuleID(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"missing", "vaultspectre/MISSING_SECRET"},
		{"access_denied", "vaultspectre/ACCESS_DENIED"},
		{"invalid", "vaultspectre/INVALID_PATH"},
		{"error", "vaultspectre/ERROR"},
		{"ok", ""},
		{"dynamic", ""},
		{"needs_resolution", ""},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := statusToRuleID(tt.status)
			if got != tt.want {
				t.Errorf("statusToRuleID(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestStatusToLevel(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"missing", "error"},
		{"invalid", "error"},
		{"access_denied", "warning"},
		{"error", "warning"},
		{"ok", "note"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := statusToLevel(tt.status)
			if got != tt.want {
				t.Errorf("statusToLevel(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestBuildMessage(t *testing.T) {
	tests := []struct {
		status, path, errMsg, want string
	}{
		{"missing", "secret/data/x", "", "Secret path secret/data/x is referenced in code but does not exist in Vault"},
		{"access_denied", "secret/data/y", "", "Token lacks permission to read secret/data/y"},
		{"invalid", "bad//path", "", "Secret path bad//path is malformed or structurally invalid"},
		{"error", "secret/data/z", "timeout", "Error validating secret/data/z: timeout"},
		{"error", "secret/data/z", "", "Error validating secret/data/z"},
		{"unknown", "p", "", "Issue with p"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := buildMessage(tt.status, tt.path, tt.errMsg)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
