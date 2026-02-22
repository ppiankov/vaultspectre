package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestTextReporter_Generate_FullReport(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr:          "https://vault.example.com",
			RepoPath:           "/opt/ansible",
			StaleThresholdDays: 90,
		},
		Summary: analyzer.Summary{
			TotalReferences:       6,
			StatusOK:              2,
			StatusMissing:         1,
			StatusAccessDenied:    1,
			StatusNeedsResolution: 1,
			StatusSkippedPolicy:   1,
			StaleSecrets:          1,
			HealthScore:           "warning",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/db/pass": {
				Path:   "secret/data/db/pass",
				Status: "ok",
				References: []scanner.Reference{
					{Path: "secret/data/db/pass", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
				},
			},
			"secret/data/api/key": {
				Path:   "secret/data/api/key",
				Status: "missing",
				References: []scanner.Reference{
					{Path: "secret/data/api/key", File: "tasks.yml", Line: 5, Type: "ansible_lookup", Status: "missing"},
				},
			},
			"secret/data/tls/cert": {
				Path:   "secret/data/tls/cert",
				Status: "access_denied",
				References: []scanner.Reference{
					{Path: "secret/data/tls/cert", File: "tls.yml", Line: 3, Type: "yaml_config", Status: "access_denied"},
				},
			},
			"secret/data/stale/old": {
				Path:         "secret/data/stale/old",
				Status:       "ok",
				IsStale:      true,
				LastAccessed: "2025-06-01T00:00:00Z (modified, 266 days ago)",
				References: []scanner.Reference{
					{Path: "secret/data/stale/old", File: "old.yml", Line: 1, Type: "yaml_config", Status: "ok"},
				},
			},
		},
		References: []scanner.Reference{
			{Path: "secret/data/db/pass", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
			{Path: "secret/data/api/key", File: "tasks.yml", Line: 5, Type: "ansible_lookup", Status: "missing"},
			{Path: "secret/data/tls/cert", File: "tls.yml", Line: 3, Type: "yaml_config", Status: "access_denied"},
			{Path: "secret/data/stale/old", File: "old.yml", Line: 1, Type: "yaml_config", Status: "ok"},
			{Path: "secret/data/{{ env }}/db", File: "vars.yml", Line: 8, Type: "ansible_lookup", Status: "needs_resolution", Variables: []string{"env"}},
			{Path: "secret/data/*/all", File: "policy.yml", Line: 2, Type: "yaml_config", Status: "skipped_policy"},
		},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Header
	if !strings.Contains(output, "VaultSpectre Report") {
		t.Error("missing report header")
	}

	// Configuration
	if !strings.Contains(output, "vault.example.com") {
		t.Error("missing vault address in config")
	}
	if !strings.Contains(output, "/opt/ansible") {
		t.Error("missing repo path in config")
	}

	// Summary
	if !strings.Contains(output, "Total References:     6") {
		t.Error("missing total references")
	}
	if !strings.Contains(output, "OK:") {
		t.Error("missing OK count")
	}
	if !strings.Contains(output, "Missing:") {
		t.Error("missing Missing count")
	}
	if !strings.Contains(output, "Access Denied:") {
		t.Error("missing Access Denied count")
	}

	// Health score
	if !strings.Contains(output, "WARNING") {
		t.Error("missing health score")
	}

	// Skipped note
	if !strings.Contains(output, "paths skipped") {
		t.Error("missing skipped paths note")
	}

	// Missing section
	if !strings.Contains(output, "Missing Secrets (1)") {
		t.Error("missing 'Missing Secrets' section")
	}
	if !strings.Contains(output, "secret/data/api/key") {
		t.Error("missing path in missing section")
	}

	// Stale section
	if !strings.Contains(output, "Stale Secrets (1)") {
		t.Error("missing 'Stale Secrets' section")
	}

	// Unresolved section
	if !strings.Contains(output, "Unresolved Paths (1)") {
		t.Error("missing 'Unresolved Paths' section")
	}
	if !strings.Contains(output, "--var env=<value>") {
		t.Error("missing variable resolution hint")
	}

	// Access denied section
	if !strings.Contains(output, "Access Denied (1)") {
		t.Error("missing 'Access Denied' section")
	}
}

func TestTextReporter_Generate_SummaryOnly(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr:   "https://vault.example.com",
			RepoPath:    "/opt/ansible",
			SummaryOnly: true,
		},
		Summary: analyzer.Summary{
			TotalReferences: 5,
			StatusOK:        3,
			StatusMissing:   2,
			HealthScore:     "warning",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/missing/one": {
				Path:   "secret/data/missing/one",
				Status: "missing",
				References: []scanner.Reference{
					{Path: "secret/data/missing/one", File: "a.yml", Line: 1, Type: "yaml_config", Status: "missing"},
				},
			},
		},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	// Should have summary
	if !strings.Contains(output, "Total References:     5") {
		t.Error("missing total references in summary-only mode")
	}

	// Should NOT have detailed sections
	if strings.Contains(output, "Missing Secrets") {
		t.Error("should not show detailed sections in summary-only mode")
	}
}

func TestTextReporter_Generate_GroupByRole(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr:   "https://vault.example.com",
			RepoPath:    "/opt/ansible",
			GroupByRole: true,
		},
		Summary: analyzer.Summary{
			TotalReferences: 3,
			StatusOK:        2,
			StatusMissing:   1,
			HealthScore:     "warning",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/db/pass": {
				Path:   "secret/data/db/pass",
				Status: "ok",
			},
			"secret/data/api/key": {
				Path:   "secret/data/api/key",
				Status: "missing",
			},
		},
		References: []scanner.Reference{
			{Path: "secret/data/db/pass", ResolvedPath: "secret/data/db/pass", File: "roles/database/tasks/main.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
			{Path: "secret/data/api/key", ResolvedPath: "secret/data/api/key", File: "roles/api/tasks/deploy.yml", Line: 5, Type: "ansible_lookup", Status: "missing"},
			{Path: "secret/data/db/pass", ResolvedPath: "secret/data/db/pass", File: "deploy.yml", Line: 20, Type: "ansible_lookup", Status: "ok"},
		},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Secrets Grouped by Role/Component") {
		t.Error("missing group-by-role header")
	}
	if !strings.Contains(output, "Role: database") {
		t.Error("missing database role")
	}
	if !strings.Contains(output, "Role: api") {
		t.Error("missing api role")
	}
	if !strings.Contains(output, "Role: other") {
		t.Error("missing other role for non-role files")
	}
}

func TestTextReporter_Generate_Empty(t *testing.T) {
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
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "UNKNOWN") {
		t.Error("missing unknown health score")
	}
}

func TestTextReporter_Generate_Verbose(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
			Verbose:   true,
		},
		Summary: analyzer.Summary{
			TotalReferences: 1,
			StatusMissing:   1,
			HealthScore:     "severe",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/prod/db": {
				Path:   "secret/data/prod/db",
				Status: "missing",
				References: []scanner.Reference{
					{Path: "secret/data/{{ env }}/db", ResolvedPath: "secret/data/prod/db", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "missing"},
				},
			},
		},
		References: []scanner.Reference{
			{Path: "secret/data/{{ env }}/db", ResolvedPath: "secret/data/prod/db", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "missing"},
		},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Template:") {
		t.Error("missing template info in verbose mode")
	}
	if !strings.Contains(output, "Resolved:") {
		t.Error("missing resolved info in verbose mode")
	}
}

func TestTextReporter_Generate_InvalidPaths(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
		},
		Summary: analyzer.Summary{
			TotalReferences: 1,
			StatusInvalid:   1,
			HealthScore:     "severe",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"bad/path": {
				Path:     "bad/path",
				Status:   "invalid",
				ErrorMsg: "malformed vault path",
				References: []scanner.Reference{
					{Path: "bad/path", File: "broken.yml", Line: 3, Type: "yaml_config", Status: "invalid"},
				},
			},
		},
		References: []scanner.Reference{
			{Path: "bad/path", File: "broken.yml", Line: 3, Type: "yaml_config", Status: "invalid"},
		},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Invalid Paths (1)") {
		t.Error("missing 'Invalid Paths' section")
	}
	if !strings.Contains(output, "malformed vault path") {
		t.Error("missing error message")
	}
}

func TestTextReporter_Generate_ErrorSecrets(t *testing.T) {
	data := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
		Config: Config{
			VaultAddr: "https://vault.example.com",
			RepoPath:  "/opt/ansible",
		},
		Summary: analyzer.Summary{
			TotalReferences: 1,
			StatusError:     1,
			HealthScore:     "severe",
		},
		Secrets: map[string]*analyzer.SecretInfo{},
	}

	var buf bytes.Buffer
	r := NewTextReporter(&buf)
	err := r.Generate(data)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Errors:") {
		t.Error("missing Errors count in summary")
	}
}

func TestFormatHealthScore(t *testing.T) {
	r := NewTextReporter(nil)

	tests := []struct {
		score string
		want  string
	}{
		{"excellent", "EXCELLENT"},
		{"good", "GOOD"},
		{"warning", "WARNING"},
		{"critical", "CRITICAL"},
		{"severe", "SEVERE"},
		{"unknown", "UNKNOWN"},
		{"custom", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.score, func(t *testing.T) {
			got := r.formatHealthScore(tt.score)
			if !strings.Contains(got, tt.want) {
				t.Errorf("formatHealthScore(%q) = %q, want to contain %q", tt.score, got, tt.want)
			}
		})
	}
}
