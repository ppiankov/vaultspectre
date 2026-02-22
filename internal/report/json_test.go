package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestJSONReporter_Generate(t *testing.T) {
	tests := []struct {
		name    string
		data    Data
		wantErr bool
	}{
		{
			name: "valid report with all fields",
			data: Data{
				Tool:      "vaultspectre",
				Version:   "0.3.0",
				Timestamp: time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC),
				Config: Config{
					VaultAddr:          "https://vault.example.com",
					RepoPath:           "/opt/ansible",
					StaleThresholdDays: 90,
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
						References: []scanner.Reference{
							{Path: "secret/data/db/pass", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty secrets map",
			data: Data{
				Tool:      "vaultspectre",
				Version:   "0.3.0",
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Config: Config{
					VaultAddr: "https://vault.example.com",
					RepoPath:  "/opt/ansible",
				},
				Summary: analyzer.Summary{
					HealthScore: "unknown",
				},
				Secrets: map[string]*analyzer.SecretInfo{},
			},
			wantErr: false,
		},
		{
			name: "minimal data",
			data: Data{
				Tool:    "vaultspectre",
				Version: "0.1.0",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			r := NewJSONReporter(&buf)

			err := r.Generate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if !json.Valid(buf.Bytes()) {
				t.Fatalf("output is not valid JSON:\n%s", buf.String())
			}
		})
	}
}

func TestJSONReporter_RoundTrip(t *testing.T) {
	original := Data{
		Tool:      "vaultspectre",
		Version:   "0.3.0",
		Timestamp: time.Date(2026, 2, 22, 15, 30, 0, 0, time.UTC),
		Config: Config{
			VaultAddr:          "https://vault.prod.internal",
			RepoPath:           "/srv/ansible-configs",
			StaleThresholdDays: 60,
			SummaryOnly:        true,
		},
		Summary: analyzer.Summary{
			TotalReferences:       5,
			StatusOK:              3,
			StatusMissing:         1,
			StatusNeedsResolution: 1,
			StaleSecrets:          1,
			HealthScore:           "warning",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/db/password": {
				Path:         "secret/data/db/password",
				Status:       "ok",
				IsStale:      true,
				LastAccessed: "2025-06-15T10:00:00Z",
				References: []scanner.Reference{
					{
						Path:         "secret/data/db/password",
						ResolvedPath: "secret/data/db/password",
						File:         "roles/db/tasks/main.yml",
						Line:         42,
						Type:         "ansible_lookup",
						Status:       "ok",
						IsStale:      true,
						LastAccessed: "2025-06-15T10:00:00Z",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	r := NewJSONReporter(&buf)
	if err := r.Generate(original); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var decoded Data
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if decoded.Tool != original.Tool {
		t.Errorf("Tool = %q, want %q", decoded.Tool, original.Tool)
	}
	if decoded.Version != original.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, original.Version)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.Summary.HealthScore != original.Summary.HealthScore {
		t.Errorf("Summary.HealthScore = %q, want %q", decoded.Summary.HealthScore, original.Summary.HealthScore)
	}
	if decoded.Summary.StaleSecrets != original.Summary.StaleSecrets {
		t.Errorf("Summary.StaleSecrets = %d, want %d", decoded.Summary.StaleSecrets, original.Summary.StaleSecrets)
	}
}

func TestJSONReporter_SpectreHubContract(t *testing.T) {
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
			StatusOK:        1,
			HealthScore:     "excellent",
		},
		Secrets: map[string]*analyzer.SecretInfo{
			"secret/data/test": {
				Path:   "secret/data/test",
				Status: "ok",
				References: []scanner.Reference{
					{Path: "secret/data/test", File: "main.yml", Line: 1, Type: "ansible_lookup", Status: "ok"},
				},
			},
		},
	}

	var buf bytes.Buffer
	r := NewJSONReporter(&buf)
	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	requiredFields := []string{"tool", "version", "timestamp", "config", "summary", "secrets"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("SpectreHub contract: missing required top-level field %q", field)
		}
	}

	var tool string
	if err := json.Unmarshal(raw["tool"], &tool); err != nil {
		t.Fatalf("failed to unmarshal tool: %v", err)
	}
	if tool != "vaultspectre" {
		t.Errorf("tool = %q, want %q", tool, "vaultspectre")
	}

	var ts string
	if err := json.Unmarshal(raw["timestamp"], &ts); err != nil {
		t.Fatalf("failed to unmarshal timestamp: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", ts, err)
	}
}
