package analyzer

import (
	"testing"

	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func ref(path, status string, stale bool) scanner.Reference {
	return scanner.Reference{
		Path:    path,
		File:    "deploy.yml",
		Line:    1,
		Type:    "ansible_lookup",
		Status:  status,
		IsStale: stale,
	}
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name        string
		refs        []scanner.Reference
		wantHealth  string
		wantSummary Summary
		wantSecrets int
	}{
		{
			name:       "empty references yields unknown health",
			refs:       nil,
			wantHealth: "unknown",
			wantSummary: Summary{
				TotalReferences: 0,
				HealthScore:     "unknown",
			},
			wantSecrets: 0,
		},
		{
			name: "all ok yields excellent",
			refs: []scanner.Reference{
				ref("secret/data/db/password", "ok", false),
				ref("secret/data/api/token", "ok", false),
				ref("secret/data/tls/cert", "ok", false),
			},
			wantHealth: "excellent",
			wantSummary: Summary{
				TotalReferences: 3,
				StatusOK:        3,
				HealthScore:     "excellent",
			},
			wantSecrets: 3,
		},
		{
			name: "all statuses counted correctly",
			refs: []scanner.Reference{
				ref("secret/data/a", "ok", false),
				ref("secret/data/b", "missing", false),
				ref("secret/data/c", "access_denied", false),
				ref("secret/data/d", "invalid", false),
				ref("secret/data/e", "dynamic", false),
				ref("secret/data/f", "error", false),
				ref("secret/data/g", "needs_resolution", false),
				ref("secret/data/h", "skipped_policy", false),
			},
			wantHealth: "severe",
			wantSummary: Summary{
				TotalReferences:       8,
				StatusOK:              1,
				StatusMissing:         1,
				StatusAccessDenied:    1,
				StatusInvalid:         1,
				StatusDynamic:         1,
				StatusError:           1,
				StatusNeedsResolution: 1,
				StatusSkippedPolicy:   1,
				HealthScore:           "severe",
			},
			wantSecrets: 8,
		},
		{
			name: "needs_resolution and skipped_policy do not affect health score",
			refs: []scanner.Reference{
				ref("secret/data/a", "ok", false),
				ref("secret/data/b", "needs_resolution", false),
				ref("secret/data/c", "skipped_policy", false),
				ref("secret/data/d", "needs_resolution", false),
				ref("secret/data/e", "skipped_policy", false),
			},
			wantHealth: "excellent",
			wantSummary: Summary{
				TotalReferences:       5,
				StatusOK:              1,
				StatusNeedsResolution: 2,
				StatusSkippedPolicy:   2,
				HealthScore:           "excellent",
			},
			wantSecrets: 5,
		},
		{
			name: "only needs_resolution and skipped_policy yields unknown",
			refs: []scanner.Reference{
				ref("secret/data/a", "needs_resolution", false),
				ref("secret/data/b", "skipped_policy", false),
			},
			wantHealth: "unknown",
			wantSummary: Summary{
				TotalReferences:       2,
				StatusNeedsResolution: 1,
				StatusSkippedPolicy:   1,
				HealthScore:           "unknown",
			},
			wantSecrets: 2,
		},
		{
			name: "multiple references to same path grouped correctly",
			refs: []scanner.Reference{
				{Path: "secret/data/db/pass", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
				{Path: "secret/data/db/pass", File: "tasks.yml", Line: 5, Type: "ansible_lookup", Status: "ok"},
				{Path: "secret/data/db/pass", File: "vars.yml", Line: 20, Type: "ansible_lookup", Status: "ok"},
			},
			wantHealth: "excellent",
			wantSummary: Summary{
				TotalReferences: 3,
				StatusOK:        3,
				HealthScore:     "excellent",
			},
			wantSecrets: 1,
		},
		{
			name: "severe health score bracket",
			refs: []scanner.Reference{
				ref("secret/data/a", "ok", false),
				ref("secret/data/b", "missing", false),
				ref("secret/data/c", "error", false),
			},
			wantHealth: "severe",
			wantSummary: Summary{
				TotalReferences: 3,
				StatusOK:        1,
				StatusMissing:   1,
				StatusError:     1,
				HealthScore:     "severe",
			},
			wantSecrets: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New(tt.refs)
			results := a.Analyze()

			if results.Summary.HealthScore != tt.wantHealth {
				t.Errorf("HealthScore = %q, want %q", results.Summary.HealthScore, tt.wantHealth)
			}
			if results.Summary.TotalReferences != tt.wantSummary.TotalReferences {
				t.Errorf("TotalReferences = %d, want %d", results.Summary.TotalReferences, tt.wantSummary.TotalReferences)
			}
			if results.Summary.StatusOK != tt.wantSummary.StatusOK {
				t.Errorf("StatusOK = %d, want %d", results.Summary.StatusOK, tt.wantSummary.StatusOK)
			}
			if results.Summary.StatusMissing != tt.wantSummary.StatusMissing {
				t.Errorf("StatusMissing = %d, want %d", results.Summary.StatusMissing, tt.wantSummary.StatusMissing)
			}
			if results.Summary.StatusAccessDenied != tt.wantSummary.StatusAccessDenied {
				t.Errorf("StatusAccessDenied = %d, want %d", results.Summary.StatusAccessDenied, tt.wantSummary.StatusAccessDenied)
			}
			if results.Summary.StatusInvalid != tt.wantSummary.StatusInvalid {
				t.Errorf("StatusInvalid = %d, want %d", results.Summary.StatusInvalid, tt.wantSummary.StatusInvalid)
			}
			if results.Summary.StatusDynamic != tt.wantSummary.StatusDynamic {
				t.Errorf("StatusDynamic = %d, want %d", results.Summary.StatusDynamic, tt.wantSummary.StatusDynamic)
			}
			if results.Summary.StatusError != tt.wantSummary.StatusError {
				t.Errorf("StatusError = %d, want %d", results.Summary.StatusError, tt.wantSummary.StatusError)
			}
			if results.Summary.StatusNeedsResolution != tt.wantSummary.StatusNeedsResolution {
				t.Errorf("StatusNeedsResolution = %d, want %d", results.Summary.StatusNeedsResolution, tt.wantSummary.StatusNeedsResolution)
			}
			if results.Summary.StatusSkippedPolicy != tt.wantSummary.StatusSkippedPolicy {
				t.Errorf("StatusSkippedPolicy = %d, want %d", results.Summary.StatusSkippedPolicy, tt.wantSummary.StatusSkippedPolicy)
			}
			if results.Summary.StaleSecrets != tt.wantSummary.StaleSecrets {
				t.Errorf("StaleSecrets = %d, want %d", results.Summary.StaleSecrets, tt.wantSummary.StaleSecrets)
			}
			if len(results.Secrets) != tt.wantSecrets {
				t.Errorf("len(Secrets) = %d, want %d", len(results.Secrets), tt.wantSecrets)
			}
		})
	}
}

func TestAnalyze_GroupingByPath(t *testing.T) {
	refs := []scanner.Reference{
		{Path: "secret/data/db/password", File: "deploy.yml", Line: 10, Type: "ansible_lookup", Status: "ok"},
		{Path: "secret/data/db/password", File: "tasks.yml", Line: 5, Type: "ansible_lookup", Status: "ok"},
		{Path: "secret/data/api/token", File: "deploy.yml", Line: 20, Type: "ansible_lookup", Status: "missing"},
	}

	a := New(refs)
	results := a.Analyze()

	if len(results.Secrets) != 2 {
		t.Fatalf("expected 2 unique paths, got %d", len(results.Secrets))
	}

	dbSecret := results.Secrets["secret/data/db/password"]
	if dbSecret == nil {
		t.Fatal("missing secret entry for secret/data/db/password")
	}
	if len(dbSecret.References) != 2 {
		t.Errorf("expected 2 references for db/password, got %d", len(dbSecret.References))
	}
	if dbSecret.Status != "ok" {
		t.Errorf("expected status ok for db/password, got %q", dbSecret.Status)
	}

	apiSecret := results.Secrets["secret/data/api/token"]
	if apiSecret == nil {
		t.Fatal("missing secret entry for secret/data/api/token")
	}
	if len(apiSecret.References) != 1 {
		t.Errorf("expected 1 reference for api/token, got %d", len(apiSecret.References))
	}
}

func TestAnalyze_SecretInfoFields(t *testing.T) {
	refs := []scanner.Reference{
		{
			Path:         "secret/data/stale/key",
			File:         "main.yml",
			Line:         42,
			Type:         "ansible_lookup",
			Status:       "ok",
			IsStale:      true,
			LastAccessed: "2024-01-01T00:00:00Z",
		},
		{
			Path:     "secret/data/broken/key",
			File:     "deploy.yml",
			Line:     99,
			Type:     "ansible_lookup",
			Status:   "error",
			ErrorMsg: "connection refused",
		},
	}

	a := New(refs)
	results := a.Analyze()

	stale := results.Secrets["secret/data/stale/key"]
	if stale == nil {
		t.Fatal("missing stale secret entry")
	}
	if !stale.IsStale {
		t.Error("expected IsStale=true")
	}
	if stale.LastAccessed != "2024-01-01T00:00:00Z" {
		t.Errorf("LastAccessed = %q, want 2024-01-01T00:00:00Z", stale.LastAccessed)
	}

	broken := results.Secrets["secret/data/broken/key"]
	if broken == nil {
		t.Fatal("missing broken secret entry")
	}
	if broken.ErrorMsg != "connection refused" {
		t.Errorf("ErrorMsg = %q, want %q", broken.ErrorMsg, "connection refused")
	}
}

func TestCalculateHealthScore(t *testing.T) {
	tests := []struct {
		name string
		s    Summary
		want string
	}{
		{
			name: "no validated paths",
			s:    Summary{},
			want: "unknown",
		},
		{
			name: "only skipped and unresolved",
			s: Summary{
				StatusNeedsResolution: 5,
				StatusSkippedPolicy:   3,
			},
			want: "unknown",
		},
		{
			name: "zero issues",
			s:    Summary{StatusOK: 10},
			want: "excellent",
		},
		{
			name: "only access_denied is not an issue",
			s:    Summary{StatusAccessDenied: 10},
			want: "excellent",
		},
		{
			name: "less than 5 percent issues",
			s:    Summary{StatusOK: 99, StatusMissing: 1},
			want: "good",
		},
		{
			name: "exactly 5 percent",
			s:    Summary{StatusOK: 19, StatusMissing: 1},
			want: "warning",
		},
		{
			name: "between 15 and 30 percent",
			s:    Summary{StatusOK: 4, StatusMissing: 1},
			want: "critical",
		},
		{
			name: "30 percent or more",
			s:    Summary{StatusOK: 2, StatusMissing: 1},
			want: "severe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateHealthScore(tt.s)
			if got != tt.want {
				t.Errorf("calculateHealthScore() = %q, want %q", got, tt.want)
			}
		})
	}
}
