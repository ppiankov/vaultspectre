package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestFingerprint(t *testing.T) {
	fp1 := Fingerprint("missing", "secret/data/prod/api")
	fp2 := Fingerprint("missing", "secret/data/prod/api")
	fp3 := Fingerprint("missing", "secret/data/prod/db")
	fp4 := Fingerprint("invalid", "secret/data/prod/api")

	if fp1 != fp2 {
		t.Error("same input should produce same fingerprint")
	}
	if fp1 == fp3 {
		t.Error("different paths should produce different fingerprints")
	}
	if fp1 == fp4 {
		t.Error("different statuses should produce different fingerprints")
	}
	if len(fp1) != 64 {
		t.Errorf("expected 64-char hex, got %d chars", len(fp1))
	}
}

func TestIsKnown(t *testing.T) {
	b := &Baseline{
		Fingerprints: []string{Fingerprint("missing", "secret/data/a")},
		lookup:       map[string]bool{Fingerprint("missing", "secret/data/a"): true},
	}

	if !b.IsKnown("missing", "secret/data/a") {
		t.Error("should be known")
	}
	if b.IsKnown("missing", "secret/data/b") {
		t.Error("should not be known")
	}
	if b.IsKnown("invalid", "secret/data/a") {
		t.Error("different status should not be known")
	}
}

func TestFilter(t *testing.T) {
	b := &Baseline{
		lookup: map[string]bool{
			Fingerprint("missing", "secret/data/known"): true,
		},
	}

	refs := []scanner.Reference{
		{Path: "secret/data/known", Status: "missing"},
		{Path: "secret/data/new", Status: "missing"},
		{Path: "secret/data/ok", Status: "ok"},
		{Path: "secret/data/denied", Status: "access_denied"},
	}

	filtered, suppressed := b.Filter(refs)
	if suppressed != 1 {
		t.Errorf("suppressed = %d, want 1", suppressed)
	}
	if len(filtered) != 3 {
		t.Errorf("filtered len = %d, want 3", len(filtered))
	}

	// Verify the known missing path was removed
	for _, ref := range filtered {
		if ref.Path == "secret/data/known" && ref.Status == "missing" {
			t.Error("known finding should have been filtered out")
		}
	}
}

func TestFilter_EmptyBaseline(t *testing.T) {
	b := &Baseline{lookup: make(map[string]bool)}

	refs := []scanner.Reference{
		{Path: "secret/data/a", Status: "missing"},
		{Path: "secret/data/b", Status: "invalid"},
	}

	filtered, suppressed := b.Filter(refs)
	if suppressed != 0 {
		t.Errorf("suppressed = %d, want 0", suppressed)
	}
	if len(filtered) != 2 {
		t.Errorf("filtered len = %d, want 2", len(filtered))
	}
}

func TestFromRefs(t *testing.T) {
	refs := []scanner.Reference{
		{Path: "secret/data/a", Status: "missing"},
		{Path: "secret/data/b", Status: "access_denied"},
		{Path: "secret/data/c", Status: "ok"},
		{Path: "secret/data/d", Status: "invalid"},
		{Path: "secret/data/a", Status: "missing"}, // duplicate
		{Path: "secret/data/e", Status: "pending_validation"},
	}

	b := FromRefs(refs, "0.3.0")

	if b.Version != "0.3.0" {
		t.Errorf("version = %q", b.Version)
	}
	// Should have 3 unique actionable fingerprints (missing a, access_denied b, invalid d)
	if len(b.Fingerprints) != 3 {
		t.Errorf("fingerprints = %d, want 3", len(b.Fingerprints))
	}
	if !b.IsKnown("missing", "secret/data/a") {
		t.Error("missing a should be known")
	}
	if !b.IsKnown("access_denied", "secret/data/b") {
		t.Error("access_denied b should be known")
	}
	if b.IsKnown("ok", "secret/data/c") {
		t.Error("ok status should not be in baseline")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	// Create and save
	original := FromRefs([]scanner.Reference{
		{Path: "secret/data/x", Status: "missing"},
		{Path: "secret/data/y", Status: "invalid"},
	}, "0.3.0")

	if err := original.Save(path); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.Version != "0.3.0" {
		t.Errorf("version = %q", loaded.Version)
	}
	if len(loaded.Fingerprints) != 2 {
		t.Errorf("fingerprints = %d, want 2", len(loaded.Fingerprints))
	}
	if !loaded.IsKnown("missing", "secret/data/x") {
		t.Error("should be known after load")
	}
}

func TestLoad_NonExistent(t *testing.T) {
	b, err := Load("/nonexistent/baseline.json")
	if err != nil {
		t.Fatalf("Load() should not error for nonexistent file: %v", err)
	}
	if len(b.Fingerprints) != 0 {
		t.Error("empty baseline should have no fingerprints")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestIsActionableStatus(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"missing", true},
		{"access_denied", true},
		{"invalid", true},
		{"error", true},
		{"ok", false},
		{"pending_validation", false},
		{"needs_resolution", false},
		{"skipped_policy", false},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			got := isActionableStatus(tt.status)
			if got != tt.want {
				t.Errorf("isActionableStatus(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}
