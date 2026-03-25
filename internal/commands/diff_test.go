package commands

import (
	"testing"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/report"
)

func TestComputeDiff(t *testing.T) {
	old := &report.Data{
		Secrets: map[string]*analyzer.SecretInfo{
			"kv/app/db":    {Path: "kv/app/db", Status: "ok"},
			"kv/app/cache": {Path: "kv/app/cache", Status: "ok"},
			"kv/app/old":   {Path: "kv/app/old", Status: "missing"},
		},
	}

	new := &report.Data{
		Secrets: map[string]*analyzer.SecretInfo{
			"kv/app/db":    {Path: "kv/app/db", Status: "missing"}, // Changed: ok → missing
			"kv/app/cache": {Path: "kv/app/cache", Status: "ok"},   // Unchanged
			"kv/app/new":   {Path: "kv/app/new", Status: "ok"},     // Added
			// kv/app/old removed
		},
	}

	result := computeDiff(old, new)

	if result.Summary.TotalAdded != 1 {
		t.Errorf("added = %d, want 1", result.Summary.TotalAdded)
	}
	if result.Summary.TotalRemoved != 1 {
		t.Errorf("removed = %d, want 1", result.Summary.TotalRemoved)
	}
	if result.Summary.TotalChanged != 1 {
		t.Errorf("changed = %d, want 1", result.Summary.TotalChanged)
	}

	// Verify added
	if len(result.Added) != 1 || result.Added[0].Path != "kv/app/new" {
		t.Errorf("added[0].Path = %q, want kv/app/new", result.Added[0].Path)
	}

	// Verify removed
	if len(result.Removed) != 1 || result.Removed[0].Path != "kv/app/old" {
		t.Errorf("removed[0].Path = %q, want kv/app/old", result.Removed[0].Path)
	}

	// Verify changed
	if len(result.Changed) != 1 || result.Changed[0].Path != "kv/app/db" {
		t.Errorf("changed[0].Path = %q, want kv/app/db", result.Changed[0].Path)
	}
	if result.Changed[0].OldStatus != "ok" || result.Changed[0].NewStatus != "missing" {
		t.Errorf("changed status = %s→%s, want ok→missing", result.Changed[0].OldStatus, result.Changed[0].NewStatus)
	}
}

func TestComputeDiffNoDifferences(t *testing.T) {
	data := &report.Data{
		Secrets: map[string]*analyzer.SecretInfo{
			"kv/app/db": {Path: "kv/app/db", Status: "ok"},
		},
	}

	result := computeDiff(data, data)

	if result.Summary.TotalAdded != 0 || result.Summary.TotalRemoved != 0 || result.Summary.TotalChanged != 0 {
		t.Errorf("expected no differences, got added=%d removed=%d changed=%d",
			result.Summary.TotalAdded, result.Summary.TotalRemoved, result.Summary.TotalChanged)
	}
}

func TestHasWorsenedFindings(t *testing.T) {
	// ok → missing is worsened
	worsened := []DiffFinding{{OldStatus: "ok", NewStatus: "missing"}}
	if !hasWorsenedFindings(worsened) {
		t.Error("ok→missing should be worsened")
	}

	// missing → ok is improved
	improved := []DiffFinding{{OldStatus: "missing", NewStatus: "ok"}}
	if hasWorsenedFindings(improved) {
		t.Error("missing→ok should not be worsened")
	}

	// ok → ok is unchanged
	unchanged := []DiffFinding{{OldStatus: "ok", NewStatus: "ok"}}
	if hasWorsenedFindings(unchanged) {
		t.Error("ok→ok should not be worsened")
	}
}
