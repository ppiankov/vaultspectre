package commands

import (
	"testing"
)

func TestComputeWatchDelta_NewFindings(t *testing.T) {
	prev := map[string]watchFinding{
		"secret/a|f1.yml": {Path: "secret/a", Status: "missing", File: "f1.yml"},
	}
	current := map[string]watchFinding{
		"secret/a|f1.yml": {Path: "secret/a", Status: "missing", File: "f1.yml"},
		"secret/b|f2.yml": {Path: "secret/b", Status: "missing", File: "f2.yml"},
	}

	delta := computeWatchDelta(prev, current, 2)

	if len(delta.New) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(delta.New))
	}
	if delta.New[0].Path != "secret/b" {
		t.Errorf("new finding path = %q, want secret/b", delta.New[0].Path)
	}
	if len(delta.Resolved) != 0 {
		t.Errorf("expected 0 resolved, got %d", len(delta.Resolved))
	}
	if delta.Total != 2 {
		t.Errorf("total = %d, want 2", delta.Total)
	}
}

func TestComputeWatchDelta_ResolvedFindings(t *testing.T) {
	prev := map[string]watchFinding{
		"secret/a|f1.yml": {Path: "secret/a", Status: "missing", File: "f1.yml"},
		"secret/b|f2.yml": {Path: "secret/b", Status: "error", File: "f2.yml"},
	}
	current := map[string]watchFinding{
		"secret/a|f1.yml": {Path: "secret/a", Status: "missing", File: "f1.yml"},
	}

	delta := computeWatchDelta(prev, current, 3)

	if len(delta.New) != 0 {
		t.Errorf("expected 0 new, got %d", len(delta.New))
	}
	if len(delta.Resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(delta.Resolved))
	}
	if delta.Resolved[0].Path != "secret/b" {
		t.Errorf("resolved path = %q, want secret/b", delta.Resolved[0].Path)
	}
}

func TestComputeWatchDelta_NoChanges(t *testing.T) {
	prev := map[string]watchFinding{
		"secret/a|f.yml": {Path: "secret/a", Status: "missing", File: "f.yml"},
	}
	current := map[string]watchFinding{
		"secret/a|f.yml": {Path: "secret/a", Status: "missing", File: "f.yml"},
	}

	delta := computeWatchDelta(prev, current, 5)

	if len(delta.New) != 0 || len(delta.Resolved) != 0 {
		t.Errorf("expected no changes, got %d new, %d resolved", len(delta.New), len(delta.Resolved))
	}
}

func TestComputeWatchDelta_EmptyPrev(t *testing.T) {
	prev := map[string]watchFinding{}
	current := map[string]watchFinding{
		"secret/a|f.yml": {Path: "secret/a", Status: "missing", File: "f.yml"},
	}

	delta := computeWatchDelta(prev, current, 2)

	if len(delta.New) != 1 {
		t.Errorf("expected 1 new, got %d", len(delta.New))
	}
}

func TestComputeWatchDelta_AllResolved(t *testing.T) {
	prev := map[string]watchFinding{
		"secret/a|f.yml": {Path: "secret/a", Status: "missing", File: "f.yml"},
		"secret/b|g.yml": {Path: "secret/b", Status: "error", File: "g.yml"},
	}
	current := map[string]watchFinding{}

	delta := computeWatchDelta(prev, current, 4)

	if len(delta.Resolved) != 2 {
		t.Errorf("expected 2 resolved, got %d", len(delta.Resolved))
	}
	if delta.Total != 0 {
		t.Errorf("total = %d, want 0", delta.Total)
	}
}
