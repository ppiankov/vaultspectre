package policy

import (
	"testing"
)

func TestEvaluateMaxFindings(t *testing.T) {
	p := &Policy{
		MaxFindings: map[string]int{
			"missing": 0,
			"error":   5,
		},
	}

	// Passes: 0 missing, 3 errors
	result := p.Evaluate(ScanSummary{
		StatusCounts: map[string]int{"missing": 0, "error": 3},
	})
	if !result.Passed {
		t.Error("expected pass with 0 missing and 3 errors")
	}

	// Fails: 2 missing
	result = p.Evaluate(ScanSummary{
		StatusCounts: map[string]int{"missing": 2, "error": 1},
	})
	if result.Passed {
		t.Error("expected fail with 2 missing findings")
	}

	// Fails: 6 errors
	result = p.Evaluate(ScanSummary{
		StatusCounts: map[string]int{"missing": 0, "error": 6},
	})
	if result.Passed {
		t.Error("expected fail with 6 errors exceeding limit of 5")
	}
}

func TestEvaluateRequiredPathPrefixes(t *testing.T) {
	p := &Policy{
		RequiredPathPrefixes: []string{"kv/projects/", "kv/shared/"},
	}

	// Passes: all paths within required prefixes
	result := p.Evaluate(ScanSummary{
		Paths: []string{"kv/projects/ads/int/config", "kv/shared/global"},
	})
	if !result.Passed {
		t.Error("expected pass when all paths within required prefixes")
	}

	// Fails: path outside allowed prefixes
	result = p.Evaluate(ScanSummary{
		Paths: []string{"kv/projects/ads/config", "secret/rogue/path"},
	})
	if result.Passed {
		t.Error("expected fail when path outside required prefixes")
	}
}

func TestEvaluateForbiddenPathPrefixes(t *testing.T) {
	p := &Policy{
		ForbiddenPathPrefixes: []string{"kv/deprecated/", "kv/test/"},
	}

	// Passes: no forbidden paths
	result := p.Evaluate(ScanSummary{
		Paths: []string{"kv/projects/ads/config"},
	})
	if !result.Passed {
		t.Error("expected pass with no forbidden paths")
	}

	// Fails: forbidden path detected
	result = p.Evaluate(ScanSummary{
		Paths: []string{"kv/projects/ads/config", "kv/deprecated/old-service"},
	})
	if result.Passed {
		t.Error("expected fail with forbidden path")
	}
}

func TestEvaluateMaxStalePercent(t *testing.T) {
	maxStale := 10
	p := &Policy{
		MaxStalePercent: &maxStale,
	}

	// Passes: 5% stale
	result := p.Evaluate(ScanSummary{
		TotalSecrets: 100,
		StaleSecrets: 5,
	})
	if !result.Passed {
		t.Error("expected pass with 5% stale")
	}

	// Fails: 20% stale
	result = p.Evaluate(ScanSummary{
		TotalSecrets: 100,
		StaleSecrets: 20,
	})
	if result.Passed {
		t.Error("expected fail with 20% stale exceeding 10% limit")
	}
}

func TestEvaluateMultipleRules(t *testing.T) {
	maxStale := 50
	p := &Policy{
		MaxFindings:           map[string]int{"missing": 0},
		RequiredPathPrefixes:  []string{"kv/"},
		ForbiddenPathPrefixes: []string{"kv/test/"},
		MaxStalePercent:       &maxStale,
	}

	// All pass
	result := p.Evaluate(ScanSummary{
		StatusCounts: map[string]int{"missing": 0},
		TotalSecrets: 10,
		StaleSecrets: 2,
		Paths:        []string{"kv/projects/app"},
	})
	if !result.Passed {
		t.Errorf("expected all rules to pass, got %d rules", len(result.Rules))
		for _, r := range result.Rules {
			t.Logf("  %s: %s — %s", r.Rule, r.Status, r.Message)
		}
	}
	if len(result.Rules) != 4 {
		t.Errorf("expected 4 rules evaluated, got %d", len(result.Rules))
	}
}

func TestEvaluateEmptyPolicy(t *testing.T) {
	p := &Policy{}
	result := p.Evaluate(ScanSummary{
		StatusCounts: map[string]int{"missing": 5},
		TotalSecrets: 10,
		Paths:        []string{"anything/goes"},
	})
	if !result.Passed {
		t.Error("empty policy should pass everything")
	}
}
