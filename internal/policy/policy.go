package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy defines enforcement rules for scan results.
type Policy struct {
	// MaxFindings limits the number of findings by status.
	// e.g. {"missing": 0, "error": 5} means zero missing allowed, up to 5 errors.
	MaxFindings map[string]int `yaml:"max_findings"`

	// RequiredPathPrefixes ensures all discovered paths start with one of these prefixes.
	RequiredPathPrefixes []string `yaml:"required_path_prefixes"`

	// ForbiddenPathPrefixes flags any path that starts with these prefixes.
	ForbiddenPathPrefixes []string `yaml:"forbidden_path_prefixes"`

	// MaxStalePercent is the maximum percentage of secrets that can be stale (0-100).
	MaxStalePercent *int `yaml:"max_stale_percent"`
}

// RuleResult holds the outcome of evaluating a single policy rule.
type RuleResult struct {
	Rule    string `json:"rule"`
	Status  string `json:"status"` // "pass" or "fail"
	Message string `json:"message"`
}

// EvalResult holds the full policy evaluation.
type EvalResult struct {
	Rules  []RuleResult `json:"rules"`
	Passed bool         `json:"passed"`
}

// Load reads a policy file from disk.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid policy YAML: %w", err)
	}

	return &p, nil
}

// ScanSummary is the minimal interface needed from scan results.
type ScanSummary struct {
	StatusCounts map[string]int // status → count (e.g. "missing" → 3)
	TotalSecrets int
	StaleSecrets int
	Paths        []string // All discovered vault paths
}

// Evaluate checks scan results against the policy and returns rule results.
func (p *Policy) Evaluate(summary ScanSummary) EvalResult {
	var rules []RuleResult
	allPassed := true

	// Rule: max_findings
	for status, maxAllowed := range p.MaxFindings {
		actual := summary.StatusCounts[status]
		if actual > maxAllowed {
			rules = append(rules, RuleResult{
				Rule:    fmt.Sprintf("max_findings[%s]", status),
				Status:  "fail",
				Message: fmt.Sprintf("%d %s findings exceed limit of %d", actual, status, maxAllowed),
			})
			allPassed = false
		} else {
			rules = append(rules, RuleResult{
				Rule:    fmt.Sprintf("max_findings[%s]", status),
				Status:  "pass",
				Message: fmt.Sprintf("%d %s findings within limit of %d", actual, status, maxAllowed),
			})
		}
	}

	// Rule: required_path_prefixes
	if len(p.RequiredPathPrefixes) > 0 {
		violations := 0
		var violatingPaths []string
		for _, path := range summary.Paths {
			hasPrefix := false
			for _, prefix := range p.RequiredPathPrefixes {
				if strings.HasPrefix(path, prefix) {
					hasPrefix = true
					break
				}
			}
			if !hasPrefix {
				violations++
				if len(violatingPaths) < 3 {
					violatingPaths = append(violatingPaths, path)
				}
			}
		}
		if violations > 0 {
			msg := fmt.Sprintf("%d paths outside required prefixes", violations)
			if len(violatingPaths) > 0 {
				msg += fmt.Sprintf(" (e.g. %s)", strings.Join(violatingPaths, ", "))
			}
			rules = append(rules, RuleResult{
				Rule:    "required_path_prefixes",
				Status:  "fail",
				Message: msg,
			})
			allPassed = false
		} else {
			rules = append(rules, RuleResult{
				Rule:    "required_path_prefixes",
				Status:  "pass",
				Message: fmt.Sprintf("all paths within required prefixes: %v", p.RequiredPathPrefixes),
			})
		}
	}

	// Rule: forbidden_path_prefixes
	if len(p.ForbiddenPathPrefixes) > 0 {
		violations := 0
		var violatingPaths []string
		for _, path := range summary.Paths {
			for _, prefix := range p.ForbiddenPathPrefixes {
				if strings.HasPrefix(path, prefix) {
					violations++
					if len(violatingPaths) < 3 {
						violatingPaths = append(violatingPaths, path)
					}
					break
				}
			}
		}
		if violations > 0 {
			msg := fmt.Sprintf("%d paths match forbidden prefixes", violations)
			if len(violatingPaths) > 0 {
				msg += fmt.Sprintf(" (e.g. %s)", strings.Join(violatingPaths, ", "))
			}
			rules = append(rules, RuleResult{
				Rule:    "forbidden_path_prefixes",
				Status:  "fail",
				Message: msg,
			})
			allPassed = false
		} else {
			rules = append(rules, RuleResult{
				Rule:    "forbidden_path_prefixes",
				Status:  "pass",
				Message: "no paths match forbidden prefixes",
			})
		}
	}

	// Rule: max_stale_percent
	if p.MaxStalePercent != nil && summary.TotalSecrets > 0 {
		stalePercent := (summary.StaleSecrets * 100) / summary.TotalSecrets
		if stalePercent > *p.MaxStalePercent {
			rules = append(rules, RuleResult{
				Rule:    "max_stale_percent",
				Status:  "fail",
				Message: fmt.Sprintf("%d%% stale secrets exceed limit of %d%%", stalePercent, *p.MaxStalePercent),
			})
			allPassed = false
		} else {
			rules = append(rules, RuleResult{
				Rule:    "max_stale_percent",
				Status:  "pass",
				Message: fmt.Sprintf("%d%% stale secrets within limit of %d%%", stalePercent, *p.MaxStalePercent),
			})
		}
	}

	return EvalResult{
		Rules:  rules,
		Passed: allPassed,
	}
}
