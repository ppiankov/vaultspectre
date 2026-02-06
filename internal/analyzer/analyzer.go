package analyzer

import (
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

// Analyzer analyzes scan results
type Analyzer struct {
	references []scanner.Reference
}

// Results contains the analysis results
type Results struct {
	Summary Summary
	Secrets map[string]*SecretInfo
}

// Summary contains summary statistics
type Summary struct {
	TotalReferences       int    `json:"total_references"`
	StatusOK              int    `json:"status_ok"`
	StatusMissing         int    `json:"status_missing"`
	StatusAccessDenied    int    `json:"status_access_denied"`
	StatusInvalid         int    `json:"status_invalid"`
	StatusDynamic         int    `json:"status_dynamic"`          // Legacy: kept for compatibility
	StatusError           int    `json:"status_error"`
	StatusNeedsResolution int    `json:"status_needs_resolution"` // Paths with unresolved variables
	StatusSkippedPolicy   int    `json:"status_skipped_policy"`   // Policy wildcards
	StaleSecrets          int    `json:"stale_secrets"`
	HealthScore           string `json:"health_score"`
}

// SecretInfo contains information about a specific secret
type SecretInfo struct {
	Path         string              `json:"path"`
	Status       string              `json:"status"`
	IsStale      bool                `json:"is_stale,omitempty"`
	LastAccessed string              `json:"last_accessed,omitempty"`
	ErrorMsg     string              `json:"error_msg,omitempty"`
	References   []scanner.Reference `json:"references"`
}

// New creates a new analyzer
func New(references []scanner.Reference) *Analyzer {
	return &Analyzer{
		references: references,
	}
}

// Analyze performs the analysis and returns results
func (a *Analyzer) Analyze() *Results {
	summary := Summary{
		TotalReferences: len(a.references),
	}

	secrets := make(map[string]*SecretInfo)

	// Group references by path and count statuses
	for _, ref := range a.references {
		if _, exists := secrets[ref.Path]; !exists {
			secrets[ref.Path] = &SecretInfo{
				Path:         ref.Path,
				Status:       ref.Status,
				IsStale:      ref.IsStale,
				LastAccessed: ref.LastAccessed,
				ErrorMsg:     ref.ErrorMsg,
				References:   []scanner.Reference{},
			}
		}
		secrets[ref.Path].References = append(secrets[ref.Path].References, ref)

		// Count by status
		switch ref.Status {
		case "ok":
			summary.StatusOK++
		case "missing":
			summary.StatusMissing++
		case "access_denied":
			summary.StatusAccessDenied++
		case "invalid":
			summary.StatusInvalid++
		case "dynamic":
			summary.StatusDynamic++
		case "error":
			summary.StatusError++
		case "needs_resolution":
			summary.StatusNeedsResolution++
		case "skipped_policy":
			summary.StatusSkippedPolicy++
		}

		// Count stale secrets
		if ref.IsStale {
			summary.StaleSecrets++
		}
	}

	// Calculate health score
	summary.HealthScore = calculateHealthScore(summary)

	return &Results{
		Summary: summary,
		Secrets: secrets,
	}
}

func calculateHealthScore(s Summary) string {
	// ROOTOPS: Only count validated paths in health score
	// Skipped and unresolved paths are not failures, just unvalidatable
	validatedCount := s.StatusOK + s.StatusMissing + s.StatusAccessDenied + s.StatusInvalid + s.StatusError

	if validatedCount == 0 {
		// No paths were validated - cannot determine health
		return "unknown"
	}

	// Calculate percentage of issues among validated paths only
	issues := s.StatusMissing + s.StatusInvalid + s.StatusError
	issuePercent := float64(issues) / float64(validatedCount) * 100

	// Consider stale secrets as partial issues
	stalePercent := float64(s.StaleSecrets) / float64(validatedCount) * 100

	totalIssuePercent := issuePercent + (stalePercent * 0.5)

	if totalIssuePercent == 0 {
		return "excellent"
	} else if totalIssuePercent < 5 {
		return "good"
	} else if totalIssuePercent < 15 {
		return "warning"
	} else if totalIssuePercent < 30 {
		return "critical"
	}
	return "severe"
}
