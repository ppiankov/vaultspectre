package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/ppiankov/vaultspectre/internal/report"
	"github.com/spf13/cobra"
)

// DiffFinding represents a single change between two scan reports.
type DiffFinding struct {
	Path      string `json:"path"`
	Change    string `json:"change"`               // "added", "removed", "changed"
	OldStatus string `json:"old_status,omitempty"` // Only for "changed"
	NewStatus string `json:"new_status,omitempty"` // Only for "changed" and "added"
}

// DiffResult holds the full diff output.
type DiffResult struct {
	Added   []DiffFinding `json:"added"`
	Removed []DiffFinding `json:"removed"`
	Changed []DiffFinding `json:"changed"`
	Summary DiffSummary   `json:"summary"`
}

// DiffSummary holds counts.
type DiffSummary struct {
	TotalAdded   int `json:"total_added"`
	TotalRemoved int `json:"total_removed"`
	TotalChanged int `json:"total_changed"`
}

var (
	diffOldPath string
	diffNewPath string
	diffFormat  string
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two scan reports and show changes",
	Long: `Compares two vaultspectre JSON scan reports and outputs the delta:
added findings, removed findings, and status changes.

Use this in CI to compare a baseline scan against a branch scan for
PR-level feedback.

Examples:
  vaultspectre diff --old baseline.json --new current.json
  vaultspectre diff --old baseline.json --new current.json --format json

Exit Codes:
  0 - No new findings
  6 - New findings detected (added or worsened)
  2 - Invalid arguments or malformed input`,
	RunE: runDiff,
}

func init() {
	diffCmd.Flags().StringVar(&diffOldPath, "old", "", "Path to old/baseline scan report (JSON)")
	diffCmd.Flags().StringVar(&diffNewPath, "new", "", "Path to new/current scan report (JSON)")
	diffCmd.Flags().StringVar(&diffFormat, "format", "text", "Output format: text, json")
	_ = diffCmd.MarkFlagRequired("old")
	_ = diffCmd.MarkFlagRequired("new")
}

func runDiff(_ *cobra.Command, _ []string) error {
	oldReport, err := loadReport(diffOldPath)
	if err != nil {
		return newExitError(ExitBadArgs, "failed to read old report %s: %v", diffOldPath, err)
	}

	newReport, err := loadReport(diffNewPath)
	if err != nil {
		return newExitError(ExitBadArgs, "failed to read new report %s: %v", diffNewPath, err)
	}

	result := computeDiff(oldReport, newReport)

	if diffFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result); encErr != nil {
			return fmt.Errorf("failed to encode JSON: %w", encErr)
		}
	} else {
		printDiffText(result)
	}

	// Exit 6 if new findings appeared or statuses worsened
	if result.Summary.TotalAdded > 0 || hasWorsenedFindings(result.Changed) {
		return newExitError(ExitFindings, "%d new finding(s) detected", result.Summary.TotalAdded+countWorsened(result.Changed))
	}

	return nil
}

func loadReport(path string) (*report.Data, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var r report.Data
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return &r, nil
}

func computeDiff(old, new *report.Data) *DiffResult {
	result := &DiffResult{}

	// Build sets of path → status from secrets maps
	oldSecrets := make(map[string]string)
	for path, info := range old.Secrets {
		oldSecrets[path] = info.Status
	}

	newSecrets := make(map[string]string)
	for path, info := range new.Secrets {
		newSecrets[path] = info.Status
	}

	// Find added and changed
	for path, newStatus := range newSecrets {
		oldStatus, existed := oldSecrets[path]
		if !existed {
			result.Added = append(result.Added, DiffFinding{
				Path:      path,
				Change:    "added",
				NewStatus: newStatus,
			})
		} else if oldStatus != newStatus {
			result.Changed = append(result.Changed, DiffFinding{
				Path:      path,
				Change:    "changed",
				OldStatus: oldStatus,
				NewStatus: newStatus,
			})
		}
	}

	// Find removed
	for path, oldStatus := range oldSecrets {
		if _, exists := newSecrets[path]; !exists {
			result.Removed = append(result.Removed, DiffFinding{
				Path:      path,
				Change:    "removed",
				OldStatus: oldStatus,
			})
		}
	}

	// Sort for deterministic output
	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].Path < result.Added[j].Path })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].Path < result.Removed[j].Path })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].Path < result.Changed[j].Path })

	result.Summary = DiffSummary{
		TotalAdded:   len(result.Added),
		TotalRemoved: len(result.Removed),
		TotalChanged: len(result.Changed),
	}

	return result
}

func printDiffText(result *DiffResult) {
	if len(result.Added) > 0 {
		fmt.Printf("Added (%d):\n", len(result.Added))
		for _, f := range result.Added {
			fmt.Printf("  + %s [%s]\n", f.Path, f.NewStatus)
		}
		fmt.Println()
	}

	if len(result.Removed) > 0 {
		fmt.Printf("Removed (%d):\n", len(result.Removed))
		for _, f := range result.Removed {
			fmt.Printf("  - %s [was: %s]\n", f.Path, f.OldStatus)
		}
		fmt.Println()
	}

	if len(result.Changed) > 0 {
		fmt.Printf("Changed (%d):\n", len(result.Changed))
		for _, f := range result.Changed {
			fmt.Printf("  ~ %s [%s → %s]\n", f.Path, f.OldStatus, f.NewStatus)
		}
		fmt.Println()
	}

	if result.Summary.TotalAdded == 0 && result.Summary.TotalRemoved == 0 && result.Summary.TotalChanged == 0 {
		fmt.Println("No changes between reports.")
	} else {
		fmt.Printf("Summary: %d added, %d removed, %d changed\n",
			result.Summary.TotalAdded, result.Summary.TotalRemoved, result.Summary.TotalChanged)
	}
}

// statusSeverity maps status to a severity level (higher = worse)
var statusSeverity = map[string]int{
	"ok":               0,
	"access_denied":    1,
	"needs_resolution": 1,
	"error":            2,
	"missing":          3,
}

func hasWorsenedFindings(changed []DiffFinding) bool {
	for _, f := range changed {
		if statusSeverity[f.NewStatus] > statusSeverity[f.OldStatus] {
			return true
		}
	}
	return false
}

func countWorsened(changed []DiffFinding) int {
	count := 0
	for _, f := range changed {
		if statusSeverity[f.NewStatus] > statusSeverity[f.OldStatus] {
			count++
		}
	}
	return count
}
