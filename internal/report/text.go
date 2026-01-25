package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
)

// TextReporter generates human-readable text reports
type TextReporter struct {
	writer io.Writer
}

// NewTextReporter creates a new text reporter
func NewTextReporter(w io.Writer) *TextReporter {
	return &TextReporter{writer: w}
}

// Generate generates a text report
func (r *TextReporter) Generate(data Data) error {
	// Header
	fmt.Fprintf(r.writer, "\n")
	fmt.Fprintf(r.writer, "═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(r.writer, "  VaultSpectre Report\n")
	fmt.Fprintf(r.writer, "═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(r.writer, "\n")

	// Configuration
	fmt.Fprintf(r.writer, "Configuration:\n")
	fmt.Fprintf(r.writer, "  Vault:       %s\n", data.Config.VaultAddr)
	fmt.Fprintf(r.writer, "  Repository:  %s\n", data.Config.RepoPath)
	fmt.Fprintf(r.writer, "  Scan Time:   %s\n", data.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(r.writer, "\n")

	// Summary
	fmt.Fprintf(r.writer, "Summary:\n")
	fmt.Fprintf(r.writer, "  Total References:  %d\n", data.Summary.TotalReferences)
	fmt.Fprintf(r.writer, "  ├─ OK:             %d\n", data.Summary.StatusOK)
	fmt.Fprintf(r.writer, "  ├─ Missing:        %d\n", data.Summary.StatusMissing)
	fmt.Fprintf(r.writer, "  ├─ Access Denied:  %d\n", data.Summary.StatusAccessDenied)
	fmt.Fprintf(r.writer, "  ├─ Invalid:        %d\n", data.Summary.StatusInvalid)
	fmt.Fprintf(r.writer, "  └─ Errors:         %d\n", data.Summary.StatusError)

	if data.Config.StaleThresholdDays > 0 {
		fmt.Fprintf(r.writer, "  Stale Secrets:     %d (>%d days)\n",
			data.Summary.StaleSecrets, data.Config.StaleThresholdDays)
	}

	fmt.Fprintf(r.writer, "\n")
	fmt.Fprintf(r.writer, "  Health Score:      %s\n", r.formatHealthScore(data.Summary.HealthScore))
	fmt.Fprintf(r.writer, "\n")

	// Detailed results
	if data.Summary.StatusMissing > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(r.writer, "Missing Secrets (%d)\n", data.Summary.StatusMissing)
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		r.printSecretsByStatus(data, "missing")
		fmt.Fprintf(r.writer, "\n")
	}

	if data.Summary.StaleSecrets > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(r.writer, "Stale Secrets (%d)\n", data.Summary.StaleSecrets)
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		r.printStaleSecrets(data)
		fmt.Fprintf(r.writer, "\n")
	}

	if data.Summary.StatusAccessDenied > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(r.writer, "Access Denied (%d)\n", data.Summary.StatusAccessDenied)
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		r.printSecretsByStatus(data, "access_denied")
		fmt.Fprintf(r.writer, "\n")
	}

	if data.Summary.StatusInvalid > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(r.writer, "Invalid Paths (%d)\n", data.Summary.StatusInvalid)
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		r.printSecretsByStatus(data, "invalid")
		fmt.Fprintf(r.writer, "\n")
	}

	// Footer
	fmt.Fprintf(r.writer, "═══════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(r.writer, "  Part of the SpectreOps family\n")
	fmt.Fprintf(r.writer, "═══════════════════════════════════════════════════════════════\n")

	return nil
}

func (r *TextReporter) printSecretsByStatus(data Data, status string) {
	// Collect secrets with the given status
	var paths []string
	for path, info := range data.Secrets {
		if info.Status == status {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	for _, path := range paths {
		info := data.Secrets[path]
		fmt.Fprintf(r.writer, "\n  [%s] %s\n", strings.ToUpper(status), path)

		if info.ErrorMsg != "" {
			fmt.Fprintf(r.writer, "    Error: %s\n", info.ErrorMsg)
		}

		fmt.Fprintf(r.writer, "    Referenced in %d location(s):\n", len(info.References))
		for _, ref := range info.References {
			fmt.Fprintf(r.writer, "      - %s:%d (%s)\n", ref.File, ref.Line, ref.Type)
		}
	}
}

func (r *TextReporter) printStaleSecrets(data Data) {
	var staleSecrets []*analyzer.SecretInfo
	for _, info := range data.Secrets {
		if info.IsStale {
			staleSecrets = append(staleSecrets, info)
		}
	}

	// Sort by path
	sort.Slice(staleSecrets, func(i, j int) bool {
		return staleSecrets[i].Path < staleSecrets[j].Path
	})

	for _, info := range staleSecrets {
		fmt.Fprintf(r.writer, "\n  [STALE] %s\n", info.Path)
		if info.LastAccessed != "" {
			// LastAccessed now contains rich information: "2026-01-23... (accessed 147 times, last 52 days ago)"
			fmt.Fprintf(r.writer, "    Activity: %s\n", info.LastAccessed)
		}
		fmt.Fprintf(r.writer, "    Referenced in %d location(s):\n", len(info.References))
		for _, ref := range info.References {
			fmt.Fprintf(r.writer, "      - %s:%d (%s)\n", ref.File, ref.Line, ref.Type)
		}
	}
}

func (r *TextReporter) formatHealthScore(score string) string {
	colors := map[string]string{
		"excellent": "EXCELLENT ✓",
		"good":      "GOOD",
		"warning":   "WARNING ⚠",
		"critical":  "CRITICAL ⚠⚠",
		"severe":    "SEVERE ⚠⚠⚠",
		"unknown":   "UNKNOWN",
	}

	if formatted, ok := colors[score]; ok {
		return formatted
	}
	return score
}
