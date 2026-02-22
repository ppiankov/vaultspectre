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

	// Summary - ROOTOPS format
	validatedCount := data.Summary.StatusOK + data.Summary.StatusMissing +
		data.Summary.StatusAccessDenied + data.Summary.StatusInvalid + data.Summary.StatusError
	skippedCount := data.Summary.StatusNeedsResolution + data.Summary.StatusSkippedPolicy

	fmt.Fprintf(r.writer, "Summary:\n")
	fmt.Fprintf(r.writer, "  Total References:     %d\n", data.Summary.TotalReferences)

	if validatedCount > 0 {
		fmt.Fprintf(r.writer, "  ├─ Validated:         %d\n", validatedCount)
		fmt.Fprintf(r.writer, "  │  ├─ OK:            %d\n", data.Summary.StatusOK)
		if data.Summary.StatusMissing > 0 {
			fmt.Fprintf(r.writer, "  │  ├─ Missing:       %d\n", data.Summary.StatusMissing)
		}
		if data.Summary.StatusAccessDenied > 0 {
			fmt.Fprintf(r.writer, "  │  ├─ Access Denied: %d\n", data.Summary.StatusAccessDenied)
		}
		if data.Summary.StatusInvalid > 0 {
			fmt.Fprintf(r.writer, "  │  ├─ Invalid:       %d\n", data.Summary.StatusInvalid)
		}
		if data.Summary.StatusError > 0 {
			fmt.Fprintf(r.writer, "  │  └─ Errors:        %d\n", data.Summary.StatusError)
		}
	}

	if skippedCount > 0 {
		fmt.Fprintf(r.writer, "  ├─ Skipped:           %d\n", skippedCount)
		if data.Summary.StatusNeedsResolution > 0 {
			fmt.Fprintf(r.writer, "  │  ├─ Unresolved:    %d (variables)\n", data.Summary.StatusNeedsResolution)
		}
		if data.Summary.StatusSkippedPolicy > 0 {
			fmt.Fprintf(r.writer, "  │  └─ Policy:        %d (wildcards)\n", data.Summary.StatusSkippedPolicy)
		}
	}

	if data.Config.StaleThresholdDays > 0 && data.Summary.StaleSecrets > 0 {
		fmt.Fprintf(r.writer, "  └─ Stale:             %d (>%d days)\n",
			data.Summary.StaleSecrets, data.Config.StaleThresholdDays)
	}

	fmt.Fprintf(r.writer, "\n")
	fmt.Fprintf(r.writer, "  Validation Health:    %s", r.formatHealthScore(data.Summary.HealthScore))
	if validatedCount > 0 {
		fmt.Fprintf(r.writer, " (%d/%d validated)", data.Summary.StatusOK, validatedCount)
	}
	fmt.Fprintf(r.writer, "\n\n")

	// Add note about skipped paths
	if skippedCount > 0 {
		fmt.Fprintf(r.writer, "  Note: %d paths skipped (not errors, cannot validate statically)\n\n", skippedCount)
	}

	// No-findings positive message
	issueCount := data.Summary.StatusMissing + data.Summary.StatusAccessDenied +
		data.Summary.StatusInvalid + data.Summary.StatusError
	if issueCount == 0 && data.Summary.StaleSecrets == 0 && validatedCount > 0 {
		fmt.Fprintf(r.writer, "  No issues detected. %d paths validated.\n\n", validatedCount)
	}

	// If summary-only mode, skip detailed results
	if data.Config.SummaryOnly {
		return nil
	}

	// Group by role mode
	if data.Config.GroupByRole {
		r.printGroupedByRole(data)
		return nil
	}

	// Show unresolved paths first (ROOTOPS: explicit about what couldn't be validated)
	if data.Summary.StatusNeedsResolution > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		fmt.Fprintf(r.writer, "Unresolved Paths (%d) - Require Variable Values\n", data.Summary.StatusNeedsResolution)
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		r.printUnresolvedPaths(data)
		fmt.Fprintf(r.writer, "\n")
	}

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

	// Exit code hints when issues are found
	if issueCount > 0 {
		fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
		if data.Config.FailOnMissing {
			fmt.Fprintf(r.writer, "Exit code 1: %d issue(s) found with --fail-on-missing enabled.\n", issueCount)
		} else {
			fmt.Fprintf(r.writer, "Hint: Use --fail-on-missing to exit with code 1 when issues are found.\n")
		}
		fmt.Fprintf(r.writer, "\n")
	}

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

		// Verbose: Show template and resolved path
		if data.Config.Verbose {
			// Find the reference to get template info
			for _, ref := range data.References {
				if ref.ResolvedPath == path && ref.Path != ref.ResolvedPath {
					fmt.Fprintf(r.writer, "    Template: %s\n", ref.Path)
					fmt.Fprintf(r.writer, "    Resolved: %s\n", ref.ResolvedPath)
					break
				}
			}
		}

		if info.ErrorMsg != "" {
			fmt.Fprintf(r.writer, "    Error: %s\n", info.ErrorMsg)
		}

		fmt.Fprintf(r.writer, "    Referenced in %d location(s):\n", len(info.References))
		for _, ref := range info.References {
			fmt.Fprintf(r.writer, "      - %s:%d (%s)\n", ref.File, ref.Line, ref.Type)
		}
	}
}

func (r *TextReporter) printUnresolvedPaths(data Data) {
	// Group by variables needed
	variableMap := make(map[string][]string) // variable -> list of paths

	for _, ref := range data.References {
		if ref.Status == "needs_resolution" && len(ref.Variables) > 0 {
			for _, varName := range ref.Variables {
				variableMap[varName] = append(variableMap[varName], ref.Path)
			}
		}
	}

	// Get unique variables
	var variables []string
	for varName := range variableMap {
		variables = append(variables, varName)
	}
	sort.Strings(variables)

	fmt.Fprintf(r.writer, "\n  These paths contain variables and cannot be validated without values.\n")
	fmt.Fprintf(r.writer, "  Provide values with:\n\n")

	if len(variables) > 0 {
		fmt.Fprintf(r.writer, "    vaultspectre scan . --var %s=<value>", variables[0])
		if len(variables) > 1 {
			fmt.Fprintf(r.writer, " --var %s=<value>", variables[1])
		}
		fmt.Fprintf(r.writer, "\n\n")
	}

	fmt.Fprintf(r.writer, "  Missing variables:\n")
	for _, varName := range variables {
		paths := variableMap[varName]
		// Get unique paths
		uniquePaths := make(map[string]bool)
		for _, p := range paths {
			uniquePaths[p] = true
		}
		fmt.Fprintf(r.writer, "    - %s (used in %d path(s))\n", varName, len(uniquePaths))
	}
	fmt.Fprintf(r.writer, "\n")
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

// printGroupedByRole groups secrets by role/component
func (r *TextReporter) printGroupedByRole(data Data) {
	// Group references by role (extract from file path)
	roleSecrets := make(map[string]map[string][]string) // role -> status -> []paths

	for _, ref := range data.References {
		// Extract role from path like "roles/clickhouse-server/tasks/vault.yml"
		role := "other"
		if strings.HasPrefix(ref.File, "roles/") {
			parts := strings.Split(ref.File, "/")
			if len(parts) >= 2 {
				role = parts[1]
			}
		}

		path := ref.ResolvedPath
		if path == "" {
			path = ref.Path
		}

		status := ref.Status
		if status == "pending_validation" {
			// Find actual status from secrets map
			if secret, exists := data.Secrets[path]; exists {
				status = secret.Status
			}
		}

		if roleSecrets[role] == nil {
			roleSecrets[role] = make(map[string][]string)
		}
		roleSecrets[role][status] = append(roleSecrets[role][status], path)
	}

	// Sort roles
	var roles []string
	for role := range roleSecrets {
		roles = append(roles, role)
	}
	sort.Strings(roles)

	fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(r.writer, "Secrets Grouped by Role/Component\n")
	fmt.Fprintf(r.writer, "───────────────────────────────────────────────────────────────\n\n")

	for _, role := range roles {
		statuses := roleSecrets[role]
		total := 0
		for _, paths := range statuses {
			total += len(paths)
		}

		fmt.Fprintf(r.writer, "Role: %s (%d secrets)\n", role, total)

		// Count by status
		okCount := len(statuses["ok"])
		missingCount := len(statuses["missing"])
		deniedCount := len(statuses["access_denied"])
		unresolvedCount := len(statuses["needs_resolution"])

		if okCount > 0 {
			fmt.Fprintf(r.writer, "  ✓ OK: %d\n", okCount)
		}
		if missingCount > 0 {
			fmt.Fprintf(r.writer, "  ✗ Missing: %d\n", missingCount)
			for _, path := range statuses["missing"] {
				fmt.Fprintf(r.writer, "      - %s\n", path)
			}
		}
		if deniedCount > 0 {
			fmt.Fprintf(r.writer, "  ✗ Access Denied: %d\n", deniedCount)
		}
		if unresolvedCount > 0 {
			fmt.Fprintf(r.writer, "  ⚠ Unresolved: %d\n", unresolvedCount)
		}
		fmt.Fprintf(r.writer, "\n")
	}
}
