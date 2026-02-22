package commands

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/audit"
	"github.com/ppiankov/vaultspectre/internal/logging"
	"github.com/ppiankov/vaultspectre/internal/report"
	"github.com/ppiankov/vaultspectre/internal/scanner"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	repoPath        string
	vaultAddr       string
	vaultToken      string
	vaultNamespace  string
	outputFormat    string
	failOnMissing   bool
	ignoreDynamic   bool
	staleDays       int
	auditLogPath    string
	auditWindowDays int
	varFlags        []string // --var key=value flags
	varFile         string   // --var-file path/to/vars.yaml
	detectVars      bool     // --detect-vars flag
	verbose         bool     // --verbose flag
	listPaths       bool     // --list-paths flag
	summaryOnly     bool     // --summary-only flag
	groupByRole     bool     // --group-by-role flag
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan repository for Vault secret references and validate them",
	Long: `Scans the specified repository for Vault secret path references
and validates each path against the configured Vault instance.

Generates a report of missing, stale, and invalid secret paths.

Exit Codes:
  0 - Success (all secrets OK or only skipped/unresolved paths)
  1 - Issues found (missing/invalid secrets when --fail-on-missing used)
  2 - Error (configuration error, Vault connection failure, etc.)

Examples:
  # Basic scan with auto-detection
  vaultspectre scan . --detect-vars

  # Scan with explicit variable
  vaultspectre scan . --var vault_secret_path=secret/production/app

  # CI/CD mode with fast summary
  vaultspectre scan . --detect-vars --summary-only --fail-on-missing

  # Export paths for documentation
  vaultspectre scan . --detect-vars --list-paths > secrets.txt`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&repoPath, "repo", ".", "Path to repository to scan")
	scanCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	scanCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	scanCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace (Enterprise)")
	scanCmd.Flags().StringVar(&outputFormat, "output", "text", "Output format: text or json")
	scanCmd.Flags().BoolVar(&failOnMissing, "fail-on-missing", false, "Exit with error if missing secrets found")
	scanCmd.Flags().BoolVar(&ignoreDynamic, "ignore-dynamic", true, "Ignore dynamic paths (with variables) in exit code")
	scanCmd.Flags().IntVar(&staleDays, "stale-days", 90, "Days threshold for stale secret detection (0 to disable)")
	scanCmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "Path to Vault audit log file (optional, for access-based staleness)")
	scanCmd.Flags().IntVar(&auditWindowDays, "audit-window-days", 90, "Days to look back in audit logs")
	scanCmd.Flags().StringArrayVar(&varFlags, "var", []string{}, "Set variable value (e.g., --var vault_secret_path=secret/data/prod)")
	scanCmd.Flags().StringVar(&varFile, "var-file", "", "Path to YAML file containing variable values")
	scanCmd.Flags().BoolVar(&detectVars, "detect-vars", false, "Auto-detect variables from Ansible inventory files")
	scanCmd.Flags().BoolVar(&verbose, "verbose", false, "Show detailed information about variable resolution and resolved paths")
	scanCmd.Flags().BoolVar(&listPaths, "list-paths", false, "Output simple list of resolved paths only (one per line)")
	scanCmd.Flags().BoolVar(&summaryOnly, "summary-only", false, "Show only the summary, skip detailed results")
	scanCmd.Flags().BoolVar(&groupByRole, "group-by-role", false, "Group secrets by role/component in the report")
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()
	logging.Init(verbose)

	// Validate required parameters
	if vaultAddr == "" {
		return fmt.Errorf("vault address is required: set --vault-addr flag or VAULT_ADDR environment variable")
	}
	if vaultToken == "" {
		return fmt.Errorf("vault token is required: set --token flag or VAULT_TOKEN environment variable")
	}

	// Initialize scanner
	s := scanner.New(repoPath)

	// Scan repository for secret references
	slog.Info("scanning repository", "path", repoPath)

	references, err := s.Scan()
	if err != nil {
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	slog.Info("found secret references", "count", len(references))

	// ROOTOPS: Resolve variables before validation
	variables, variableSources, err := loadVariables(varFlags, varFile, detectVars, repoPath)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Show loaded variables and their sources
	if len(variables) > 0 {
		slog.Debug("loaded variables", "count", len(variables))
		for key, value := range variables {
			source := variableSources[key]
			if source == "" {
				source = "unknown"
			}
			slog.Debug("variable", "key", key, "value", value, "source", source)
		}
	}

	resolver := scanner.NewResolver(variables)

	// Detect all required variables
	allVariables := resolver.DetectVariables(references)
	if len(allVariables) > 0 && len(variables) == 0 && !detectVars {
		// ROOTOPS: Refuse to proceed without variable values
		fmt.Fprintf(os.Stderr, "\nERROR: Found %d paths with unresolved variables\n\n", countRefsNeedingResolution(references))
		fmt.Fprintf(os.Stderr, "Cannot validate:\n")
		for _, ref := range references {
			if ref.Status == "needs_resolution" && len(ref.Variables) > 0 {
				fmt.Fprintf(os.Stderr, "  - %s (missing: %s)\n", ref.Path, strings.Join(ref.Variables, ", "))
			}
		}
		fmt.Fprintf(os.Stderr, "\nPlease provide variable values:\n")
		fmt.Fprintf(os.Stderr, "  vaultspectre scan . --var %s=<value>\n", allVariables[0])
		fmt.Fprintf(os.Stderr, "\nOr provide a variable file:\n")
		fmt.Fprintf(os.Stderr, "  vaultspectre scan . --var-file vars.yaml\n\n")
		return fmt.Errorf("missing required variables: %s", strings.Join(allVariables, ", "))
	}

	// Resolve variables in paths
	references, missingVarsMap := resolver.ResolveAll(references)

	if len(missingVarsMap) > 0 {
		vars := make([]string, 0, len(missingVarsMap))
		for varName := range missingVarsMap {
			vars = append(vars, varName)
		}
		slog.Warn("some variables could not be resolved", "variables", strings.Join(vars, ", "))
	}

	resolvedCount := countResolvedRefs(references)
	unresolvedCount := countUnresolvedRefs(references)

	if resolvedCount > 0 {
		slog.Info("resolved variable paths", "count", resolvedCount)
	}
	if unresolvedCount > 0 {
		slog.Warn("paths remain unresolved", "count", unresolvedCount)
	}
	for _, ref := range references {
		if ref.ResolvedPath != "" && ref.ResolvedPath != ref.Path {
			slog.Debug("resolved path", "original", ref.Path, "resolved", ref.ResolvedPath)
		}
	}
	slog.Info("connecting to vault", "address", vaultAddr)

	// Initialize Vault client
	vaultClient, err := vault.NewClient(vault.Config{
		Address:   vaultAddr,
		Token:     vaultToken,
		Namespace: vaultNamespace,
	})
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Parse audit log if provided
	var auditAnalyzer *audit.Analyzer
	if auditLogPath != "" {
		slog.Info("parsing audit log", "path", auditLogPath)

		auditParser := audit.NewParser(auditLogPath)
		accessMap, err := auditParser.Parse(auditWindowDays)
		if err != nil {
			slog.Warn("failed to parse audit log, continuing with metadata-only staleness detection", "error", err)
		} else {
			auditAnalyzer = audit.NewAnalyzer(accessMap)
			slog.Info("audit log parsed", "unique_paths", auditAnalyzer.GetTotalPaths())
		}
	}

	// Initialize validator with audit analyzer if available
	var validator *vault.Validator
	if auditAnalyzer != nil {
		validator = vault.NewValidatorWithAudit(vaultClient, auditAnalyzer)
	} else {
		validator = vault.NewValidator(vaultClient)
	}

	// Validate each secret reference
	slog.Info("validating secret paths")

	for i := range references {
		// ROOTOPS: Only validate paths that are ready (resolved or static)
		if references[i].Status != "pending_validation" {
			// Skip: needs_resolution, skipped_policy, etc.
			continue
		}

		// Use ResolvedPath for validation (will be same as Path for static paths)
		pathToValidate := references[i].ResolvedPath
		if pathToValidate == "" {
			pathToValidate = references[i].Path
		}

		status, err := validator.ValidatePath(pathToValidate)
		if err != nil {
			// Non-fatal, record the error in status
			references[i].Status = "error"
			references[i].ErrorMsg = err.Error()
		} else {
			references[i].Status = status
		}

		// Check for staleness if enabled
		if staleDays > 0 && status == "ok" {
			isStale, lastAccessed, err := validator.CheckStaleness(pathToValidate, staleDays)
			if err == nil {
				references[i].IsStale = isStale
				references[i].LastAccessed = lastAccessed
			}
		}
	}

	// Analyze results
	a := analyzer.New(references)
	results := a.Analyze()

	slog.Info("analysis complete",
		"total", results.Summary.TotalReferences,
		"ok", results.Summary.StatusOK,
		"missing", results.Summary.StatusMissing,
		"stale", results.Summary.StaleSecrets,
		"health", results.Summary.HealthScore,
		"duration", time.Since(startTime).Round(time.Millisecond),
	)

	// Handle --list-paths mode: output simple list and exit
	if listPaths {
		printPathsList(references)
		return nil
	}

	// Generate report
	var reporter report.Reporter
	if outputFormat == "json" {
		reporter = report.NewJSONReporter(os.Stdout)
	} else {
		reporter = report.NewTextReporter(os.Stdout)
	}

	reportData := report.Data{
		Tool:      "vaultspectre",
		Version:   Version,
		Timestamp: startTime,
		Config: report.Config{
			VaultAddr:          vaultAddr,
			RepoPath:           repoPath,
			StaleThresholdDays: staleDays,
			Verbose:            verbose,
			SummaryOnly:        summaryOnly,
			GroupByRole:        groupByRole,
		},
		Summary:    results.Summary,
		Secrets:    results.Secrets,
		References: references,
	}

	if err := reporter.Generate(reportData); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Exit with error if requested and issues found
	if failOnMissing {
		issueCount := results.Summary.StatusMissing + results.Summary.StatusInvalid + results.Summary.StatusError
		if !ignoreDynamic {
			issueCount += results.Summary.StatusDynamic
		}
		if issueCount > 0 {
			return fmt.Errorf("found %d issue(s) in secret references", issueCount)
		}
	}

	return nil
}

// loadVariables loads variable values from CLI flags, file, or auto-detection
// Returns variables map and sources map (variable -> source description)
func loadVariables(varFlags []string, varFile string, detectVars bool, repoPath string) (map[string]string, map[string]string, error) {
	variables := make(map[string]string)
	sources := make(map[string]string)

	// Load from --var flags
	for _, v := range varFlags {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid --var format: %s (expected key=value)", v)
		}
		variables[parts[0]] = parts[1]
		sources[parts[0]] = "--var flag (CLI)"
	}

	// Load from --var-file
	if varFile != "" {
		fileVars, err := loadVarFile(varFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load var file: %w", err)
		}
		// Merge file vars (CLI flags take precedence)
		for k, v := range fileVars {
			if _, exists := variables[k]; !exists {
				variables[k] = v
				sources[k] = fmt.Sprintf("--var-file (%s)", varFile)
			}
		}
	}

	// Auto-detect from Ansible inventory (opt-in)
	if detectVars {
		detectedVars, detectedSources, err := detectAnsibleVariables(repoPath)
		if err != nil {
			slog.Warn("variable auto-detection failed", "error", err)
		} else {
			// Merge detected vars (explicit flags take precedence)
			for k, v := range detectedVars {
				if _, exists := variables[k]; !exists {
					variables[k] = v
					sources[k] = detectedSources[k]
				}
			}
			slog.Info("auto-detected variables from ansible inventory", "count", len(detectedVars))
		}
	}

	return variables, sources, nil
}

// loadVarFile loads variables from a YAML file
func loadVarFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var content struct {
		Variables map[string]string `yaml:"variables"`
	}

	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	return content.Variables, nil
}

// detectAnsibleVariables scans Ansible inventory for variable definitions
// Looks in: inventory/*/group_vars/*.yml, group_vars/*.yml, host_vars/*.yml
// Returns variables map and sources map (variable -> file path)
func detectAnsibleVariables(repoPath string) (map[string]string, map[string]string, error) {
	variables := make(map[string]string)
	sources := make(map[string]string)

	// Search patterns for Ansible variable files
	searchPaths := []string{
		"inventory/*/group_vars/*.yml",
		"inventory/*/group_vars/*.yaml",
		"inventory/*/host_vars/*.yml",
		"inventory/*/host_vars/*.yaml",
		"group_vars/*.yml",
		"group_vars/*.yaml",
		"host_vars/*.yml",
		"host_vars/*.yaml",
	}

	for _, pattern := range searchPaths {
		fullPattern := filepath.Join(repoPath, pattern)
		matches, err := filepath.Glob(fullPattern)
		if err != nil {
			continue // Skip patterns that error
		}

		for _, filePath := range matches {
			// Skip example files
			if strings.Contains(filepath.Base(filePath), "example") ||
				strings.Contains(filepath.Base(filePath), "sample") {
				continue
			}

			vars, err := parseAnsibleVarsFile(filePath)
			if err != nil {
				continue // Skip files that can't be parsed
			}

			// Get relative path for source display
			relPath, _ := filepath.Rel(repoPath, filePath)

			// Merge variables (first occurrence wins)
			for key, value := range vars {
				if _, exists := variables[key]; !exists {
					variables[key] = value
					sources[key] = fmt.Sprintf("auto-detect (%s)", relPath)
				}
			}
		}
	}

	return variables, sources, nil
}

// parseAnsibleVarsFile parses a YAML file and extracts string variables
func parseAnsibleVarsFile(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse YAML into generic map
	var content map[string]interface{}
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	variables := make(map[string]string)

	// Extract only string variables (ignore complex types)
	for key, value := range content {
		// Only extract simple string values
		if strValue, ok := value.(string); ok {
			// Skip if the value contains Jinja2 templates (these are derived variables)
			if !strings.Contains(strValue, "{{") {
				variables[key] = strValue
			}
		}
	}

	return variables, nil
}

// countRefsNeedingResolution counts references that need variable resolution
func countRefsNeedingResolution(refs []scanner.Reference) int {
	count := 0
	for _, ref := range refs {
		if ref.Status == "needs_resolution" {
			count++
		}
	}
	return count
}

// countResolvedRefs counts references that were successfully resolved
func countResolvedRefs(refs []scanner.Reference) int {
	count := 0
	for _, ref := range refs {
		if ref.ResolvedPath != "" && ref.ResolvedPath != ref.Path {
			count++
		}
	}
	return count
}

// countUnresolvedRefs counts references that still need resolution
func countUnresolvedRefs(refs []scanner.Reference) int {
	count := 0
	for _, ref := range refs {
		if ref.Status == "needs_resolution" {
			count++
		}
	}
	return count
}

// printPathsList outputs a simple list of resolved Vault paths (one per line)
func printPathsList(refs []scanner.Reference) {
	seen := make(map[string]bool)
	for _, ref := range refs {
		path := ref.ResolvedPath
		if path == "" {
			path = ref.Path
		}
		// Only include validated paths, skip unresolved
		if ref.Status != "needs_resolution" && ref.Status != "skipped_policy" && !seen[path] {
			fmt.Println(path)
			seen[path] = true
		}
	}
}
