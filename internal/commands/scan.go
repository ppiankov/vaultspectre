package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/audit"
	"github.com/ppiankov/vaultspectre/internal/baseline"
	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/logging"
	"github.com/ppiankov/vaultspectre/internal/policy"
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
	timeoutSeconds  int      // --timeout flag (seconds)
	baselinePath    string   // --baseline flag
	updateBaseline  bool     // --update-baseline flag
	excludeFlag     string   // --exclude flag (comma-separated globs)
	scanTimeoutMins int      // --scan-timeout flag (minutes, 0 to disable)
	policyPath      string   // --policy flag
	authMethod      string   // --auth-method flag
	roleID          string   // --role-id for AppRole
	secretID        string   // --secret-id for AppRole
	k8sRole         string   // --k8s-role for Kubernetes auth
	k8sJWTPath      string   // --k8s-jwt-path for Kubernetes auth
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
	scanCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json, sarif, or spectrehub")
	scanCmd.Flags().StringVar(&outputFormat, "output", "text", "Output format (deprecated, use --format)")
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
	scanCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Timeout in seconds for Vault API calls (includes retry window)")
	scanCmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline file for suppressing known findings")
	scanCmd.Flags().BoolVar(&updateBaseline, "update-baseline", false, "Save current findings as new baseline")
	scanCmd.Flags().StringVar(&excludeFlag, "exclude", "", "Comma-separated glob patterns to exclude from scanning")
	scanCmd.Flags().IntVar(&scanTimeoutMins, "scan-timeout", 10, "Global scan timeout in minutes (0 to disable)")
	scanCmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy YAML file for enforcement")
	scanCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	scanCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	scanCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
	scanCmd.Flags().StringVar(&k8sRole, "k8s-role", "", "Kubernetes auth role name")
	scanCmd.Flags().StringVar(&k8sJWTPath, "k8s-jwt-path", "", "Path to Kubernetes JWT file")
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()
	logging.Init(verbose)

	// Load config file (values apply only when CLI flag not explicitly set)
	cfg, cfgSource, err := config.Load()
	if err != nil {
		slog.Warn("failed to load config file", "error", err)
	}
	if cfgSource != "" {
		slog.Info("loaded config file", "path", cfgSource)
		applyConfig(cmd, cfg)
	} else {
		slog.Debug("no config file found; create .vaultspectre.yaml to set persistent defaults")
	}

	// Validate required parameters
	if vaultAddr == "" {
		return newExitError(ExitBadArgs, "vault address is required: set --vault-addr flag or VAULT_ADDR environment variable")
	}
	if !vault.ValidAuthMethod(authMethod) {
		return newExitError(ExitBadArgs, "unsupported auth method: %s (use token, approle, or kubernetes)", authMethod)
	}
	if vault.AuthMethod(authMethod) == vault.AuthToken && vaultToken == "" {
		return newExitError(ExitBadArgs, "vault token is required: set --token flag or VAULT_TOKEN environment variable")
	}

	// Build exclude patterns from config + CLI flag
	var excludePatterns []string
	excludePatterns = append(excludePatterns, cfg.ExcludePatterns...)
	if excludeFlag != "" {
		for _, p := range strings.Split(excludeFlag, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				excludePatterns = append(excludePatterns, trimmed)
			}
		}
	}

	// Initialize scanner
	var s *scanner.Scanner
	if len(excludePatterns) > 0 {
		s = scanner.NewWithExcludes(repoPath, excludePatterns)
	} else {
		s = scanner.New(repoPath)
	}

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
		for key := range variables {
			source := variableSources[key]
			if source == "" {
				source = "unknown"
			}
			slog.Debug("variable", "key", key, "value", "[set]", "source", source)
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
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	})
	if err != nil {
		return newExitError(ExitNetwork, "failed to create Vault client: %v", err)
	}

	// Authenticate using configured method
	if err := vault.Authenticate(vaultClient.GetClient(), vault.AuthConfig{
		Method:     vault.AuthMethod(authMethod),
		Token:      vaultToken,
		RoleID:     roleID,
		SecretID:   secretID,
		K8sRole:    k8sRole,
		K8sJWTPath: k8sJWTPath,
	}); err != nil {
		return newExitError(ExitBadArgs, "authentication failed: %v", err)
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

	// Set up global scan timeout
	var ctx context.Context
	var cancel context.CancelFunc
	if scanTimeoutMins > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(scanTimeoutMins)*time.Minute)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	totalPaths := 0
	validatedPaths := 0
	for i := range references {
		if references[i].Status == "pending_validation" {
			totalPaths++
		}
	}

	for i := range references {
		// ROOTOPS: Only validate paths that are ready (resolved or static)
		if references[i].Status != "pending_validation" {
			// Skip: needs_resolution, skipped_policy, etc.
			continue
		}

		// Check scan timeout
		if ctx.Err() != nil {
			slog.Warn("scan timed out, flushing partial results",
				"validated", validatedPaths,
				"total", totalPaths,
				"timeout_minutes", scanTimeoutMins,
			)
			fmt.Fprintf(os.Stderr, "scan timed out after %dm: %d/%d paths validated\n",
				scanTimeoutMins, validatedPaths, totalPaths)
			break
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
		validatedPaths++

		// Check for staleness if enabled
		if staleDays > 0 && status == "ok" {
			isStale, lastAccessed, err := validator.CheckStaleness(pathToValidate, staleDays)
			if err == nil {
				references[i].IsStale = isStale
				references[i].LastAccessed = lastAccessed
			}
		}
	}

	scanTimedOut := ctx.Err() != nil

	// Update baseline if requested (before filtering)
	if updateBaseline && baselinePath != "" {
		b := baseline.FromRefs(references, Version)
		if err := b.Save(baselinePath); err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}
		slog.Info("baseline saved", "path", baselinePath, "fingerprints", len(b.Fingerprints))
	}

	// Filter known findings if baseline provided
	var suppressed int
	if baselinePath != "" && !updateBaseline {
		b, err := baseline.Load(baselinePath)
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}
		references, suppressed = b.Filter(references)
		if suppressed > 0 {
			slog.Info("baseline applied", "suppressed", suppressed)
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
	switch outputFormat {
	case "json":
		reporter = report.NewJSONReporter(os.Stdout)
	case "sarif":
		reporter = report.NewSARIFReporter(os.Stdout)
	case "spectrehub":
		reporter = report.NewSpectreHubReporter(os.Stdout)
	default:
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
			FailOnMissing:      failOnMissing,
		},
		Summary:    results.Summary,
		Secrets:    results.Secrets,
		References: references,
	}

	if err := reporter.Generate(reportData); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Exit with timeout code if scan was interrupted
	if scanTimedOut {
		return newExitError(ExitNetwork, "scan timed out after %dm: %d/%d paths validated", scanTimeoutMins, validatedPaths, totalPaths)
	}

	// Policy evaluation
	if policyPath != "" {
		pol, polErr := policy.Load(policyPath)
		if polErr != nil {
			return newExitError(ExitBadArgs, "failed to load policy: %v", polErr)
		}

		// Build summary for policy evaluation
		paths := make([]string, 0, len(results.Secrets))
		for p := range results.Secrets {
			paths = append(paths, p)
		}
		polSummary := policy.ScanSummary{
			StatusCounts: map[string]int{
				"ok":               results.Summary.StatusOK,
				"missing":          results.Summary.StatusMissing,
				"access_denied":    results.Summary.StatusAccessDenied,
				"invalid":          results.Summary.StatusInvalid,
				"error":            results.Summary.StatusError,
				"needs_resolution": results.Summary.StatusNeedsResolution,
			},
			TotalSecrets: results.Summary.TotalReferences,
			StaleSecrets: results.Summary.StaleSecrets,
			Paths:        paths,
		}

		evalResult := pol.Evaluate(polSummary)

		if outputFormat == "json" {
			// Include policy results in JSON output
			polJSON, _ := json.Marshal(evalResult)
			slog.Info("policy evaluation", "result", string(polJSON))
		} else {
			// Print policy results as text
			fmt.Println("\nPolicy evaluation:")
			for _, r := range evalResult.Rules {
				icon := "✓"
				if r.Status == "fail" {
					icon = "✗"
				}
				fmt.Printf("  %s %s: %s\n", icon, r.Rule, r.Message)
			}
			if evalResult.Passed {
				fmt.Println("\nPolicy: PASSED")
			} else {
				fmt.Println("\nPolicy: FAILED")
			}
		}

		if !evalResult.Passed {
			return newExitError(ExitFindings, "policy evaluation failed")
		}
	}

	// Exit with error if requested and issues found
	if failOnMissing {
		issueCount := results.Summary.StatusMissing + results.Summary.StatusInvalid + results.Summary.StatusError
		if !ignoreDynamic {
			issueCount += results.Summary.StatusDynamic
		}
		if issueCount > 0 {
			return newExitError(ExitFindings, "found %d issue(s) in secret references", issueCount)
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

// applyConfig applies config file values for flags not explicitly set on the CLI.
func applyConfig(cmd *cobra.Command, cfg config.Config) {
	if cfg.VaultAddr != "" && !cmd.Flags().Changed("vault-addr") && vaultAddr == "" {
		vaultAddr = cfg.VaultAddr
	}
	if cfg.VaultNamespace != "" && !cmd.Flags().Changed("namespace") && vaultNamespace == "" {
		vaultNamespace = cfg.VaultNamespace
	}
	if cfg.Format != "" && !cmd.Flags().Changed("format") && !cmd.Flags().Changed("output") {
		outputFormat = cfg.Format
	} else if cfg.Output != "" && !cmd.Flags().Changed("format") && !cmd.Flags().Changed("output") {
		outputFormat = cfg.Output
	}
	if cfg.StaleDays != 0 && !cmd.Flags().Changed("stale-days") {
		staleDays = cfg.StaleDays
	}
	if cfg.Timeout != 0 && !cmd.Flags().Changed("timeout") {
		timeoutSeconds = cfg.Timeout
	}
	if cfg.DetectVars && !cmd.Flags().Changed("detect-vars") {
		detectVars = cfg.DetectVars
	}
	if cfg.FailOnMissing && !cmd.Flags().Changed("fail-on-missing") {
		failOnMissing = cfg.FailOnMissing
	}
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
