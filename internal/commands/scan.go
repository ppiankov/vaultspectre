package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/audit"
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
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan repository for Vault secret references and validate them",
	Long: `Scans the specified repository for Vault secret path references
and validates each path against the configured Vault instance.

Generates a report of missing, stale, and invalid secret paths.`,
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
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

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
	if outputFormat == "text" {
		fmt.Fprintf(os.Stderr, "Scanning repository: %s\n", repoPath)
	}

	references, err := s.Scan()
	if err != nil {
		return fmt.Errorf("failed to scan repository: %w", err)
	}

	if outputFormat == "text" {
		fmt.Fprintf(os.Stderr, "Found %d secret references\n", len(references))
	}

	// ROOTOPS: Resolve variables before validation
	variables, err := loadVariables(varFlags, varFile, detectVars, repoPath)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
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
		fmt.Fprintf(os.Stderr, "\nWARNING: Some variables could not be resolved:\n")
		for varName := range missingVarsMap {
			fmt.Fprintf(os.Stderr, "  - %s\n", varName)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	resolvedCount := countResolvedRefs(references)
	unresolvedCount := countUnresolvedRefs(references)

	if outputFormat == "text" {
		if resolvedCount > 0 {
			fmt.Fprintf(os.Stderr, "Resolved %d paths with variables\n", resolvedCount)
		}
		if unresolvedCount > 0 {
			fmt.Fprintf(os.Stderr, "WARNING: %d paths remain unresolved\n", unresolvedCount)
		}
		fmt.Fprintf(os.Stderr, "Connecting to Vault: %s\n", vaultAddr)
	}

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
		if outputFormat == "text" {
			fmt.Fprintf(os.Stderr, "Parsing audit log: %s\n", auditLogPath)
		}

		auditParser := audit.NewParser(auditLogPath)
		accessMap, err := auditParser.Parse(auditWindowDays)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse audit log: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing with metadata-only staleness detection...\n")
		} else {
			auditAnalyzer = audit.NewAnalyzer(accessMap)
			if outputFormat == "text" {
				fmt.Fprintf(os.Stderr, "Found %d unique paths in audit log\n", auditAnalyzer.GetTotalPaths())
			}
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
	if outputFormat == "text" {
		fmt.Fprintf(os.Stderr, "Validating secret paths...\n")
	}

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

	// Generate report
	var reporter report.Reporter
	if outputFormat == "json" {
		reporter = report.NewJSONReporter(os.Stdout)
	} else {
		reporter = report.NewTextReporter(os.Stdout)
	}

	reportData := report.Data{
		Tool:      "vaultspectre",
		Version:   version,
		Timestamp: startTime,
		Config: report.Config{
			VaultAddr:          vaultAddr,
			RepoPath:           repoPath,
			StaleThresholdDays: staleDays,
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
func loadVariables(varFlags []string, varFile string, detectVars bool, repoPath string) (map[string]string, error) {
	variables := make(map[string]string)

	// Load from --var flags
	for _, v := range varFlags {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --var format: %s (expected key=value)", v)
		}
		variables[parts[0]] = parts[1]
	}

	// Load from --var-file
	if varFile != "" {
		fileVars, err := loadVarFile(varFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load var file: %w", err)
		}
		// Merge file vars (CLI flags take precedence)
		for k, v := range fileVars {
			if _, exists := variables[k]; !exists {
				variables[k] = v
			}
		}
	}

	// Auto-detect from Ansible inventory (opt-in)
	if detectVars {
		detectedVars, err := detectAnsibleVariables(repoPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: auto-detection failed: %v\n", err)
		} else {
			// Merge detected vars (explicit flags take precedence)
			for k, v := range detectedVars {
				if _, exists := variables[k]; !exists {
					variables[k] = v
				}
			}
			fmt.Fprintf(os.Stderr, "Auto-detected %d variables from Ansible inventory\n", len(detectedVars))
		}
	}

	return variables, nil
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
func detectAnsibleVariables(repoPath string) (map[string]string, error) {
	variables := make(map[string]string)

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

			// Merge variables (first occurrence wins)
			for key, value := range vars {
				if _, exists := variables[key]; !exists {
					variables[key] = value
				}
			}
		}
	}

	return variables, nil
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
