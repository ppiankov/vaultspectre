package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/audit"
	"github.com/ppiankov/vaultspectre/internal/report"
	"github.com/ppiankov/vaultspectre/internal/scanner"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
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

	scanCmd.MarkFlagRequired("vault-addr")
	scanCmd.MarkFlagRequired("token")
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

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
		// Skip validation for paths already marked as dynamic
		if references[i].Status == "dynamic" {
			continue
		}

		status, err := validator.ValidatePath(references[i].Path)
		if err != nil {
			// Non-fatal, record the error in status
			references[i].Status = "error"
			references[i].ErrorMsg = err.Error()
		} else {
			references[i].Status = status
		}

		// Check for staleness if enabled
		if staleDays > 0 && status == "ok" {
			isStale, lastAccessed, err := validator.CheckStaleness(references[i].Path, staleDays)
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
