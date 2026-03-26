package commands

import (
	"os"

	"github.com/spf13/cobra"
)

// auditCmd is the SpectreHub-compatible entry point.
// SpectreHub invokes tools as: <binary> audit --format json
// This wraps scan with spectrehub-compatible defaults and exit code mapping.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run scan for SpectreHub integration",
	Long: `SpectreHub-compatible audit command. Equivalent to scan with
spectrehub output format and SpectreHub exit code conventions.

SpectreHub invokes this as: vaultspectre audit --format json

Exit Codes (SpectreHub convention):
  0 - Success (no findings)
  1 - Findings detected (policy violation)
  2 - Invalid arguments
  3 - Runtime error (network, Vault unreachable)`,
	RunE: runAudit,
}

func init() {
	// Mirror all scan flags
	auditCmd.Flags().StringVar(&repoPath, "repo", ".", "Path to repository to scan")
	auditCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	auditCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	auditCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace (Enterprise)")
	auditCmd.Flags().StringVar(&outputFormat, "format", "spectrehub", "Output format (default: spectrehub)")
	auditCmd.Flags().IntVar(&staleDays, "stale-days", 90, "Stale secret threshold")
	auditCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
	auditCmd.Flags().IntVar(&scanTimeoutMins, "scan-timeout", 10, "Global scan timeout in minutes")
	auditCmd.Flags().BoolVar(&detectVars, "detect-vars", false, "Auto-detect variables")
	auditCmd.Flags().StringArrayVar(&varFlags, "var", []string{}, "Set variable value")
	auditCmd.Flags().StringVar(&varFile, "var-file", "", "Path to YAML variable file")
	auditCmd.Flags().StringVar(&excludeFlag, "exclude", "", "Comma-separated exclude patterns")
	auditCmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline file")
	auditCmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy file")
	auditCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	auditCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	auditCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
	auditCmd.Flags().StringVar(&k8sRole, "k8s-role", "", "Kubernetes auth role name")
	auditCmd.Flags().StringVar(&k8sJWTPath, "k8s-jwt-path", "", "Path to Kubernetes JWT file")
	auditCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")

	// Flags that audit always sets
	auditCmd.Flags().BoolVar(&failOnMissing, "fail-on-missing", true, "Exit with findings code on issues (default true for audit)")
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Run scan with spectrehub defaults
	err := runScan(cmd, args)
	if err == nil {
		return nil
	}

	// Map exit codes to SpectreHub convention:
	// SpectreHub: 0=success, 1=policy/findings, 2=invalid, 3=runtime
	// vaultspectre: 0=success, 1=error, 2=badargs, 5=network, 6=findings
	exitCode := ExitCodeFromError(err)
	switch exitCode {
	case ExitFindings:
		// 6 → 1 (findings = policy violation in SpectreHub terms)
		return &ExitCodeError{Code: 1, Err: err}
	case ExitBadArgs:
		// 2 → 2 (already matches)
		return err
	case ExitNetwork:
		// 5 → 3 (runtime error)
		return &ExitCodeError{Code: 3, Err: err}
	case ExitError:
		// 1 → 3 (runtime error)
		return &ExitCodeError{Code: 3, Err: err}
	default:
		return err
	}
}
