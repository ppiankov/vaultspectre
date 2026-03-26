package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/redact"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
)

// CheckStatus represents the result of a single doctor check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
	CheckWarn CheckStatus = "warn"
)

// CheckResult holds the result of a single doctor check.
type CheckResult struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message"`
}

// DoctorReport holds the full doctor output.
type DoctorReport struct {
	Checks []CheckResult `json:"checks"`
	Ready  bool          `json:"ready"`
}

var doctorFormat string

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check configuration, connectivity, and readiness",
	Long: `Runs diagnostic checks to verify that vaultspectre is properly configured
and can connect to the Vault instance.

Checks:
  - Config file: validates .vaultspectre.yaml if present
  - Vault address: ensures VAULT_ADDR or --vault-addr is set
  - Vault token: ensures VAULT_TOKEN or --token is set
  - Vault connectivity: attempts token lookup to verify connection
  - Token permissions: verifies the token can read secrets

Exit Codes:
  0 - All checks pass
  1 - One or more checks failed`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().StringVar(&doctorFormat, "format", "", "output format (json)")
	doctorCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	doctorCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	doctorCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace (Enterprise)")
	doctorCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Timeout in seconds for Vault API calls")
}

func runDoctor(_ *cobra.Command, _ []string) error {
	var checks []CheckResult
	hasFail := false

	// Check 1: Config file
	checks = append(checks, checkConfig())

	// Check 2: Vault address
	c := checkVaultAddr()
	checks = append(checks, c)
	if c.Status == CheckFail {
		hasFail = true
	}

	// Check 3: Vault token
	c = checkVaultToken()
	checks = append(checks, c)
	if c.Status == CheckFail {
		hasFail = true
	}

	// Check 4 & 5: Connectivity and permissions (only if addr+token present)
	if vaultAddr != "" && vaultToken != "" {
		c = checkVaultConnectivity()
		checks = append(checks, c)
		if c.Status == CheckFail {
			hasFail = true
		}

		if c.Status == CheckPass {
			c = checkTokenPermissions()
			checks = append(checks, c)
			if c.Status == CheckFail {
				hasFail = true
			}
		}
	}

	report := DoctorReport{
		Checks: checks,
		Ready:  !hasFail,
	}

	if doctorFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	// Text output
	for _, ch := range checks {
		var icon string
		switch ch.Status {
		case CheckFail:
			icon = "✗"
		case CheckWarn:
			icon = "!"
		default:
			icon = "✓"
		}
		fmt.Printf("  %s %s: %s\n", icon, ch.Name, ch.Message)
	}
	fmt.Println()
	if report.Ready {
		fmt.Println("vaultspectre is ready.")
	} else {
		fmt.Println("vaultspectre is not ready. Fix the issues above.")
	}

	if hasFail {
		return newExitError(ExitError, "doctor checks failed")
	}
	return nil
}

func checkConfig() CheckResult {
	cfg, source, err := config.Load()
	if err != nil {
		return CheckResult{Name: "config_file", Status: CheckFail, Message: fmt.Sprintf("invalid config: %v", err)}
	}
	if source == "" {
		return CheckResult{Name: "config_file", Status: CheckWarn, Message: "no config file found (run vaultspectre init to create one)"}
	}

	// Apply config values for subsequent checks
	if cfg.VaultAddr != "" && vaultAddr == "" {
		vaultAddr = cfg.VaultAddr
	}

	return CheckResult{Name: "config_file", Status: CheckPass, Message: fmt.Sprintf("loaded %s", source)}
}

func checkVaultAddr() CheckResult {
	if vaultAddr == "" {
		return CheckResult{Name: "vault_address", Status: CheckFail, Message: "not set (use --vault-addr or VAULT_ADDR)"}
	}
	return CheckResult{Name: "vault_address", Status: CheckPass, Message: vaultAddr}
}

func checkVaultToken() CheckResult {
	if vaultToken == "" {
		return CheckResult{Name: "vault_token", Status: CheckFail, Message: "not set (use --token or VAULT_TOKEN)"}
	}
	// Mask token for display using safe masking
	masked := redact.MaskToken(vaultToken)
	return CheckResult{Name: "vault_token", Status: CheckPass, Message: fmt.Sprintf("present (%s)", masked)}
}

func checkVaultConnectivity() CheckResult {
	client, err := vault.NewClient(vault.Config{
		Address:   vaultAddr,
		Token:     vaultToken,
		Namespace: vaultNamespace,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	})
	if err != nil {
		return CheckResult{Name: "vault_connectivity", Status: CheckFail, Message: fmt.Sprintf("client error: %v", err)}
	}

	// Try token lookup-self to verify connectivity + valid token
	start := time.Now()
	secret, err := client.GetClient().Auth().Token().LookupSelf()
	latency := time.Since(start).Round(time.Millisecond)

	if err != nil {
		return CheckResult{Name: "vault_connectivity", Status: CheckFail, Message: fmt.Sprintf("connection failed: %v", err)}
	}
	if secret == nil {
		return CheckResult{Name: "vault_connectivity", Status: CheckFail, Message: "token lookup returned nil"}
	}

	return CheckResult{Name: "vault_connectivity", Status: CheckPass, Message: fmt.Sprintf("connected (%s)", latency)}
}

func checkTokenPermissions() CheckResult {
	client, err := vault.NewClient(vault.Config{
		Address:   vaultAddr,
		Token:     vaultToken,
		Namespace: vaultNamespace,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	})
	if err != nil {
		return CheckResult{Name: "token_permissions", Status: CheckFail, Message: fmt.Sprintf("client error: %v", err)}
	}

	// Look up token policies
	secret, err := client.GetClient().Auth().Token().LookupSelf()
	if err != nil {
		return CheckResult{Name: "token_permissions", Status: CheckFail, Message: fmt.Sprintf("lookup failed: %v", err)}
	}

	policies, _ := secret.TokenPolicies()
	if len(policies) == 0 {
		return CheckResult{Name: "token_permissions", Status: CheckWarn, Message: "no policies found on token"}
	}

	return CheckResult{Name: "token_permissions", Status: CheckPass, Message: fmt.Sprintf("policies: %v", policies)}
}
