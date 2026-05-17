package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/eso"
	"github.com/ppiankov/vaultspectre/internal/report"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
)

var (
	esoDir            string
	esoHelmValues     []string
	esoManifests      []string
	esoEnvValue       string
	esoVaultListMount string
	esoVaultMount     string
	esoFailOnFindings bool
)

var esoCmd = &cobra.Command{
	Use:   "eso",
	Short: "Audit ExternalSecret manifests against Vault and K8s consumers",
	Long: `Cross-reference External Secrets Operator manifests, live Vault state,
and K8s/Helm workload manifests to find ESO misconfigurations.

Finding classes:
  ESO_VAULT_PATH_MISSING            — ESO references Vault path that does not exist
  ESO_VAULT_PROPERTY_MISSING        — Vault path exists; referenced property absent
  ESO_VAULT_ORPHANED_PROPERTY       — Vault has a property no ExternalSecret pulls (--vault-list-mount)
  ESO_K8S_KEY_UNUSED                — ExternalSecret produces a Secret key no consumer references
  ESO_K8S_KEY_MISSING               — Consumer references a Secret key no ExternalSecret produces
  ESO_TARGET_NAME_MISSING           — ExternalSecret has no spec.target.name
  ESO_DUPLICATE_KEY                 — Same secretKey produced by multiple ExternalSecrets
  ESO_ENV_PLACEHOLDER_UNSUBSTITUTED — Literal <ENV> placeholder remains in remoteRef.key

Exit Codes:
  0 - Clean (no findings, or no error-severity findings when --fail-on-findings)
  2 - Invalid arguments
  5 - Network error (Vault unreachable)
  6 - Findings detected (requires --fail-on-findings)

Examples:
  # Offline: validate manifests structure only
  vaultspectre eso --eso-dir ./manifests

  # With Vault: validate paths and properties
  vaultspectre eso --eso-dir ./manifests --vault-addr $VAULT_ADDR --token $VAULT_TOKEN

  # With consumer cross-check
  vaultspectre eso --eso-dir ./manifests --helm-values values-prod.yaml --manifests ./k8s/

  # Substitute <ENV> placeholder before Vault lookup
  vaultspectre eso --eso-dir ./manifests --env prod --vault-addr $VAULT_ADDR --token $VAULT_TOKEN

  # CI mode: fail on error findings, JSON output
  vaultspectre eso --eso-dir ./manifests --vault-addr $VAULT_ADDR --token $VAULT_TOKEN \
    --fail-on-findings --format json`,
	RunE: runEso,
}

func init() {
	esoCmd.Flags().StringVar(&esoDir, "eso-dir", "", "Directory containing ExternalSecret manifests (required)")
	esoCmd.Flags().StringArrayVar(&esoHelmValues, "helm-values", []string{}, "Helm values files to scan for consumers (repeatable)")
	esoCmd.Flags().StringArrayVar(&esoManifests, "manifests", []string{}, "K8s manifest paths/dirs for consumer scan (repeatable)")
	esoCmd.Flags().StringVar(&esoEnvValue, "env", "", "Substitute this value for <ENV> placeholder in Vault paths")
	esoCmd.Flags().StringVar(&esoVaultListMount, "vault-list-mount", "", "Vault mount to list for orphaned property detection (e.g. secret)")
	esoCmd.Flags().StringVar(&esoVaultMount, "vault-mount", "", "KV mount prefix for ExternalSecrets that use secretStoreRef (e.g. kv)")
	esoCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	esoCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	esoCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	esoCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	esoCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
	esoCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json, sarif, spectrehub")
	esoCmd.Flags().BoolVar(&esoFailOnFindings, "fail-on-findings", false, "Exit 6 if any error-severity finding is present")
	esoCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
}

func runEso(_ *cobra.Command, _ []string) error {
	if esoDir == "" {
		return newExitError(ExitBadArgs, "--eso-dir is required")
	}

	// 1. Parse ExternalSecret manifests
	secrets, err := eso.ParseDirectory(esoDir)
	if err != nil {
		return newExitError(ExitBadArgs, "parse ESO manifests: %v", err)
	}

	// 2. Substitute <ENV> placeholder when --env is provided
	if esoEnvValue != "" {
		secrets = substituteEnvInSecrets(secrets, "<ENV>", esoEnvValue)
	}

	// 3. Scan K8s / Helm consumers
	var consumers *eso.ConsumerScanResult
	var consumerPaths []string
	consumerPaths = append(consumerPaths, esoHelmValues...)
	consumerPaths = append(consumerPaths, esoManifests...)
	if len(consumerPaths) > 0 {
		consumers, err = eso.ScanConsumers(consumerPaths)
		if err != nil {
			return fmt.Errorf("scan consumers: %w", err)
		}
	}

	// 4. Build Vault validator (optional — skipped when no vault-addr)
	var validator *vault.Validator
	if vaultAddr != "" {
		if vaultToken == "" && authMethod == "token" {
			return newExitError(ExitBadArgs, "--token or VAULT_TOKEN is required when --vault-addr is set")
		}
		vaultClient, clientErr := vault.NewClient(vault.Config{
			Address: vaultAddr,
			Token:   vaultToken,
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		})
		if clientErr != nil {
			return newExitError(ExitNetwork, "failed to create Vault client: %v", clientErr)
		}
		if authErr := vault.Authenticate(vaultClient.GetClient(), vault.AuthConfig{
			Method:   vault.AuthMethod(authMethod),
			Token:    vaultToken,
			RoleID:   roleID,
			SecretID: secretID,
		}); authErr != nil {
			return newExitError(ExitBadArgs, "vault authentication failed: %v", authErr)
		}
		validator = vault.NewValidator(vaultClient)
	}

	// 5. Run audit
	ctx := context.Background()
	findings, auditErr := eso.Audit(ctx, eso.AuditInput{
		ExternalSecrets:   secrets,
		Consumers:         consumers,
		Validator:         validator,
		VaultListMount:    esoVaultListMount,
		DefaultVaultMount: esoVaultMount,
		// When --env was set, <ENV> is already substituted; use a non-matching sentinel
		// so the placeholder check doesn't fire on unrelated angle-bracket tokens.
		EnvPlaceholder: placeholderForAudit(),
	})
	if auditErr != nil {
		if strings.Contains(auditErr.Error(), "network error") || strings.Contains(auditErr.Error(), "retry exhausted") {
			return newExitError(ExitNetwork, "%v", auditErr)
		}
		return auditErr
	}

	// 6. Generate report
	reportData := report.ESOReportData{
		Tool:      "vaultspectre",
		Version:   Version,
		Timestamp: time.Now(),
		ESODir:    esoDir,
		Findings:  findings,
	}
	var reporter interface {
		Generate(report.ESOReportData) error
	}
	switch outputFormat {
	case "json":
		reporter = report.NewESOJSONReporter(os.Stdout)
	case "sarif":
		reporter = report.NewESOSARIFReporter(os.Stdout)
	case "spectrehub":
		reporter = report.NewESOSpectreHubReporter(os.Stdout)
	default:
		reporter = report.NewESOTextReporter(os.Stdout)
	}
	if genErr := reporter.Generate(reportData); genErr != nil {
		return fmt.Errorf("generate report: %w", genErr)
	}

	// 7. Exit code
	if esoFailOnFindings {
		for _, f := range findings {
			if f.Severity == eso.SeverityError {
				return newExitError(ExitFindings, "ESO error-severity findings detected")
			}
		}
	}
	return nil
}

// substituteEnvInSecrets returns a copy of secrets with placeholder replaced by value in all Vault paths.
func substituteEnvInSecrets(secrets []*eso.ExternalSecret, placeholder, value string) []*eso.ExternalSecret {
	result := make([]*eso.ExternalSecret, len(secrets))
	for i, es := range secrets {
		copy := *es
		copy.Data = make([]eso.DataEntry, len(es.Data))
		for j, d := range es.Data {
			copy.Data[j] = d
			copy.Data[j].RemoteRefKey = strings.ReplaceAll(d.RemoteRefKey, placeholder, value)
		}
		copy.DataFrom = make([]eso.DataFromEntry, len(es.DataFrom))
		for j, df := range es.DataFrom {
			copy.DataFrom[j] = df
			copy.DataFrom[j].RemoteRefKey = strings.ReplaceAll(df.RemoteRefKey, placeholder, value)
		}
		result[i] = &copy
	}
	return result
}

// placeholderForAudit returns the placeholder string to pass to Audit.
// When --env substitution was applied, paths no longer contain <ENV>, so the
// default placeholder has no effect. When --env is not set, return default <ENV>.
func placeholderForAudit() string {
	if esoEnvValue != "" {
		// Substitution already happened; use an unmatchable sentinel.
		return "\x00ESO_ENV_PLACEHOLDER\x00"
	}
	return "<ENV>"
}
