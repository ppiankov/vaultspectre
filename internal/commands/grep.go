package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/grep"
	"github.com/ppiankov/vaultspectre/internal/logging"
	"github.com/ppiankov/vaultspectre/internal/redact"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
)

var (
	grepPath          string
	grepKeyPattern    string
	grepValuePattern  string
	grepShowValues    bool
	grepDepth         int
	grepWorkers       int
	grepDryRun        bool
	grepFormat        string
	grepCaseSensitive bool
	grepVerifyFormat  bool
	grepNoRedact      bool
	grepStdin         bool
)

var grepCmd = &cobra.Command{
	Use:   "grep",
	Short: "Search Vault secrets by key or value pattern",
	Long: `Recursively walks a Vault KV tree and returns all paths whose secret
data contains keys (or values) matching the given pattern.

This is the inverse of 'scan': instead of code→Vault, grep searches Vault→keys.

Values are masked by default. Use --show-values to reveal them (with a warning).

Examples:
  # Find all paths with ClickHouse credentials
  vaultspectre grep --path kv/projects/ --key-pattern "CLICKHOUSE_*,STAT_CLICKHOUSE_*"

  # Find secrets containing a specific host IP
  vaultspectre grep --path kv/ --key-pattern "*" --value-pattern "10.200.4.206"

  # Dry run: list paths that would be read
  vaultspectre grep --path kv/projects/ --dry-run

Exit Codes:
  0 - Matches found
  3 - No matches found
  5 - Vault unreachable
  1 - Internal error
  2 - Invalid arguments`,
	RunE: runGrep,
}

func init() {
	grepCmd.Flags().StringVar(&grepPath, "path", "kv", "Vault path to search (e.g. kv/projects/)")
	grepCmd.Flags().StringVar(&grepKeyPattern, "key-pattern", "", "Comma-separated glob patterns for key names (e.g. CLICKHOUSE_*)")
	grepCmd.Flags().StringVar(&grepValuePattern, "value-pattern", "", "Comma-separated patterns for value content")
	grepCmd.Flags().BoolVar(&grepShowValues, "show-values", false, "Show secret values in output (WARNING: plaintext)")
	grepCmd.Flags().IntVar(&grepDepth, "depth", 0, "Max recursion depth (0 = unlimited)")
	grepCmd.Flags().IntVar(&grepWorkers, "workers", 10, "Number of concurrent Vault readers")
	grepCmd.Flags().BoolVar(&grepDryRun, "dry-run", false, "List paths that would be read without reading them")
	grepCmd.Flags().StringVar(&grepFormat, "format", "text", "Output format: text, json")
	grepCmd.Flags().BoolVar(&grepCaseSensitive, "case-sensitive", false, "Case-sensitive pattern matching")
	grepCmd.Flags().BoolVar(&grepVerifyFormat, "verify-format", true, "Verify credential value formats (default on)")
	grepCmd.Flags().BoolVar(&grepNoRedact, "no-redact", false, "Show raw values without redaction (TTY only, never with --format json)")
	grepCmd.Flags().BoolVar(&grepStdin, "stdin", false, "Read Vault paths from stdin (one per line) instead of walking")
	grepCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	grepCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	grepCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace (Enterprise)")
	grepCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Timeout in seconds for Vault API calls")
	grepCmd.Flags().BoolVar(&verbose, "verbose", false, "Show detailed information")
	grepCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	grepCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	grepCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
	grepCmd.Flags().StringVar(&k8sRole, "k8s-role", "", "Kubernetes auth role name")
	grepCmd.Flags().StringVar(&k8sJWTPath, "k8s-jwt-path", "", "Path to Kubernetes JWT file")
}

func runGrep(cmd *cobra.Command, _ []string) error {
	logging.Init(verbose)

	// Load config for vault addr/token fallback
	cfg, cfgSource, err := config.Load()
	if err != nil {
		slog.Warn("failed to load config file", "error", err)
	}
	if cfgSource != "" {
		slog.Info("loaded config file", "path", cfgSource)
		if cfg.VaultAddr != "" && !cmd.Flags().Changed("vault-addr") && vaultAddr == "" {
			vaultAddr = cfg.VaultAddr
		}
	}

	if vaultAddr == "" {
		return newExitError(ExitBadArgs, "vault address is required: set --vault-addr or VAULT_ADDR")
	}
	if vault.AuthMethod(authMethod) == vault.AuthToken && vaultToken == "" {
		return newExitError(ExitBadArgs, "vault token is required: set --token or VAULT_TOKEN")
	}
	if grepKeyPattern == "" && grepValuePattern == "" && !grepDryRun {
		return newExitError(ExitBadArgs, "at least one of --key-pattern or --value-pattern is required (or use --dry-run)")
	}

	client, err := vault.NewClient(vault.Config{
		Address:   vaultAddr,
		Token:     vaultToken,
		Namespace: vaultNamespace,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	})
	if err != nil {
		return newExitError(ExitNetwork, "failed to create Vault client: %v", err)
	}

	if err := vault.Authenticate(client.GetClient(), vault.AuthConfig{
		Method:     vault.AuthMethod(authMethod),
		Token:      vaultToken,
		RoleID:     roleID,
		SecretID:   secretID,
		K8sRole:    k8sRole,
		K8sJWTPath: k8sJWTPath,
	}); err != nil {
		return newExitError(ExitBadArgs, "authentication failed: %v", err)
	}

	matcher := grep.NewMatcher(grepKeyPattern, grepValuePattern, grepCaseSensitive)
	walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
		ShowValues:   grepShowValues,
		MaxDepth:     grepDepth,
		Workers:      grepWorkers,
		DryRun:       grepDryRun,
		VerifyFormat: grepVerifyFormat,
	})

	// Enforce redaction rules
	if grepNoRedact {
		if grepFormat == "json" {
			return newExitError(ExitBadArgs, "cannot disable redaction for structured output (--no-redact incompatible with --format json)")
		}
		if !redact.IsTTY() {
			fmt.Fprintln(os.Stderr, "WARNING: --no-redact ignored (stdout is not a terminal, redaction forced)")
			grepNoRedact = false
		}
	}

	if grepShowValues && grepNoRedact {
		fmt.Fprintln(os.Stderr, "WARNING: raw secret values will be displayed")
	} else if grepShowValues {
		fmt.Fprintln(os.Stderr, "NOTE: secret values are redacted (use --no-redact on a terminal for raw values)")
	}

	// Validate stdin vs path
	if grepStdin && cmd.Flags().Changed("path") {
		return newExitError(ExitBadArgs, "--stdin and --path are mutually exclusive")
	}

	slog.Info("searching vault", "path", grepPath, "key_pattern", grepKeyPattern)

	var result *grep.GrepResult
	if grepStdin {
		paths, scanErr := readStdinPaths()
		if scanErr != nil {
			return scanErr
		}
		if len(paths) == 0 {
			return newExitError(ExitNotFound, "no paths provided on stdin")
		}
		result, err = walker.WalkPaths(paths)
	} else {
		result, err = walker.Walk(grepPath)
	}
	if err != nil {
		return newExitError(ExitNetwork, "vault search failed: %v", err)
	}

	// Redact values in results
	rd := redact.New()
	redactValues(result, rd, grepFormat == "json" || !grepNoRedact)

	// Output
	if grepFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result); encErr != nil {
			return fmt.Errorf("failed to encode JSON: %w", encErr)
		}
	} else {
		printGrepText(result, grepDryRun)
	}

	// Exit code
	if result.MatchCount == 0 {
		if grepDryRun {
			return nil
		}
		return newExitError(ExitNotFound, "no matches found")
	}
	return nil
}

func printGrepText(result *grep.GrepResult, dryRun bool) {
	if dryRun {
		for _, m := range result.Matches {
			fmt.Println(m.Path)
		}
		fmt.Fprintf(os.Stderr, "\n%d paths would be read\n", len(result.Matches))
		return
	}

	for _, m := range result.Matches {
		fmt.Println(m.Path)
		for _, k := range m.Keys {
			if k.Value != "" {
				valDisplay := k.Value
				if len(valDisplay) > 80 {
					valDisplay = valDisplay[:77] + "..."
				}
				typeHint := ""
				if k.Type != "string" {
					typeHint = fmt.Sprintf(" (%s)", k.Type)
				}
				fmt.Printf("  %-30s = %s%s\n", k.Name, valDisplay, typeHint)
			} else {
				typeHint := ""
				if k.Type != "string" {
					typeHint = fmt.Sprintf(" (%s)", k.Type)
				}
				fmt.Printf("  %-30s = ***%s\n", k.Name, typeHint)
			}
		}
		if m.FormatIssues != "" {
			fmt.Printf("  FORMAT ERROR: %s\n", m.FormatIssues)
		}
		fmt.Println()
	}

	// Summary
	parts := []string{
		fmt.Sprintf("%d paths matched", result.MatchCount),
		fmt.Sprintf("%d paths scanned", result.TotalScanned),
	}
	if result.TotalSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped (permission denied)", result.TotalSkipped))
	}
	fmt.Fprintln(os.Stderr, strings.Join(parts, ", "))
}

// readStdinPaths reads Vault paths from stdin, one per line.
func readStdinPaths() ([]string, error) {
	var paths []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			paths = append(paths, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}
	return paths, nil
}

// redactValues redacts secret values in grep results in-place.
// When shouldRedact is true, sensitive values are masked.
// JSON output always redacts; text output redacts unless --no-redact on TTY.
func redactValues(result *grep.GrepResult, rd redact.Redactor, shouldRedact bool) {
	if !shouldRedact {
		return
	}
	for i := range result.Matches {
		for j := range result.Matches[i].Keys {
			k := &result.Matches[i].Keys[j]
			if k.Value == "" {
				continue
			}
			// Always redact by key name (PASSWORD, TOKEN, etc.)
			if redact.IsSensitiveKey(k.Name) {
				k.Value = redact.RedactByKeyName(k.Name, k.Value)
				continue
			}
			// Redact by value pattern (vault tokens, JWTs, DSNs, etc.)
			k.Value = rd.Redact(k.Value)
		}
	}
}
