package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/grep"
	"github.com/ppiankov/vaultspectre/internal/logging"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
)

var (
	lsPath   string
	lsDepth  int
	lsTree   bool
	lsCount  bool
	lsFormat string
)

// LsResult holds the output for --format json.
type LsResult struct {
	Paths        []string `json:"paths"`
	TotalSecrets int      `json:"total_secrets"`
	TotalSkipped int      `json:"total_skipped"`
}

var lsCmd = &cobra.Command{
	Use:   "ls [path]",
	Short: "List Vault secret paths recursively",
	Long: `Recursively lists all secret paths in a Vault KV tree.
No secret data is read — list operations only.

This is the discovery entry point: explore your Vault when you
don't know what you're looking for yet.

Output is one path per line (pipeable to grep --stdin).

Examples:
  vaultspectre ls kv/projects/
  vaultspectre ls kv/ --depth 2
  vaultspectre ls kv/ --tree
  vaultspectre ls kv/ --count
  vaultspectre ls kv/ --format json

Exit Codes:
  0 - Paths found
  3 - Empty tree (no secrets)
  5 - Vault unreachable`,
	RunE: runLs,
}

func init() {
	lsCmd.Flags().StringVar(&lsPath, "path", "kv", "Vault path to list")
	lsCmd.Flags().IntVar(&lsDepth, "depth", 0, "Max recursion depth (0 = unlimited)")
	lsCmd.Flags().BoolVar(&lsTree, "tree", false, "Show indented tree hierarchy")
	lsCmd.Flags().BoolVar(&lsCount, "count", false, "Show secret count per subtree")
	lsCmd.Flags().StringVar(&lsFormat, "format", "text", "Output format: text, json")
	lsCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	lsCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	lsCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace")
	lsCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
	lsCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	lsCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	lsCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	lsCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
	lsCmd.Flags().StringVar(&k8sRole, "k8s-role", "", "Kubernetes auth role name")
	lsCmd.Flags().StringVar(&k8sJWTPath, "k8s-jwt-path", "", "Path to Kubernetes JWT file")
}

func runLs(cmd *cobra.Command, args []string) error {
	logging.Init(verbose)

	// Accept path as positional arg
	if len(args) > 0 && !cmd.Flags().Changed("path") {
		lsPath = args[0]
	}

	// Load config
	cfg, cfgSource, _ := config.Load()
	if cfgSource != "" {
		if cfg.VaultAddr != "" && !cmd.Flags().Changed("vault-addr") && vaultAddr == "" {
			vaultAddr = cfg.VaultAddr
		}
	}

	if vaultAddr == "" {
		return newExitError(ExitBadArgs, "vault address is required")
	}
	if vault.AuthMethod(authMethod) == vault.AuthToken && vaultToken == "" {
		return newExitError(ExitBadArgs, "vault token is required")
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

	// Use walker in dry-run mode (list only, no secret reads)
	matcher := grep.NewMatcher("", "", false)
	walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
		MaxDepth: lsDepth,
		Workers:  10,
		DryRun:   true,
	})

	result, err := walker.Walk(lsPath)
	if err != nil {
		return newExitError(ExitNetwork, "vault list failed: %v", err)
	}

	// Extract and sort paths
	paths := make([]string, len(result.Matches))
	for i, m := range result.Matches {
		paths[i] = m.Path
	}
	sort.Strings(paths)

	if len(paths) == 0 {
		return newExitError(ExitNotFound, "no secrets found at %s", lsPath)
	}

	// Output
	if lsFormat == "json" {
		lsResult := LsResult{
			Paths:        paths,
			TotalSecrets: len(paths),
			TotalSkipped: result.TotalSkipped,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(lsResult)
	}

	if lsTree {
		printTree(paths, lsPath)
	} else if lsCount {
		printCount(paths)
	} else {
		for _, p := range paths {
			fmt.Println(p)
		}
	}

	fmt.Fprintf(os.Stderr, "%d secrets", len(paths))
	if result.TotalSkipped > 0 {
		fmt.Fprintf(os.Stderr, ", %d skipped (permission denied)", result.TotalSkipped)
	}
	fmt.Fprintln(os.Stderr)

	return nil
}

func printTree(paths []string, base string) {
	base = strings.TrimSuffix(base, "/")
	for _, p := range paths {
		rel := strings.TrimPrefix(p, base+"/")
		if rel == p {
			rel = strings.TrimPrefix(p, base)
		}
		depth := strings.Count(rel, "/")
		indent := strings.Repeat("  ", depth)
		name := rel
		if idx := strings.LastIndex(rel, "/"); idx >= 0 {
			name = rel[idx+1:]
		}
		fmt.Printf("%s%s\n", indent, name)
	}
}

func printCount(paths []string) {
	counts := make(map[string]int)
	for _, p := range paths {
		parts := strings.Split(p, "/")
		// Count at each prefix depth
		for i := 1; i <= len(parts)-1; i++ {
			prefix := strings.Join(parts[:i], "/") + "/"
			counts[prefix]++
		}
	}

	// Sort prefixes
	prefixes := make([]string, 0, len(counts))
	for p := range counts {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		fmt.Printf("%6d  %s\n", counts[prefix], prefix)
	}
}
