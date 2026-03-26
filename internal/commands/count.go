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
	countPath     string
	countDepth    int
	countByDepth  bool
	countByPrefix int
	countFormat   string
)

// CountResult holds the output for --format json.
type CountResult struct {
	Total   int          `json:"total"`
	Skipped int          `json:"skipped"`
	Groups  []CountGroup `json:"groups,omitempty"`
}

// CountGroup holds a prefix/depth group.
type CountGroup struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

var countCmd = &cobra.Command{
	Use:   "count [path]",
	Short: "Count secrets in a Vault tree",
	Long: `Quick statistics about a Vault tree: total secrets, grouped by depth
or path prefix. Like du -sh for Vault.

No secret data is read — list operations only.

Examples:
  vaultspectre count kv/
  vaultspectre count kv/ --by-depth
  vaultspectre count kv/ --by-prefix 3
  vaultspectre count kv/ --format json

Exit Codes:
  0 - Counted successfully
  5 - Vault unreachable`,
	RunE: runCount,
}

func init() {
	countCmd.Flags().StringVar(&countPath, "path", "kv", "Vault path to count")
	countCmd.Flags().IntVar(&countDepth, "depth", 0, "Max recursion depth (0 = unlimited)")
	countCmd.Flags().BoolVar(&countByDepth, "by-depth", false, "Group counts by depth level")
	countCmd.Flags().IntVar(&countByPrefix, "by-prefix", 0, "Group counts by first N path segments")
	countCmd.Flags().StringVar(&countFormat, "format", "text", "Output format: text, json")
	countCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	countCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	countCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace")
	countCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
	countCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	countCmd.Flags().StringVar(&authMethod, "auth-method", "token", "Auth method: token, approle, kubernetes")
	countCmd.Flags().StringVar(&roleID, "role-id", os.Getenv("VAULT_ROLE_ID"), "AppRole role ID")
	countCmd.Flags().StringVar(&secretID, "secret-id", os.Getenv("VAULT_SECRET_ID"), "AppRole secret ID")
}

func runCount(cmd *cobra.Command, args []string) error {
	logging.Init(verbose)

	if len(args) > 0 && !cmd.Flags().Changed("path") {
		countPath = args[0]
	}

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
		Method:   vault.AuthMethod(authMethod),
		Token:    vaultToken,
		RoleID:   roleID,
		SecretID: secretID,
	}); err != nil {
		return newExitError(ExitBadArgs, "authentication failed: %v", err)
	}

	matcher := grep.NewMatcher("", "", false)
	walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
		MaxDepth: countDepth,
		Workers:  10,
		DryRun:   true,
	})

	result, err := walker.Walk(countPath)
	if err != nil {
		return newExitError(ExitNetwork, "vault list failed: %v", err)
	}

	paths := make([]string, len(result.Matches))
	for i, m := range result.Matches {
		paths[i] = m.Path
	}

	countResult := &CountResult{
		Total:   len(paths),
		Skipped: result.TotalSkipped,
	}

	if countByDepth {
		countResult.Groups = groupByDepthLevel(paths)
	} else if countByPrefix > 0 {
		countResult.Groups = groupByPrefixN(paths, countByPrefix)
	}

	if countFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(countResult)
	}

	// Text output
	if countByDepth || countByPrefix > 0 {
		for _, g := range countResult.Groups {
			fmt.Printf("%6d  %s\n", g.Count, g.Key)
		}
		fmt.Println()
	}
	fmt.Printf("%d secrets total", countResult.Total)
	if countResult.Skipped > 0 {
		fmt.Printf(", %d skipped (permission denied)", countResult.Skipped)
	}
	fmt.Println()

	return nil
}

func groupByDepthLevel(paths []string) []CountGroup {
	counts := make(map[int]int)
	for _, p := range paths {
		depth := strings.Count(p, "/")
		counts[depth]++
	}

	var groups []CountGroup
	for d, c := range counts {
		groups = append(groups, CountGroup{Key: fmt.Sprintf("depth-%d", d), Count: c})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
	return groups
}

func groupByPrefixN(paths []string, n int) []CountGroup {
	counts := make(map[string]int)
	for _, p := range paths {
		parts := strings.Split(p, "/")
		end := n
		if end > len(parts) {
			end = len(parts)
		}
		prefix := strings.Join(parts[:end], "/") + "/"
		counts[prefix]++
	}

	var groups []CountGroup
	for prefix, c := range counts {
		groups = append(groups, CountGroup{Key: prefix, Count: c})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
	return groups
}
