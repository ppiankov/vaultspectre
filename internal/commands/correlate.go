package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ppiankov/vaultspectre/internal/grep"
	"github.com/spf13/cobra"
)

// UserClassification categorizes a CH user based on Vault + CH correlation.
type UserClassification string

const (
	ClassActiveWithVault UserClassification = "active_with_vault"
	ClassActiveNoVault   UserClassification = "active_no_vault"
	ClassInactiveVault   UserClassification = "inactive_with_vault"
	ClassInactiveNoVault UserClassification = "inactive_no_vault"
	ClassVaultOnly       UserClassification = "vault_only"
)

// CorrelatedUser holds the correlation result for a single CH user.
type CorrelatedUser struct {
	Username       string             `json:"username"`
	Classification UserClassification `json:"classification"`
	QueryCount     int64              `json:"query_count"`
	VaultPaths     []string           `json:"vault_paths,omitempty"`
	LastSeen       string             `json:"last_seen,omitempty"`
}

// CorrelateResult holds the full correlation output.
type CorrelateResult struct {
	Users   []CorrelatedUser `json:"users"`
	Summary CorrelateSummary `json:"summary"`
}

// CorrelateSummary holds counts per classification.
type CorrelateSummary struct {
	ActiveWithVault int `json:"active_with_vault"`
	ActiveNoVault   int `json:"active_no_vault"`
	InactiveVault   int `json:"inactive_with_vault"`
	InactiveNoVault int `json:"inactive_no_vault"`
	VaultOnly       int `json:"vault_only"`
}

// ClickSpectreUser is the minimal structure expected from clickspectre JSON.
type ClickSpectreUser struct {
	Username   string `json:"username"`
	QueryCount int64  `json:"query_count"`
	LastSeen   string `json:"last_seen"`
	IsActive   bool   `json:"is_active"`
}

// ClickSpectreReport is the expected format from clickspectre --by-user JSON.
type ClickSpectreReport struct {
	Users []ClickSpectreUser `json:"users"`
}

var (
	correlateVaultFile string
	correlateCHFile    string
	correlateFormat    string
	correlateKeyField  string
)

var correlateCmd = &cobra.Command{
	Use:   "correlate",
	Short: "Correlate Vault secrets with ClickHouse user activity",
	Long: `Joins vaultspectre grep output (Vault paths with CH credentials) with
clickspectre user activity data to classify each CH user:

  - active_with_vault:  queries + Vault path (healthy)
  - active_no_vault:    queries but no Vault path (hardcoded creds?)
  - inactive_with_vault: Vault path exists, zero queries (cleanup candidate)
  - inactive_no_vault:  no queries, no Vault path (orphan user)
  - vault_only:         in Vault but not in CH system.users (stale path)

Uses --from-file mode: accepts JSON files from both tools without live connections.

Examples:
  vaultspectre grep --path kv/ --key-pattern "CLICKHOUSE_USER" --format json > vault.json
  clickspectre analyze --by-user --format json > ch.json
  vaultspectre correlate --vault-file vault.json --ch-file ch.json`,
	RunE: runCorrelate,
}

func init() {
	correlateCmd.Flags().StringVar(&correlateVaultFile, "vault-file", "", "Path to vaultspectre grep JSON output")
	correlateCmd.Flags().StringVar(&correlateCHFile, "ch-file", "", "Path to clickspectre user activity JSON")
	correlateCmd.Flags().StringVar(&correlateFormat, "format", "text", "Output format: text, json")
	correlateCmd.Flags().StringVar(&correlateKeyField, "key-field", "CLICKHOUSE_USER", "Secret key name containing CH username")
	_ = correlateCmd.MarkFlagRequired("vault-file")
	_ = correlateCmd.MarkFlagRequired("ch-file")
}

func runCorrelate(_ *cobra.Command, _ []string) error {
	// Load vault grep results
	vaultData, err := os.ReadFile(correlateVaultFile)
	if err != nil {
		return newExitError(ExitBadArgs, "failed to read vault file: %v", err)
	}
	var grepResult grep.GrepResult
	if err := json.Unmarshal(vaultData, &grepResult); err != nil {
		return newExitError(ExitBadArgs, "invalid vault JSON: %v", err)
	}

	// Load clickspectre user data
	chData, err := os.ReadFile(correlateCHFile)
	if err != nil {
		return newExitError(ExitBadArgs, "failed to read CH file: %v", err)
	}
	var chReport ClickSpectreReport
	if err := json.Unmarshal(chData, &chReport); err != nil {
		return newExitError(ExitBadArgs, "invalid CH JSON: %v", err)
	}

	result := correlate(grepResult, chReport)

	if correlateFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	printCorrelateText(result)

	// Exit 6 if inactive users with vault paths found
	if result.Summary.InactiveVault > 0 || result.Summary.VaultOnly > 0 {
		return newExitError(ExitFindings, "%d inactive/stale users found",
			result.Summary.InactiveVault+result.Summary.VaultOnly)
	}
	return nil
}

func correlate(vaultResult grep.GrepResult, chReport ClickSpectreReport) *CorrelateResult {
	// Build vault user → paths map
	vaultUsers := make(map[string][]string) // username → vault paths
	keyFieldUpper := strings.ToUpper(correlateKeyField)

	for _, match := range vaultResult.Matches {
		for _, key := range match.Keys {
			if strings.ToUpper(key.Name) == keyFieldUpper && key.Value != "" {
				vaultUsers[key.Value] = append(vaultUsers[key.Value], match.Path)
			}
		}
	}

	// Build CH user activity map
	chUsers := make(map[string]*ClickSpectreUser)
	for i := range chReport.Users {
		chUsers[chReport.Users[i].Username] = &chReport.Users[i]
	}

	// Correlate
	seen := make(map[string]bool)
	var users []CorrelatedUser

	// Process all CH users
	for _, chu := range chReport.Users {
		seen[chu.Username] = true
		paths := vaultUsers[chu.Username]

		var class UserClassification
		switch {
		case chu.IsActive && len(paths) > 0:
			class = ClassActiveWithVault
		case chu.IsActive && len(paths) == 0:
			class = ClassActiveNoVault
		case !chu.IsActive && len(paths) > 0:
			class = ClassInactiveVault
		default:
			class = ClassInactiveNoVault
		}

		users = append(users, CorrelatedUser{
			Username:       chu.Username,
			Classification: class,
			QueryCount:     chu.QueryCount,
			VaultPaths:     paths,
			LastSeen:       chu.LastSeen,
		})
	}

	// Process vault-only users (in Vault but not in CH)
	for username, paths := range vaultUsers {
		if !seen[username] {
			users = append(users, CorrelatedUser{
				Username:       username,
				Classification: ClassVaultOnly,
				VaultPaths:     paths,
			})
		}
	}

	// Sort by classification then username
	sort.Slice(users, func(i, j int) bool {
		if users[i].Classification != users[j].Classification {
			return classOrder(users[i].Classification) < classOrder(users[j].Classification)
		}
		return users[i].Username < users[j].Username
	})

	// Build summary
	summary := CorrelateSummary{}
	for _, u := range users {
		switch u.Classification {
		case ClassActiveWithVault:
			summary.ActiveWithVault++
		case ClassActiveNoVault:
			summary.ActiveNoVault++
		case ClassInactiveVault:
			summary.InactiveVault++
		case ClassInactiveNoVault:
			summary.InactiveNoVault++
		case ClassVaultOnly:
			summary.VaultOnly++
		}
	}

	return &CorrelateResult{Users: users, Summary: summary}
}

func classOrder(c UserClassification) int {
	switch c {
	case ClassActiveWithVault:
		return 0
	case ClassActiveNoVault:
		return 1
	case ClassInactiveVault:
		return 2
	case ClassInactiveNoVault:
		return 3
	case ClassVaultOnly:
		return 4
	default:
		return 5
	}
}

func printCorrelateText(result *CorrelateResult) {
	groups := map[UserClassification]string{
		ClassActiveWithVault: "ACTIVE WITH VAULT",
		ClassActiveNoVault:   "ACTIVE — NO VAULT PATH",
		ClassInactiveVault:   "INACTIVE — CLEANUP CANDIDATES",
		ClassInactiveNoVault: "INACTIVE — NO VAULT PATH",
		ClassVaultOnly:       "STALE VAULT PATHS — USER ABSENT FROM CH",
	}

	order := []UserClassification{
		ClassActiveWithVault, ClassActiveNoVault,
		ClassInactiveVault, ClassInactiveNoVault, ClassVaultOnly,
	}

	for _, class := range order {
		var classUsers []CorrelatedUser
		for _, u := range result.Users {
			if u.Classification == class {
				classUsers = append(classUsers, u)
			}
		}
		if len(classUsers) == 0 {
			continue
		}

		fmt.Printf("%s (%d)\n", groups[class], len(classUsers))
		for _, u := range classUsers {
			if u.QueryCount > 0 {
				fmt.Printf("  %-25s %d queries", u.Username, u.QueryCount)
			} else {
				fmt.Printf("  %-25s 0 queries", u.Username)
			}
			if len(u.VaultPaths) > 0 {
				fmt.Printf("  -> %s", u.VaultPaths[0])
				if len(u.VaultPaths) > 1 {
					fmt.Printf(" (+%d)", len(u.VaultPaths)-1)
				}
			}
			fmt.Println()
		}
		fmt.Println()
	}

	fmt.Printf("Summary: %d active+vault, %d active-no-vault, %d inactive+vault, %d inactive, %d vault-only\n",
		result.Summary.ActiveWithVault, result.Summary.ActiveNoVault,
		result.Summary.InactiveVault, result.Summary.InactiveNoVault, result.Summary.VaultOnly)
}
