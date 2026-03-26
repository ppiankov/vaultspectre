package commands

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vaultspectre",
	Short: "VaultSpectre - HashiCorp Vault secret usage auditor",
	Long: `VaultSpectre scans code repositories for Vault secret references,
validates them against your Vault instance, and identifies missing,
unused, and stale secret paths.

Part of the Spectre family of infrastructure cleanup tools.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(grepCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(ciInitCmd)
	rootCmd.AddCommand(correlateCmd)
	rootCmd.AddCommand(lsCmd)
}
