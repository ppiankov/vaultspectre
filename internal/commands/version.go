package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.2.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("VaultSpectre v%s\n", version)
		fmt.Println("Part of the SpectreOps family")
	},
}
