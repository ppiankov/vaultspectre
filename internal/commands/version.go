package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version and Commit are set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("vaultspectre %s (%s)\n", Version, Commit)
	},
}
