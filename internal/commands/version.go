package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Version and Commit are set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
)

var versionFormat string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		if versionFormat == "json" {
			info := map[string]string{
				"tool":       "vaultspectre",
				"version":    Version,
				"commit":     Commit,
				"go_version": runtime.Version(),
				"platform":   runtime.GOOS + "/" + runtime.GOARCH,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(info)
			return
		}
		fmt.Printf("vaultspectre %s (%s)\n", Version, Commit)
	},
}

func init() {
	versionCmd.Flags().StringVar(&versionFormat, "format", "", "output format (json)")
}
