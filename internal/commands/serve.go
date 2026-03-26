package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/server"
	vsmcp "github.com/ppiankov/vaultspectre/internal/mcp"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start vaultspectre as an MCP server",
	Long: `Starts a Model Context Protocol (MCP) server over stdio, exposing
vaultspectre capabilities as typed tools for AI agents.

Tools exposed:
  - vaultspectre_ls:      List Vault paths recursively
  - vaultspectre_grep:    Search secrets by key/value pattern
  - vaultspectre_count:   Count secrets in a tree
  - vaultspectre_doctor:  Check connectivity and config

All tool responses have secret values redacted — structural guarantee.

Usage in Claude Code settings.json:
  "mcpServers": {
    "vaultspectre": {
      "command": "vaultspectre",
      "args": ["serve"],
      "env": {
        "VAULT_ADDR": "https://vault.example.com",
        "VAULT_TOKEN": "hvs.xxx"
      }
    }
  }`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	serveCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	serveCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace")
	serveCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
}

func runServe(_ *cobra.Command, _ []string) error {
	s := vsmcp.NewServer(vsmcp.ServerConfig{
		VaultAddr:  vaultAddr,
		VaultToken: vaultToken,
		Namespace:  vaultNamespace,
		Timeout:    time.Duration(timeoutSeconds) * time.Second,
		Version:    Version,
	})

	// Serve over stdio
	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}
	return nil
}
