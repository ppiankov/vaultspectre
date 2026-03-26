package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/ppiankov/vaultspectre/internal/grep"
	"github.com/ppiankov/vaultspectre/internal/redact"
	"github.com/ppiankov/vaultspectre/internal/vault"
)

// ServerConfig holds Vault connection parameters for the MCP server.
type ServerConfig struct {
	VaultAddr  string
	VaultToken string
	Namespace  string
	Timeout    time.Duration
	Version    string
}

// NewServer creates a vaultspectre MCP server with all tools registered.
func NewServer(cfg ServerConfig) *server.MCPServer {
	s := server.NewMCPServer(
		"vaultspectre",
		cfg.Version,
		server.WithToolCapabilities(false),
	)

	// Register tools
	s.AddTool(lsTool(), lsHandler(cfg))
	s.AddTool(grepTool(), grepHandler(cfg))
	s.AddTool(countTool(), countHandler(cfg))
	s.AddTool(doctorTool(), doctorHandler(cfg))

	return s
}

// --- ls tool ---

func lsTool() mcp.Tool {
	return mcp.NewTool("vaultspectre_ls",
		mcp.WithDescription("List Vault secret paths recursively. No secret data is read."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Vault path to list (e.g. kv/projects/)"),
		),
		mcp.WithNumber("depth",
			mcp.Description("Max recursion depth (0 = unlimited)"),
		),
	)
}

type lsArgs struct {
	Path  string  `json:"path"`
	Depth float64 `json:"depth"`
}

func lsHandler(cfg ServerConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args lsArgs
		if err := request.BindArguments(&args); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
		}

		client, err := newClient(cfg)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault connection failed: %v", err)), nil
		}

		matcher := grep.NewMatcher("", "", false)
		walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
			MaxDepth: int(args.Depth),
			Workers:  10,
			DryRun:   true,
		})

		result, err := walker.Walk(args.Path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault list failed: %v", err)), nil
		}

		paths := make([]string, len(result.Matches))
		for i, m := range result.Matches {
			paths[i] = m.Path
		}

		data, _ := json.Marshal(map[string]interface{}{
			"paths":         paths,
			"total_secrets": len(paths),
			"total_skipped": result.TotalSkipped,
		})
		return mcp.NewToolResultText(string(data)), nil
	}
}

// --- grep tool ---

func grepTool() mcp.Tool {
	return mcp.NewTool("vaultspectre_grep",
		mcp.WithDescription("Search Vault secrets by key or value pattern. Values are always redacted in responses."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Vault path to search (e.g. kv/projects/)"),
		),
		mcp.WithString("key_pattern",
			mcp.Required(),
			mcp.Description("Comma-separated glob patterns for key names (e.g. CLICKHOUSE_*)"),
		),
		mcp.WithString("value_pattern",
			mcp.Description("Pattern to match against values"),
		),
		mcp.WithNumber("depth",
			mcp.Description("Max recursion depth (0 = unlimited)"),
		),
	)
}

type grepArgs struct {
	Path         string  `json:"path"`
	KeyPattern   string  `json:"key_pattern"`
	ValuePattern string  `json:"value_pattern"`
	Depth        float64 `json:"depth"`
}

func grepHandler(cfg ServerConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args grepArgs
		if err := request.BindArguments(&args); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
		}

		client, err := newClient(cfg)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault connection failed: %v", err)), nil
		}

		matcher := grep.NewMatcher(args.KeyPattern, args.ValuePattern, false)
		walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
			ShowValues: true, // Read values for matching, but redact in output
			MaxDepth:   int(args.Depth),
			Workers:    10,
		})

		result, err := walker.Walk(args.Path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault search failed: %v", err)), nil
		}

		// MCP responses ALWAYS redacted — structural guarantee
		rd := redact.New()
		for i := range result.Matches {
			for j := range result.Matches[i].Keys {
				k := &result.Matches[i].Keys[j]
				if k.Value != "" {
					if redact.IsSensitiveKey(k.Name) {
						k.Value = redact.RedactByKeyName(k.Name, k.Value)
					} else {
						k.Value = rd.Redact(k.Value)
					}
				}
			}
		}

		data, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(data)), nil
	}
}

// --- count tool ---

func countTool() mcp.Tool {
	return mcp.NewTool("vaultspectre_count",
		mcp.WithDescription("Count secrets in a Vault tree. No secret data is read."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Vault path to count (e.g. kv/)"),
		),
		mcp.WithNumber("depth",
			mcp.Description("Max recursion depth (0 = unlimited)"),
		),
	)
}

type countArgs struct {
	Path  string  `json:"path"`
	Depth float64 `json:"depth"`
}

func countHandler(cfg ServerConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args countArgs
		if err := request.BindArguments(&args); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid arguments: %v", err)), nil
		}

		client, err := newClient(cfg)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault connection failed: %v", err)), nil
		}

		matcher := grep.NewMatcher("", "", false)
		walker := grep.NewWalker(client, matcher, grep.WalkerConfig{
			MaxDepth: int(args.Depth),
			Workers:  10,
			DryRun:   true,
		})

		result, err := walker.Walk(args.Path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("vault list failed: %v", err)), nil
		}

		data, _ := json.Marshal(map[string]interface{}{
			"total":   len(result.Matches),
			"skipped": result.TotalSkipped,
		})
		return mcp.NewToolResultText(string(data)), nil
	}
}

// --- doctor tool ---

func doctorTool() mcp.Tool {
	return mcp.NewTool("vaultspectre_doctor",
		mcp.WithDescription("Check vaultspectre configuration and Vault connectivity."),
	)
}

func doctorHandler(cfg ServerConfig) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		checks := []map[string]string{}

		// Check vault address
		if cfg.VaultAddr == "" {
			checks = append(checks, map[string]string{"name": "vault_address", "status": "fail", "message": "not set"})
		} else {
			checks = append(checks, map[string]string{"name": "vault_address", "status": "pass", "message": cfg.VaultAddr})
		}

		// Check vault token
		if cfg.VaultToken == "" {
			checks = append(checks, map[string]string{"name": "vault_token", "status": "fail", "message": "not set"})
		} else {
			checks = append(checks, map[string]string{"name": "vault_token", "status": "pass", "message": "present (" + redact.MaskToken(cfg.VaultToken) + ")"})
		}

		// Check connectivity
		if cfg.VaultAddr != "" && cfg.VaultToken != "" {
			client, err := newClient(cfg)
			if err != nil {
				checks = append(checks, map[string]string{"name": "vault_connectivity", "status": "fail", "message": err.Error()})
			} else {
				start := time.Now()
				_, lookupErr := client.GetClient().Auth().Token().LookupSelf()
				latency := time.Since(start).Round(time.Millisecond)
				if lookupErr != nil {
					checks = append(checks, map[string]string{"name": "vault_connectivity", "status": "fail", "message": lookupErr.Error()})
				} else {
					checks = append(checks, map[string]string{"name": "vault_connectivity", "status": "pass", "message": fmt.Sprintf("connected (%s)", latency)})
				}
			}
		}

		passed := 0
		for _, c := range checks {
			if c["status"] == "pass" {
				passed++
			}
		}
		status := "healthy"
		if passed < len(checks) {
			status = "unavailable"
		}

		data, _ := json.Marshal(map[string]interface{}{
			"status":    status,
			"version":   cfg.Version,
			"checks":    checks,
			"readiness": float64(passed) / float64(len(checks)),
		})
		return mcp.NewToolResultText(string(data)), nil
	}
}

// --- helpers ---

func newClient(cfg ServerConfig) (*vault.Client, error) {
	client, err := vault.NewClient(vault.Config{
		Address:   cfg.VaultAddr,
		Token:     cfg.VaultToken,
		Namespace: cfg.Namespace,
		Timeout:   cfg.Timeout,
	})
	if err != nil {
		return nil, err
	}

	if err := vault.Authenticate(client.GetClient(), vault.AuthConfig{
		Method: vault.AuthToken,
		Token:  cfg.VaultToken,
	}); err != nil {
		return nil, err
	}

	return client, nil
}
