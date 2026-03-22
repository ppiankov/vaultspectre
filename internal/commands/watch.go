package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/logging"
	"github.com/ppiankov/vaultspectre/internal/notify"
	"github.com/ppiankov/vaultspectre/internal/scanner"
	"github.com/ppiankov/vaultspectre/internal/vault"
	"github.com/spf13/cobra"
)

var (
	watchInterval   time.Duration
	slackWebhookURL string
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Continuously monitor for Vault secret drift",
	Long: `Runs periodic scans on a configurable interval, comparing each run
against the previous state and reporting only deltas (new and resolved findings).

Gracefully shuts down on SIGINT/SIGTERM.

Exit Codes:
  0 - Clean shutdown, no findings ever detected
  6 - Findings were detected during at least one run`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 5*time.Minute, "Scan interval (e.g. 1m, 5m, 1h)")

	watchCmd.Flags().StringVar(&repoPath, "repo", ".", "Path to repository to scan")
	watchCmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault server address")
	watchCmd.Flags().StringVar(&vaultToken, "token", os.Getenv("VAULT_TOKEN"), "Vault authentication token")
	watchCmd.Flags().StringVar(&vaultNamespace, "namespace", os.Getenv("VAULT_NAMESPACE"), "Vault namespace (Enterprise)")
	watchCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json")
	watchCmd.Flags().BoolVar(&failOnMissing, "fail-on-missing", false, "Track findings for exit code")
	watchCmd.Flags().StringVar(&excludeFlag, "exclude", "", "Comma-separated glob patterns to exclude")
	watchCmd.Flags().BoolVar(&detectVars, "detect-vars", false, "Auto-detect variables from Ansible inventory")
	watchCmd.Flags().StringArrayVar(&varFlags, "var", []string{}, "Set variable value")
	watchCmd.Flags().StringVar(&varFile, "var-file", "", "Path to YAML variable file")
	watchCmd.Flags().IntVar(&staleDays, "stale-days", 90, "Stale secret threshold in days")
	watchCmd.Flags().IntVar(&timeoutSeconds, "timeout", 30, "Vault API timeout in seconds")
	watchCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	watchCmd.Flags().StringVar(&slackWebhookURL, "slack-webhook", "", "Slack webhook URL for notifications")
}

// watchFinding is a simplified representation for delta comparison
type watchFinding struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	File   string `json:"file"`
}

// watchDelta represents changes between two scan runs
type watchDelta struct {
	Timestamp string         `json:"timestamp"`
	RunNumber int            `json:"run"`
	New       []watchFinding `json:"new,omitempty"`
	Resolved  []watchFinding `json:"resolved,omitempty"`
	Total     int            `json:"total_findings"`
}

func runWatch(cmd *cobra.Command, _ []string) error {
	logging.Init(verbose)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		slog.Info("shutdown signal received, stopping...")
		cancel()
	}()

	// Load config
	cfg, cfgSource, err := config.Load()
	if err != nil {
		slog.Warn("failed to load config file", "error", err)
	}
	if cfgSource != "" {
		slog.Info("loaded config file", "path", cfgSource)
		applyConfig(cmd, cfg)
	}

	if vaultAddr == "" {
		return newExitError(ExitBadArgs, "vault address is required")
	}
	if vaultToken == "" {
		return newExitError(ExitBadArgs, "vault token is required")
	}

	// Set up notifier
	webhookURL := slackWebhookURL
	if webhookURL == "" {
		webhookURL = cfg.SlackWebhookURL
	}
	var notifier notify.Notifier
	if webhookURL != "" {
		notifier = notify.NewSlackNotifier(webhookURL)
		slog.Info("slack notifications enabled")
	}

	slog.Info("starting watch mode", "interval", watchInterval, "repo", repoPath)

	var prevFindings map[string]watchFinding
	runNum := 0
	everFoundIssues := false

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()

	for {
		runNum++
		currentFindings := collectFindings(cfg)

		if prevFindings != nil {
			delta := computeWatchDelta(prevFindings, currentFindings, runNum)
			reportWatchDelta(delta)
			if len(delta.New) > 0 {
				everFoundIssues = true
			}

			// Send notification if configured
			if notifier != nil && (len(delta.New) > 0 || len(delta.Resolved) > 0) {
				event := notify.Event{
					RepoPath: repoPath,
					Total:    delta.Total,
				}
				for _, f := range delta.New {
					event.New = append(event.New, notify.Finding{Path: f.Path, Status: f.Status, File: f.File})
				}
				for _, f := range delta.Resolved {
					event.Resolved = append(event.Resolved, notify.Finding{Path: f.Path, Status: f.Status, File: f.File})
				}
				if err := notifier.Notify(event); err != nil {
					slog.Warn("notification failed", "error", err)
				}
			}
		} else {
			slog.Info("initial scan complete", "findings", len(currentFindings))
			if len(currentFindings) > 0 {
				everFoundIssues = true
			}
		}

		prevFindings = currentFindings

		select {
		case <-ctx.Done():
			slog.Info("watch stopped", "total_runs", runNum)
			if everFoundIssues {
				return newExitError(ExitFindings, "findings detected during watch")
			}
			return nil
		case <-ticker.C:
		}
	}
}

// collectFindings runs a lightweight scan and returns findings keyed for comparison
func collectFindings(cfg config.Config) map[string]watchFinding {
	findings := make(map[string]watchFinding)

	// Build exclude patterns
	var excludePatterns []string
	excludePatterns = append(excludePatterns, cfg.ExcludePatterns...)
	if excludeFlag != "" {
		for _, p := range strings.Split(excludeFlag, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				excludePatterns = append(excludePatterns, trimmed)
			}
		}
	}

	// Scan
	var s *scanner.Scanner
	if len(excludePatterns) > 0 {
		s = scanner.NewWithExcludes(repoPath, excludePatterns)
	} else {
		s = scanner.New(repoPath)
	}

	refs, err := s.Scan()
	if err != nil {
		slog.Error("scan failed", "error", err)
		return findings
	}

	// Resolve variables
	variables, _, err := loadVariables(varFlags, varFile, detectVars, repoPath)
	if err != nil {
		slog.Warn("variable resolution failed", "error", err)
	}

	if len(variables) > 0 {
		resolver := scanner.NewResolver(variables)
		refs, _ = resolver.ResolveAll(refs)
	}

	// Validate against Vault
	vaultClient, err := vault.NewClient(vault.Config{
		Address:   vaultAddr,
		Token:     vaultToken,
		Namespace: vaultNamespace,
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
	})
	if err != nil {
		slog.Error("vault client creation failed", "error", err)
		return findings
	}

	validator := vault.NewValidator(vaultClient)

	for i := range refs {
		if refs[i].Status != "pending_validation" {
			continue
		}

		pathToValidate := refs[i].ResolvedPath
		if pathToValidate == "" {
			pathToValidate = refs[i].Path
		}

		status, err := validator.ValidatePath(pathToValidate)
		if err != nil {
			refs[i].Status = "error"
		} else {
			refs[i].Status = status
		}

		if staleDays > 0 && refs[i].Status == "ok" {
			isStale, _, stalenessErr := validator.CheckStaleness(pathToValidate, staleDays)
			if stalenessErr == nil && isStale {
				refs[i].IsStale = true
			}
		}
	}

	// Collect issue findings
	for _, ref := range refs {
		status := ref.Status
		if ref.IsStale && status == "ok" {
			status = "stale"
		}
		if status == "missing" || status == "error" || status == "access_denied" ||
			status == "invalid" || status == "stale" {
			key := ref.Path + "|" + ref.File
			findings[key] = watchFinding{
				Path:   ref.Path,
				Status: status,
				File:   ref.File,
			}
		}
	}

	return findings
}

func computeWatchDelta(prev, current map[string]watchFinding, runNum int) watchDelta {
	delta := watchDelta{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RunNumber: runNum,
		Total:     len(current),
	}

	for key, f := range current {
		if _, existed := prev[key]; !existed {
			delta.New = append(delta.New, f)
		}
	}

	for key, f := range prev {
		if _, exists := current[key]; !exists {
			delta.Resolved = append(delta.Resolved, f)
		}
	}

	return delta
}

func reportWatchDelta(delta watchDelta) {
	if len(delta.New) == 0 && len(delta.Resolved) == 0 {
		slog.Info("no changes", "run", delta.RunNumber, "total_findings", delta.Total)
		return
	}

	if outputFormat == "json" {
		data, err := json.Marshal(delta)
		if err == nil {
			fmt.Println(string(data))
		}
		return
	}

	fmt.Fprintf(os.Stderr, "\n--- Run %d (%s) ---\n", delta.RunNumber, delta.Timestamp)
	if len(delta.New) > 0 {
		fmt.Fprintf(os.Stderr, "New findings (%d):\n", len(delta.New))
		for _, f := range delta.New {
			fmt.Fprintf(os.Stderr, "  + [%s] %s (%s)\n", f.Status, f.Path, f.File)
		}
	}
	if len(delta.Resolved) > 0 {
		fmt.Fprintf(os.Stderr, "Resolved (%d):\n", len(delta.Resolved))
		for _, f := range delta.Resolved {
			fmt.Fprintf(os.Stderr, "  - [%s] %s (%s)\n", f.Status, f.Path, f.File)
		}
	}
	fmt.Fprintf(os.Stderr, "Total findings: %d\n", delta.Total)
}
