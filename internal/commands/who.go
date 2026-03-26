package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/ppiankov/vaultspectre/internal/scanner"
	"github.com/spf13/cobra"
)

// WhoMatch represents a file that references a target Vault path.
type WhoMatch struct {
	Repo string `json:"repo"`
	File string `json:"file"`
	Line int    `json:"line"`
	Type string `json:"type"`
}

// WhoResult holds the full who output.
type WhoResult struct {
	Results map[string][]WhoMatch `json:"results"` // path → matches
	Summary WhoSummary            `json:"summary"`
}

// WhoSummary holds counts.
type WhoSummary struct {
	TargetPaths  int `json:"target_paths"`
	TotalMatches int `json:"total_matches"`
	ReposScanned int `json:"repos_scanned"`
}

var (
	whoRepos  string
	whoFormat string
	whoStdin  bool
)

var whoCmd = &cobra.Command{
	Use:   "who [paths...]",
	Short: "Find which codebases reference a Vault secret path",
	Long: `The inverse of scan: given Vault path(s), find which code files reference them.
Answers the rotation-readiness question: "who will break if I rotate this secret?"

Scans multiple repos in parallel for the target path(s).

Examples:
  vaultspectre who kv/payments/db --repos ~/dev/svc-a,~/dev/svc-b
  vaultspectre who kv/payments/db kv/payments/api --repos @repos.txt
  vaultspectre ls kv/payments/ | vaultspectre who --stdin --repos ~/dev/svc-a

Exit Codes:
  0 - Consumers found
  3 - No references found
  2 - Invalid arguments`,
	RunE: runWho,
}

func init() {
	whoCmd.Flags().StringVar(&whoRepos, "repos", "", "Comma-separated repo paths, or @file for one per line")
	whoCmd.Flags().StringVar(&whoFormat, "format", "text", "Output format: text, json")
	whoCmd.Flags().BoolVar(&whoStdin, "stdin", false, "Read target Vault paths from stdin")
	_ = whoCmd.MarkFlagRequired("repos")
}

func runWho(_ *cobra.Command, args []string) error {
	// Collect target paths
	var targetPaths []string
	if whoStdin {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" {
				targetPaths = append(targetPaths, line)
			}
		}
		if err := s.Err(); err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
	}
	targetPaths = append(targetPaths, args...)

	if len(targetPaths) == 0 {
		return newExitError(ExitBadArgs, "at least one target path is required (positional args or --stdin)")
	}

	// Parse repos
	repos, err := parseRepos(whoRepos)
	if err != nil {
		return newExitError(ExitBadArgs, "invalid --repos: %v", err)
	}
	if len(repos) == 0 {
		return newExitError(ExitBadArgs, "--repos is required")
	}

	// Build target set for fast lookup
	targetSet := make(map[string]bool)
	for _, p := range targetPaths {
		targetSet[p] = true
	}

	// Scan repos in parallel
	results := make(map[string][]WhoMatch)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, repo := range repos {
		wg.Add(1)
		go func(repoPath string) {
			defer wg.Done()

			s := scanner.New(repoPath)
			refs, scanErr := s.Scan()
			if scanErr != nil {
				return
			}

			for _, ref := range refs {
				path := ref.ResolvedPath
				if path == "" {
					path = ref.Path
				}
				if targetSet[path] {
					mu.Lock()
					results[path] = append(results[path], WhoMatch{
						Repo: repoPath,
						File: ref.File,
						Line: ref.Line,
						Type: ref.Type,
					})
					mu.Unlock()
				}
			}
		}(repo)
	}
	wg.Wait()

	// Build output
	totalMatches := 0
	for _, matches := range results {
		totalMatches += len(matches)
	}

	whoResult := &WhoResult{
		Results: results,
		Summary: WhoSummary{
			TargetPaths:  len(targetPaths),
			TotalMatches: totalMatches,
			ReposScanned: len(repos),
		},
	}

	if whoFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(whoResult)
	}

	printWhoText(whoResult, targetPaths)

	if totalMatches == 0 {
		return newExitError(ExitNotFound, "no references found for %d path(s) across %d repo(s)",
			len(targetPaths), len(repos))
	}
	return nil
}

func printWhoText(result *WhoResult, targetPaths []string) {
	for _, path := range targetPaths {
		matches := result.Results[path]
		if len(matches) == 0 {
			fmt.Printf("%s: no references found\n", path)
			continue
		}

		fmt.Printf("%s: %d reference(s)\n", path, len(matches))
		// Sort by repo then file
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].Repo != matches[j].Repo {
				return matches[i].Repo < matches[j].Repo
			}
			return matches[i].File < matches[j].File
		})
		for _, m := range matches {
			fmt.Printf("  %s:%d [%s]\n", m.File, m.Line, m.Type)
		}
		fmt.Println()
	}

	fmt.Fprintf(os.Stderr, "%d match(es) across %d repo(s)\n",
		result.Summary.TotalMatches, result.Summary.ReposScanned)
}

func parseRepos(input string) ([]string, error) {
	if strings.HasPrefix(input, "@") {
		// Read from file
		filePath := input[1:]
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read repos file %s: %w", filePath, err)
		}
		var repos []string
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				repos = append(repos, trimmed)
			}
		}
		return repos, nil
	}

	// Comma-separated
	var repos []string
	for _, r := range strings.Split(input, ",") {
		trimmed := strings.TrimSpace(r)
		if trimmed != "" {
			repos = append(repos, trimmed)
		}
	}
	return repos, nil
}
