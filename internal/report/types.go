package report

import (
	"time"

	"github.com/ppiankov/vaultspectre/internal/analyzer"
	"github.com/ppiankov/vaultspectre/internal/scanner"
)

// Reporter interface for different report formats
type Reporter interface {
	Generate(data Data) error
}

// Data contains all report data
type Data struct {
	Tool       string                          `json:"tool"`
	Version    string                          `json:"version"`
	Timestamp  time.Time                       `json:"timestamp"`
	Config     Config                          `json:"config"`
	Summary    analyzer.Summary                `json:"summary"`
	Secrets    map[string]*analyzer.SecretInfo `json:"secrets"`
	References []scanner.Reference             `json:"references,omitempty"`
}

// Config contains scan configuration
type Config struct {
	VaultAddr          string `json:"vault_addr"`
	RepoPath           string `json:"repo_path"`
	StaleThresholdDays int    `json:"stale_threshold_days"`
	Verbose            bool   `json:"verbose,omitempty"`
	SummaryOnly        bool   `json:"summary_only,omitempty"`
	GroupByRole        bool   `json:"group_by_role,omitempty"`
}
