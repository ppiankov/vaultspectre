package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds persistent configuration loaded from .vaultspectre.yaml.
type Config struct {
	VaultAddr       string   `yaml:"vault_addr"`
	VaultNamespace  string   `yaml:"vault_namespace"`
	Format          string   `yaml:"format"`
	Output          string   `yaml:"output"`
	StaleDays       int      `yaml:"stale_days"`
	Timeout         int      `yaml:"timeout"`
	ExcludePatterns []string `yaml:"exclude_patterns"`
	DetectVars      bool     `yaml:"detect_vars"`
	FailOnMissing   bool     `yaml:"fail_on_missing"`
	SlackWebhookURL string   `yaml:"slack_webhook_url"`
}

// Load reads config from .vaultspectre.yaml in CWD, then ~/.vaultspectre.yaml.
// Returns zero-value Config if no config file found (not an error).
func Load() (Config, string, error) {
	// Try CWD first
	if cfg, err := loadFile(".vaultspectre.yaml"); err == nil {
		return cfg, ".vaultspectre.yaml", nil
	}

	// Try home directory
	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".vaultspectre.yaml")
		if cfg, err := loadFile(path); err == nil {
			return cfg, path, nil
		}
	}

	// No config file found — return defaults
	return Config{}, "", nil
}

// LoadFile reads config from a specific file path.
func LoadFile(path string) (Config, error) {
	return loadFile(path)
}

func loadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
