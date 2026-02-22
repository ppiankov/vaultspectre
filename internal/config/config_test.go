package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vaultspectre.yaml")

	content := `vault_addr: https://vault.example.com
vault_namespace: admin
output: json
stale_days: 60
timeout: 45
detect_vars: true
fail_on_missing: true
exclude_patterns:
  - "*.example"
  - "test/**"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}

	if cfg.VaultAddr != "https://vault.example.com" {
		t.Errorf("VaultAddr = %q", cfg.VaultAddr)
	}
	if cfg.VaultNamespace != "admin" {
		t.Errorf("VaultNamespace = %q", cfg.VaultNamespace)
	}
	if cfg.Output != "json" {
		t.Errorf("Output = %q", cfg.Output)
	}
	if cfg.StaleDays != 60 {
		t.Errorf("StaleDays = %d", cfg.StaleDays)
	}
	if cfg.Timeout != 45 {
		t.Errorf("Timeout = %d", cfg.Timeout)
	}
	if !cfg.DetectVars {
		t.Error("DetectVars should be true")
	}
	if !cfg.FailOnMissing {
		t.Error("FailOnMissing should be true")
	}
	if len(cfg.ExcludePatterns) != 2 {
		t.Errorf("ExcludePatterns len = %d, want 2", len(cfg.ExcludePatterns))
	}
}

func TestLoadFile_NonExistent(t *testing.T) {
	_, err := LoadFile("/nonexistent/.vaultspectre.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vaultspectre.yaml")
	if err := os.WriteFile(path, []byte(":::invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vaultspectre.yaml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}

	// All zero values
	if cfg.VaultAddr != "" {
		t.Errorf("VaultAddr = %q, want empty", cfg.VaultAddr)
	}
	if cfg.StaleDays != 0 {
		t.Errorf("StaleDays = %d, want 0", cfg.StaleDays)
	}
}

func TestLoad_CWD(t *testing.T) {
	// Create config in a temp directory and chdir there
	dir := t.TempDir()
	path := filepath.Join(dir, ".vaultspectre.yaml")
	if err := os.WriteFile(path, []byte("vault_addr: https://local.vault"), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, source, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.VaultAddr != "https://local.vault" {
		t.Errorf("VaultAddr = %q", cfg.VaultAddr)
	}
	if source != ".vaultspectre.yaml" {
		t.Errorf("source = %q, want .vaultspectre.yaml", source)
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, source, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if source != "" {
		t.Errorf("source = %q, want empty (no config found)", source)
	}
	if cfg.VaultAddr != "" {
		t.Errorf("VaultAddr = %q, want empty", cfg.VaultAddr)
	}
}

func TestLoadFile_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vaultspectre.yaml")
	if err := os.WriteFile(path, []byte("stale_days: 30\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}
	if cfg.StaleDays != 30 {
		t.Errorf("StaleDays = %d, want 30", cfg.StaleDays)
	}
	if cfg.VaultAddr != "" {
		t.Errorf("VaultAddr = %q, want empty", cfg.VaultAddr)
	}
}
