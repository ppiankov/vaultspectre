package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInit_CreatesConfig(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer func() { _ = os.Chdir(orig) }()
	_ = os.Chdir(dir)

	forceInit = false
	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vaultspectre.yaml"))
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "vault_addr") {
		t.Error("config missing vault_addr")
	}
	if !strings.Contains(content, "exclude_patterns") {
		t.Error("config missing exclude_patterns")
	}
	if !strings.Contains(content, "format: text") {
		t.Error("config missing format default")
	}
}

func TestRunInit_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer func() { _ = os.Chdir(orig) }()
	_ = os.Chdir(dir)

	// Create existing config
	_ = os.WriteFile(filepath.Join(dir, ".vaultspectre.yaml"), []byte("existing"), 0o644)

	forceInit = false
	err := runInit(nil, nil)
	if err == nil {
		t.Fatal("expected error when config exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want 'already exists'", err.Error())
	}
}

func TestRunInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer func() { _ = os.Chdir(orig) }()
	_ = os.Chdir(dir)

	// Create existing config
	_ = os.WriteFile(filepath.Join(dir, ".vaultspectre.yaml"), []byte("old"), 0o644)

	forceInit = true
	err := runInit(nil, nil)
	if err != nil {
		t.Fatalf("runInit(--force) error = %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".vaultspectre.yaml"))
	if string(data) == "old" {
		t.Error("config was not overwritten")
	}
}
