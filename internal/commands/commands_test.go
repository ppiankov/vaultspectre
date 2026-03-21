package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/vaultspectre/internal/config"
	"github.com/ppiankov/vaultspectre/internal/scanner"
	"github.com/spf13/cobra"
)

func TestApplyConfig_SetsUnchangedFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("vault-addr", "", "")
	cmd.Flags().String("namespace", "", "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Int("stale-days", 90, "")
	cmd.Flags().Int("timeout", 30, "")
	cmd.Flags().Bool("detect-vars", false, "")
	cmd.Flags().Bool("fail-on-missing", false, "")

	// Reset package-level vars
	vaultAddr = ""
	vaultNamespace = ""
	outputFormat = ""
	staleDays = 90
	timeoutSeconds = 30
	detectVars = false
	failOnMissing = false

	cfg := config.Config{
		VaultAddr:      "https://vault.example.com",
		VaultNamespace: "admin",
		Format:         "json",
		StaleDays:      30,
		Timeout:        60,
		DetectVars:     true,
		FailOnMissing:  true,
	}

	applyConfig(cmd, cfg)

	if vaultAddr != "https://vault.example.com" {
		t.Errorf("vaultAddr = %q, want https://vault.example.com", vaultAddr)
	}
	if vaultNamespace != "admin" {
		t.Errorf("vaultNamespace = %q, want admin", vaultNamespace)
	}
	if outputFormat != "json" {
		t.Errorf("outputFormat = %q, want json", outputFormat)
	}
	if staleDays != 30 {
		t.Errorf("staleDays = %d, want 30", staleDays)
	}
	if timeoutSeconds != 60 {
		t.Errorf("timeoutSeconds = %d, want 60", timeoutSeconds)
	}
	if !detectVars {
		t.Error("detectVars should be true")
	}
	if !failOnMissing {
		t.Error("failOnMissing should be true")
	}
}

func TestApplyConfig_CLIFlagsTakePrecedence(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("vault-addr", "", "")
	cmd.Flags().String("namespace", "", "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Int("stale-days", 90, "")
	cmd.Flags().Int("timeout", 30, "")
	cmd.Flags().Bool("detect-vars", false, "")
	cmd.Flags().Bool("fail-on-missing", false, "")

	// Simulate CLI flag being explicitly set
	_ = cmd.Flags().Set("vault-addr", "https://cli-vault.example.com")
	vaultAddr = "https://cli-vault.example.com"
	vaultNamespace = ""
	outputFormat = ""

	cfg := config.Config{
		VaultAddr: "https://config-vault.example.com",
	}

	applyConfig(cmd, cfg)

	// CLI flag should win
	if vaultAddr != "https://cli-vault.example.com" {
		t.Errorf("vaultAddr = %q, want https://cli-vault.example.com (CLI should take precedence)", vaultAddr)
	}
}

func TestApplyConfig_LegacyOutputField(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("vault-addr", "", "")
	cmd.Flags().String("namespace", "", "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Int("stale-days", 90, "")
	cmd.Flags().Int("timeout", 30, "")
	cmd.Flags().Bool("detect-vars", false, "")
	cmd.Flags().Bool("fail-on-missing", false, "")

	vaultAddr = ""
	vaultNamespace = ""
	outputFormat = ""
	staleDays = 90
	timeoutSeconds = 30
	detectVars = false
	failOnMissing = false

	// Legacy config uses Output, not Format
	cfg := config.Config{
		Output: "sarif",
	}

	applyConfig(cmd, cfg)

	if outputFormat != "sarif" {
		t.Errorf("outputFormat = %q, want sarif (legacy output field)", outputFormat)
	}
}

func TestPrintPathsList(t *testing.T) {
	refs := []scanner.Reference{
		{Path: "secret/data/prod/db", ResolvedPath: "secret/data/prod/db", Status: "ok"},
		{Path: "secret/data/prod/api", ResolvedPath: "secret/data/prod/api", Status: "ok"},
		{Path: "secret/{{ env }}/cache", Status: "needs_resolution"},
		{Path: "secret/data/prod/db", ResolvedPath: "secret/data/prod/db", Status: "ok"}, // duplicate
		{Path: "secret/data/staging/app", Status: "skipped_policy"},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printPathsList(refs)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should include ok paths, deduplicated
	if !bytes.Contains([]byte(output), []byte("secret/data/prod/db\n")) {
		t.Error("missing secret/data/prod/db")
	}
	if !bytes.Contains([]byte(output), []byte("secret/data/prod/api\n")) {
		t.Error("missing secret/data/prod/api")
	}
	// Should NOT include needs_resolution or skipped_policy
	if bytes.Contains([]byte(output), []byte("{{ env }}")) {
		t.Error("should not include needs_resolution paths")
	}
	if bytes.Contains([]byte(output), []byte("staging")) {
		t.Error("should not include skipped_policy paths")
	}
}

func TestDetectAnsibleVariables(t *testing.T) {
	dir := t.TempDir()

	// Create group_vars directory with a vars file
	groupVars := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(groupVars, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "app_env: production\napp_region: us-east-1\njinja: \"{{ derived }}\"\n"
	if err := os.WriteFile(filepath.Join(groupVars, "all.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create an example file that should be skipped
	if err := os.WriteFile(filepath.Join(groupVars, "example.yml"), []byte("skip: me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, sources, err := detectAnsibleVariables(dir)
	if err != nil {
		t.Fatal(err)
	}

	if vars["app_env"] != "production" {
		t.Errorf("app_env = %q, want production", vars["app_env"])
	}
	if vars["app_region"] != "us-east-1" {
		t.Errorf("app_region = %q, want us-east-1", vars["app_region"])
	}
	// Jinja templates should be skipped
	if _, exists := vars["jinja"]; exists {
		t.Error("jinja template variable should be skipped")
	}
	// Example file should be skipped
	if _, exists := vars["skip"]; exists {
		t.Error("example file variables should be skipped")
	}
	// Sources should reference auto-detect
	if sources["app_env"] == "" {
		t.Error("expected source to be set")
	}
}

func TestDetectAnsibleVariables_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	vars, _, err := detectAnsibleVariables(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 0 {
		t.Errorf("expected 0 vars from empty dir, got %d", len(vars))
	}
}

func TestVersionCommand(t *testing.T) {
	// Capture version output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	Version = "1.2.3"
	Commit = "abc1234"
	versionCmd.Run(versionCmd, nil)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if output != "vaultspectre 1.2.3 (abc1234)\n" {
		t.Errorf("version output = %q, want %q", output, "vaultspectre 1.2.3 (abc1234)\n")
	}
}

func TestExecute_VersionSubcommand(t *testing.T) {
	// Just verify Execute doesn't panic
	Version = "test"
	Commit = "test"
	rootCmd.SetArgs([]string{"version"})

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := Execute()

	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Errorf("Execute() with version subcommand should not error: %v", err)
	}
}
