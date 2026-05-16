package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppiankov/vaultspectre/internal/eso"
	"github.com/ppiankov/vaultspectre/internal/grep"
)

// --- diff helpers ---

func TestCountWorsened_NoneMixed(t *testing.T) {
	changed := []DiffFinding{
		{Path: "a", OldStatus: "ok", NewStatus: "missing"},       // worsened
		{Path: "b", OldStatus: "missing", NewStatus: "ok"},       // improved (not worsened)
		{Path: "c", OldStatus: "ok", NewStatus: "access_denied"}, // worsened
	}
	got := countWorsened(changed)
	if got != 2 {
		t.Errorf("countWorsened: got %d, want 2", got)
	}
}

func TestCountWorsened_NoneWorsened(t *testing.T) {
	changed := []DiffFinding{
		{Path: "a", OldStatus: "missing", NewStatus: "ok"},
		{Path: "b", OldStatus: "error", NewStatus: "ok"},
	}
	if countWorsened(changed) != 0 {
		t.Error("expected 0 worsened when all improved")
	}
}

func TestCountWorsened_Empty(t *testing.T) {
	if countWorsened(nil) != 0 {
		t.Error("expected 0 for nil slice")
	}
}

func TestPrintDiffText_WithChanges(t *testing.T) {
	result := &DiffResult{
		Added:   []DiffFinding{{Path: "new/path", NewStatus: "missing"}},
		Removed: []DiffFinding{{Path: "old/path", OldStatus: "ok"}},
		Changed: []DiffFinding{{Path: "changed/path", OldStatus: "ok", NewStatus: "missing"}},
		Summary: DiffSummary{TotalAdded: 1, TotalRemoved: 1, TotalChanged: 1},
	}

	out := captureStdout(func() { printDiffText(result) })

	if !strings.Contains(out, "new/path") {
		t.Error("output should contain added path")
	}
	if !strings.Contains(out, "old/path") {
		t.Error("output should contain removed path")
	}
	if !strings.Contains(out, "changed/path") {
		t.Error("output should contain changed path")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("output should contain Summary line")
	}
}

func TestPrintDiffText_NoChanges(t *testing.T) {
	result := &DiffResult{Summary: DiffSummary{}}
	out := captureStdout(func() { printDiffText(result) })
	if !strings.Contains(out, "No changes") {
		t.Error("output should say no changes when diff is empty")
	}
}

// --- count helpers ---

func TestGroupByDepthLevel_Basic(t *testing.T) {
	paths := []string{
		"kv/a",
		"kv/b",
		"kv/a/c",
	}
	groups := groupByDepthLevel(paths)

	byDepth := map[string]int{}
	for _, g := range groups {
		byDepth[g.Key] = g.Count
	}

	if byDepth["depth-1"] != 2 {
		t.Errorf("depth-1: got %d, want 2", byDepth["depth-1"])
	}
	if byDepth["depth-2"] != 1 {
		t.Errorf("depth-2: got %d, want 1", byDepth["depth-2"])
	}
}

func TestGroupByDepthLevel_Empty(t *testing.T) {
	groups := groupByDepthLevel(nil)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups for nil input, got %d", len(groups))
	}
}

func TestGroupByPrefixN_Basic(t *testing.T) {
	paths := []string{
		"kv/app/db",
		"kv/app/cache",
		"kv/infra/network",
	}
	groups := groupByPrefixN(paths, 2)

	byKey := map[string]int{}
	for _, g := range groups {
		byKey[g.Key] = g.Count
	}

	if byKey["kv/app/"] != 2 {
		t.Errorf("kv/app/: got %d, want 2", byKey["kv/app/"])
	}
	if byKey["kv/infra/"] != 1 {
		t.Errorf("kv/infra/: got %d, want 1", byKey["kv/infra/"])
	}
}

func TestGroupByPrefixN_DepthExceedsPath(t *testing.T) {
	paths := []string{"a"}
	groups := groupByPrefixN(paths, 5) // deeper than path has segments
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Count != 1 {
		t.Errorf("count: got %d, want 1", groups[0].Count)
	}
}

// --- doctor helpers ---

func TestCheckVaultAddr_Empty(t *testing.T) {
	vaultAddr = ""
	r := checkVaultAddr()
	if r.Status != CheckFail {
		t.Errorf("empty vault addr: want CheckFail, got %s", r.Status)
	}
}

func TestCheckVaultAddr_Set(t *testing.T) {
	vaultAddr = "https://vault.example.com"
	r := checkVaultAddr()
	if r.Status != CheckPass {
		t.Errorf("set vault addr: want CheckPass, got %s", r.Status)
	}
	if !strings.Contains(r.Message, "vault.example.com") {
		t.Errorf("message should contain the addr, got: %q", r.Message)
	}
	vaultAddr = ""
}

func TestCheckVaultToken_Empty(t *testing.T) {
	vaultToken = ""
	r := checkVaultToken()
	if r.Status != CheckFail {
		t.Errorf("empty token: want CheckFail, got %s", r.Status)
	}
}

func TestCheckVaultToken_Set(t *testing.T) {
	vaultToken = "s.mytoken1234567890"
	r := checkVaultToken()
	if r.Status != CheckPass {
		t.Errorf("set token: want CheckPass, got %s", r.Status)
	}
	// Token should be masked — not the full value
	if strings.Contains(r.Message, "mytoken1234567890") {
		t.Error("full token should not appear in message")
	}
	vaultToken = ""
}

func TestCheckEsoDir_ValidDir(t *testing.T) {
	// Use the testdata directory which has real ESO fixtures
	r := checkEsoDir("../eso/testdata")
	if r.Status == CheckFail {
		t.Errorf("valid eso dir should not fail: %s", r.Message)
	}
}

func TestCheckEsoDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	r := checkEsoDir(dir)
	if r.Status != CheckWarn {
		t.Errorf("empty dir: want CheckWarn, got %s", r.Status)
	}
}

func TestCheckEsoDir_InvalidPath(t *testing.T) {
	r := checkEsoDir("/nonexistent/path/to/eso")
	if r.Status != CheckFail {
		t.Errorf("invalid path: want CheckFail, got %s", r.Status)
	}
}

func TestCheckEsoDir_ParseError(t *testing.T) {
	dir := t.TempDir()
	// Write invalid YAML that claims to be an ExternalSecret
	content := "apiVersion: external-secrets.io/v1beta1\nkind: ExternalSecret\n: invalid: yaml: [\n"
	if err := writeTestFile(dir, "bad.yaml", content); err != nil {
		t.Fatal(err)
	}
	r := checkEsoDir(dir)
	// Either fail (parse error) or warn (no valid ESO) — not pass
	if r.Status == CheckPass {
		t.Error("parse error dir should not return CheckPass")
	}
}

// --- ESO substituteEnvInSecrets ---

func TestSubstituteEnvInSecrets_NoMutation(t *testing.T) {
	originals := []*eso.ExternalSecret{
		{
			Name:       "test-es",
			TargetName: "test-secret",
			SourceFile: "test.yml",
			Data: []eso.DataEntry{
				{SecretKey: "KEY", RemoteRefKey: "secret/docflow/<ENV>/db", RemoteRefProperty: "password"},
			},
		},
	}

	result := substituteEnvInSecrets(originals, "<ENV>", "prod")

	if result[0].Data[0].RemoteRefKey != "secret/docflow/prod/db" {
		t.Errorf("substitution failed: got %q", result[0].Data[0].RemoteRefKey)
	}
	// Original must be unchanged
	if originals[0].Data[0].RemoteRefKey != "secret/docflow/<ENV>/db" {
		t.Error("original was mutated")
	}
}

func writeTestFile(dir, name, content string) error {
	return os.WriteFile(dir+"/"+name, []byte(content), 0o644)
}

// --- loadReport ---

func TestLoadReport_Valid(t *testing.T) {
	dir := t.TempDir()
	payload := map[string]interface{}{
		"tool":    "vaultspectre",
		"version": "test",
		"secrets": map[string]interface{}{},
	}
	b, _ := json.Marshal(payload)
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := loadReport(path)
	if err != nil {
		t.Fatalf("loadReport: %v", err)
	}
	if r.Tool != "vaultspectre" {
		t.Errorf("tool: got %q, want vaultspectre", r.Tool)
	}
}

func TestLoadReport_NotFound(t *testing.T) {
	_, err := loadReport("/nonexistent/path/report.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadReport_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadReport(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- printCorrelateText ---

func TestPrintCorrelateText_Basic(t *testing.T) {
	result := &CorrelateResult{
		Users: []CorrelatedUser{
			{Username: "user1", Classification: ClassActiveWithVault, QueryCount: 42, VaultPaths: []string{"kv/app/db"}},
			{Username: "user2", Classification: ClassInactiveVault, QueryCount: 0, VaultPaths: []string{"kv/app/cache"}},
		},
		Summary: CorrelateSummary{ActiveWithVault: 1, InactiveVault: 1},
	}

	out := captureStdout(func() { printCorrelateText(result) })

	if !strings.Contains(out, "user1") {
		t.Error("output should contain user1")
	}
	if !strings.Contains(out, "user2") {
		t.Error("output should contain user2")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("output should contain Summary line")
	}
}

func TestPrintCorrelateText_MultipleVaultPaths(t *testing.T) {
	result := &CorrelateResult{
		Users: []CorrelatedUser{
			{Username: "multi", Classification: ClassVaultOnly, QueryCount: 0,
				VaultPaths: []string{"kv/a", "kv/b", "kv/c"}},
		},
		Summary: CorrelateSummary{VaultOnly: 1},
	}

	out := captureStdout(func() { printCorrelateText(result) })
	// Should show +2 for extra paths beyond the first
	if !strings.Contains(out, "+2") {
		t.Error("output should indicate extra vault paths with +N")
	}
}

// --- ls helpers ---

func TestPrintTree_Basic(t *testing.T) {
	paths := []string{
		"kv/prod/app",
		"kv/prod/db",
		"kv/staging/app",
	}
	out := captureStdout(func() { printTree(paths, "kv") })
	if !strings.Contains(out, "app") {
		t.Error("tree output should contain 'app'")
	}
	if !strings.Contains(out, "db") {
		t.Error("tree output should contain 'db'")
	}
}

func TestPrintTree_Empty(t *testing.T) {
	out := captureStdout(func() { printTree(nil, "kv") })
	if out != "" {
		t.Errorf("empty paths should produce no output, got %q", out)
	}
}

func TestPrintCount_Basic(t *testing.T) {
	paths := []string{
		"kv/app/db",
		"kv/app/cache",
		"kv/infra/network",
	}
	out := captureStdout(func() { printCount(paths) })
	if !strings.Contains(out, "kv/") {
		t.Error("count output should show kv/ prefix")
	}
	if !strings.Contains(out, "kv/app/") {
		t.Error("count output should show kv/app/ prefix")
	}
}

func TestPrintCount_Empty(t *testing.T) {
	out := captureStdout(func() { printCount(nil) })
	if out != "" {
		t.Errorf("empty paths should produce no output, got %q", out)
	}
}

// --- grep output helpers ---

func TestPrintGrepText_DryRun(t *testing.T) {
	result := &grep.GrepResult{
		Matches: []grep.PathMatch{
			{Path: "kv/app/db"},
			{Path: "kv/app/cache"},
		},
		MatchCount: 2,
	}
	out := captureStdout(func() { printGrepText(result, true) })
	if !strings.Contains(out, "kv/app/db") {
		t.Error("dry-run output should list matched paths")
	}
}

func TestPrintGrepText_WithKeys(t *testing.T) {
	result := &grep.GrepResult{
		Matches: []grep.PathMatch{
			{
				Path: "kv/app/db",
				Keys: []grep.MatchedKey{
					{Name: "password", Type: "string"},
					{Name: "debug_blob", Type: "json_blob"},
				},
			},
		},
		TotalScanned: 10,
		MatchCount:   1,
	}
	out := captureStdout(func() { printGrepText(result, false) })
	if !strings.Contains(out, "password") {
		t.Error("output should contain key name 'password'")
	}
	if !strings.Contains(out, "json_blob") {
		t.Error("output should show type hint for non-string keys")
	}
}

// --- who helpers ---

func TestParseRepos_CommaSeparated(t *testing.T) {
	repos, err := parseRepos("/path/to/repo1, /path/to/repo2")
	if err != nil {
		t.Fatalf("parseRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d: %v", len(repos), repos)
	}
	if repos[0] != "/path/to/repo1" || repos[1] != "/path/to/repo2" {
		t.Errorf("repos: %v", repos)
	}
}

func TestParseRepos_FromFile(t *testing.T) {
	dir := t.TempDir()
	content := "# comment\n/repo/a\n/repo/b\n\n"
	reposFile := filepath.Join(dir, "repos.txt")
	if err := os.WriteFile(reposFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	repos, err := parseRepos("@" + reposFile)
	if err != nil {
		t.Fatalf("parseRepos @file: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d: %v", len(repos), repos)
	}
}

func TestParseRepos_FileNotFound(t *testing.T) {
	_, err := parseRepos("@/nonexistent/repos.txt")
	if err == nil {
		t.Error("expected error for missing repos file")
	}
}

func TestPrintWhoText_WithMatches(t *testing.T) {
	result := &WhoResult{
		Results: map[string][]WhoMatch{
			"kv/app/db": {
				{Repo: "/repos/myapp", File: "deploy.yml", Line: 10, Type: "env"},
			},
		},
		Summary: WhoSummary{TotalMatches: 1, ReposScanned: 1},
	}
	out := captureStdout(func() { printWhoText(result, []string{"kv/app/db"}) })
	if !strings.Contains(out, "kv/app/db") {
		t.Error("output should contain the target path")
	}
	if !strings.Contains(out, "deploy.yml") {
		t.Error("output should contain the matching file")
	}
}

func TestPrintWhoText_NoMatches(t *testing.T) {
	result := &WhoResult{
		Results: map[string][]WhoMatch{},
		Summary: WhoSummary{},
	}
	out := captureStdout(func() { printWhoText(result, []string{"kv/no/match"}) })
	if !strings.Contains(out, "no references found") {
		t.Error("output should indicate no references for unmatched path")
	}
}
