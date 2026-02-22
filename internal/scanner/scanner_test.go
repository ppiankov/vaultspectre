package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// isExampleFile
// ---------------------------------------------------------------------------

func TestIsExampleFile(t *testing.T) {
	tests := []struct {
		basename string
		want     bool
	}{
		{"config.example.yml", true},
		{"config_example.yml", true},
		{"example_config.yml", true},
		{"sample_config.yml", true},
		{"template_config.yml", true},
		{"config.yml", false},
		{"playbook.yml", false},
		{"deploy.sh", false},
	}

	for _, tt := range tests {
		t.Run(tt.basename, func(t *testing.T) {
			got := isExampleFile(tt.basename)
			if got != tt.want {
				t.Errorf("isExampleFile(%q) = %v, want %v", tt.basename, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isPolicyFile
// ---------------------------------------------------------------------------

func TestIsPolicyFile(t *testing.T) {
	tests := []struct {
		name     string
		ext      string
		basename string
		want     bool
	}{
		{"hcl_extension", ".hcl", "admin.hcl", true},
		{"policy_json", ".json", "policy.json", true},
		{"policy_no_ext", "", "policy", true},
		{"admin_policy_no_ext", "", "admin_policy", true},
		{"normal_json", ".json", "config.json", false},
		{"normal_yml", ".yml", "playbook.yml", false},
		{"normal_py", ".py", "script.py", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPolicyFile(tt.ext, tt.basename)
			if got != tt.want {
				t.Errorf("isPolicyFile(%q, %q) = %v, want %v", tt.ext, tt.basename, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cleanSecretPath
// ---------------------------------------------------------------------------

func TestCleanSecretPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"secret/data/prod/db"`, "secret/data/prod/db"},
		{`'secret/data/prod/db'`, "secret/data/prod/db"},
		{`/secret/data/prod/db`, "secret/data/prod/db"},
		{` secret/data/prod/db `, "secret/data/prod/db"},
		{"secret/data/clean", "secret/data/clean"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanSecretPath(tt.input)
			if got != tt.want {
				t.Errorf("cleanSecretPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isValidVaultPath
// ---------------------------------------------------------------------------

func TestIsValidVaultPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"valid_basic", "secret/data/prod", true},
		{"valid_deep", "secret/data/prod/db/password", true},
		{"valid_kv", "kv/data/myapp", true},
		{"no_slash", "secretdata", false},
		{"http_url", "http://vault.example.com/secret", false},
		{"https_url", "https://vault.example.com/secret", false},
		{"too_short", "a/", false},
		{"minimum_valid", "a/b", true},
		{"too_long", strings.Repeat("a", 256) + "/" + strings.Repeat("b", 257), false},
		{"empty", "", false},
		{"just_slash", "/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidVaultPath(tt.path)
			if got != tt.want {
				t.Errorf("isValidVaultPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsAnsibleVar
// ---------------------------------------------------------------------------

func TestContainsAnsibleVar(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"secret/data/{{ env }}/db", true},
		{"{{ vault_path }}", true},
		{"secret/data/prod/db", false},
		{"secret/data/{single}/db", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := containsAnsibleVar(tt.path)
			if got != tt.want {
				t.Errorf("containsAnsibleVar(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsWildcard
// ---------------------------------------------------------------------------

func TestContainsWildcard(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"secret/data/*", true},
		{"secret/data/+/db", true},
		{"secret/*/prod", true},
		{"secret/data/prod/db", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := containsWildcard(tt.path)
			if got != tt.want {
				t.Errorf("containsWildcard(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractAnsibleVars
// ---------------------------------------------------------------------------

func TestExtractAnsibleVars(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "single_var",
			path: "secret/data/{{ env }}/db",
			want: []string{"env"},
		},
		{
			name: "multiple_vars",
			path: "secret/data/{{ env }}/{{ service }}/config",
			want: []string{"env", "service"},
		},
		{
			name: "var_with_filter",
			path: "secret/data/{{ env | default('prod') }}/db",
			want: []string{"env"},
		},
		{
			name: "var_with_property_access",
			path: "secret/data/{{ cluster.name }}/db",
			want: []string{"cluster"},
		},
		{
			name: "no_vars",
			path: "secret/data/prod/db",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAnsibleVars(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("extractAnsibleVars(%q) returned %v (len %d), want %v (len %d)",
					tt.path, got, len(got), tt.want, len(tt.want))
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("extractAnsibleVars(%q)[%d] = %q, want %q", tt.path, i, v, tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isYAMLVariableDefinition
// ---------------------------------------------------------------------------

func TestIsYAMLVariableDefinition(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "variable_definition_with_secret_path",
			line: `vault_secret_path: "secret/data/production/db"`,
			want: true,
		},
		{
			name: "variable_definition_with_kv_path",
			line: `vault_secret_path: "kv/data/production/db"`,
			want: true,
		},
		{
			name: "lookup_not_definition",
			line: `vault_secret: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/prod/db') }}"`,
			want: false,
		},
		{
			name: "comment_line",
			line: `# vault_secret_path: secret/data/prod/db`,
			want: false,
		},
		{
			name: "no_colon",
			line: `vault read secret/data/prod/db`,
			want: false,
		},
		{
			name: "function_call_before_colon",
			line: `lookup('vault'): secret/data/prod/db`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isYAMLVariableDefinition(tt.line)
			if got != tt.want {
				t.Errorf("isYAMLVariableDefinition(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	s := New("/some/repo")
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.repoPath != "/some/repo" {
		t.Errorf("repoPath = %q, want %q", s.repoPath, "/some/repo")
	}
	if len(s.patterns) == 0 {
		t.Error("patterns slice is empty")
	}
}

// ---------------------------------------------------------------------------
// GetPatterns sanity check
// ---------------------------------------------------------------------------

func TestGetPatterns(t *testing.T) {
	patterns := GetPatterns()
	if len(patterns) == 0 {
		t.Fatal("GetPatterns() returned empty slice")
	}

	seen := make(map[string]bool)
	for _, p := range patterns {
		if p.Name == "" {
			t.Error("pattern has empty name")
		}
		if p.Type == "" {
			t.Errorf("pattern %q has empty type", p.Name)
		}
		if p.Regex == nil {
			t.Errorf("pattern %q has nil regex", p.Name)
		}
		if seen[p.Name] {
			t.Errorf("duplicate pattern name: %q", p.Name)
		}
		seen[p.Name] = true
	}
}

// ---------------------------------------------------------------------------
// Scan: integration-style tests using temp directory
// ---------------------------------------------------------------------------

func TestScan_AnsibleLookup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "playbook.yml", `---
- name: Read DB creds
  set_fact:
    db_pass: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/prod/db:password') }}"
`)

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) == 0 {
		t.Fatal("expected at least one reference from Ansible lookup")
	}

	found := false
	for _, ref := range refs {
		if ref.Path == "secret/data/prod/db" && ref.Type == "ansible_lookup" {
			found = true
			if ref.Status != "pending_validation" {
				t.Errorf("status = %q, want pending_validation", ref.Status)
			}
		}
	}
	if !found {
		t.Errorf("did not find expected ansible_lookup reference; got %+v", refs)
	}
}

func TestScan_BashVaultRead(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.sh", "#!/bin/bash\nvault kv read secret/data/prod/api\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) == 0 {
		t.Fatal("expected at least one reference from bash vault read")
	}

	found := false
	for _, ref := range refs {
		if ref.Path == "secret/data/prod/api" && ref.Type == "bash_script" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find expected bash_script reference; got %+v", refs)
	}
}

func TestScan_K8sAnnotation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deployment.yml", `apiVersion: apps/v1
metadata:
  annotations:
    vault.hashicorp.com/agent-inject-secret-db: secret/data/prod/db
`)

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) == 0 {
		t.Fatal("expected at least one reference from K8s annotation")
	}

	found := false
	for _, ref := range refs {
		if ref.Path == "secret/data/prod/db" && ref.Type == "k8s_annotation" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find expected k8s_annotation reference; got %+v", refs)
	}
}

func TestScan_GoCode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

func readSecret() {
	secret, _ := client.Logical().Read("secret/data/prod/api-key")
}
`)

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ref := range refs {
		if ref.Path == "secret/data/prod/api-key" && ref.Type == "go_code" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find expected go_code reference; got %+v", refs)
	}
}

// ---------------------------------------------------------------------------
// Scan: edge cases
// ---------------------------------------------------------------------------

func TestScan_SkipsDotDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".git/deploy.sh", "vault kv read secret/data/hidden/git\n")
	writeFile(t, dir, "deploy.sh", "vault kv read secret/data/visible/app\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	for _, ref := range refs {
		if strings.Contains(ref.Path, "hidden/git") {
			t.Errorf("should not have scanned dotdir file; got ref: %+v", ref)
		}
	}

	found := false
	for _, ref := range refs {
		if strings.Contains(ref.Path, "visible/app") {
			found = true
		}
	}
	if !found {
		t.Error("expected to find reference from visible.yml")
	}
}

func TestScan_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	bigContent := strings.Repeat("x", 10*1024*1024+1) + "\nvault_path: secret/data/large/file\n"
	writeFile(t, dir, "huge.yml", bigContent)

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	for _, ref := range refs {
		if strings.Contains(ref.Path, "large/file") {
			t.Errorf("should not have scanned >10MB file; got ref: %+v", ref)
		}
	}
}

func TestScan_SkipsExampleFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config_example.yml", "vault_path: secret/data/example/app\n")
	writeFile(t, dir, "config.example.yml", "vault_path: secret/data/example/dot\n")
	writeFile(t, dir, "sample_config.yml", "vault_path: secret/data/sample/app\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 0 {
		t.Errorf("expected no references from example files; got %+v", refs)
	}
}

func TestScan_SkipsPolicyFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "admin.hcl", "path \"secret/data/*\" {\n  capabilities = [\"read\"]\n}\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 0 {
		t.Errorf("expected no references from .hcl files; got %+v", refs)
	}
}

func TestScan_VariablesGetNeedsResolution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "playbook.yml", `---
- name: Read secret
  set_fact:
    secret: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/{{ env }}/db') }}"
`)

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ref := range refs {
		if ref.Status == "needs_resolution" {
			found = true
			if len(ref.Variables) == 0 {
				t.Error("expected Variables to be populated")
			}
			hasEnv := false
			for _, v := range ref.Variables {
				if v == "env" {
					hasEnv = true
				}
			}
			if !hasEnv {
				t.Errorf("expected 'env' in Variables, got %v", ref.Variables)
			}
		}
	}
	if !found {
		t.Errorf("expected at least one needs_resolution reference; got %+v", refs)
	}
}

func TestScan_DeduplicatesSamePathAndFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.sh", "vault kv read secret/data/dedup/test\nvault kv read secret/data/dedup/test\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, ref := range refs {
		if ref.Path == "secret/data/dedup/test" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated reference, got %d; refs: %+v", count, refs)
	}
}

func TestScan_SamePathDifferentFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.sh", "vault kv read secret/data/shared/path\n")
	writeFile(t, dir, "b.sh", "vault kv read secret/data/shared/path\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, ref := range refs {
		if ref.Path == "secret/data/shared/path" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 references (different files), got %d; refs: %+v", count, refs)
	}
}

func TestScan_EmptyRepository(t *testing.T) {
	dir := t.TempDir()

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 0 {
		t.Errorf("expected 0 references from empty dir, got %d", len(refs))
	}
}

func TestScan_InvalidRepoPath(t *testing.T) {
	s := New("/nonexistent/path/that/does/not/exist")
	_, err := s.Scan()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestScan_SubdirectoryTraversal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sub/deep/deploy.sh", "vault kv read secret/data/sub/deep\n")

	s := New(dir)
	refs, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ref := range refs {
		if ref.Path == "secret/data/sub/deep" {
			found = true
			if ref.File != filepath.Join("sub", "deep", "deploy.sh") {
				t.Errorf("file = %q, want %q", ref.File, filepath.Join("sub", "deep", "deploy.sh"))
			}
		}
	}
	if !found {
		t.Errorf("expected to find reference in subdirectory; got %+v", refs)
	}
}

// ---------------------------------------------------------------------------
// Resolver tests
// ---------------------------------------------------------------------------

func TestResolver_Resolve_AllVariablesPresent(t *testing.T) {
	vars := map[string]string{
		"env":     "production",
		"service": "api",
	}
	resolver := NewResolver(vars)

	ref := Reference{
		Path:      "secret/data/{{ env }}/{{ service }}/config",
		Status:    "needs_resolution",
		Variables: []string{"env", "service"},
	}

	resolved, missing, err := resolver.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing vars, got %v", missing)
	}
	if resolved.ResolvedPath != "secret/data/production/api/config" {
		t.Errorf("ResolvedPath = %q, want %q", resolved.ResolvedPath, "secret/data/production/api/config")
	}
	if resolved.Status != "pending_validation" {
		t.Errorf("Status = %q, want pending_validation", resolved.Status)
	}
}

func TestResolver_Resolve_MissingVariables(t *testing.T) {
	vars := map[string]string{
		"env": "production",
	}
	resolver := NewResolver(vars)

	ref := Reference{
		Path:      "secret/data/{{ env }}/{{ service }}/config",
		Status:    "needs_resolution",
		Variables: []string{"env", "service"},
	}

	resolved, missing, err := resolver.Resolve(ref)
	if err == nil {
		t.Fatal("expected error for missing variable")
	}
	if len(missing) != 1 || missing[0] != "service" {
		t.Errorf("missing = %v, want [service]", missing)
	}
	if resolved.Status != "unresolved" {
		t.Errorf("Status = %q, want unresolved", resolved.Status)
	}
	if resolved.ErrorMsg == "" {
		t.Error("expected ErrorMsg to be set")
	}
}

func TestResolver_Resolve_NoVariables(t *testing.T) {
	resolver := NewResolver(map[string]string{})

	ref := Reference{
		Path:   "secret/data/prod/db",
		Status: "pending_validation",
	}

	resolved, missing, err := resolver.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing vars, got %v", missing)
	}
	if resolved.ResolvedPath != "secret/data/prod/db" {
		t.Errorf("ResolvedPath = %q, want %q", resolved.ResolvedPath, "secret/data/prod/db")
	}
}

func TestResolver_ResolveAll_Mixed(t *testing.T) {
	vars := map[string]string{
		"env": "staging",
	}
	resolver := NewResolver(vars)

	refs := []Reference{
		{
			Path:      "secret/data/{{ env }}/db",
			Status:    "needs_resolution",
			Variables: []string{"env"},
		},
		{
			Path:      "secret/data/{{ env }}/{{ missing_var }}/config",
			Status:    "needs_resolution",
			Variables: []string{"env", "missing_var"},
		},
		{
			Path:         "secret/data/prod/static",
			ResolvedPath: "secret/data/prod/static",
			Status:       "pending_validation",
		},
	}

	resolved, unresolved := resolver.ResolveAll(refs)

	if len(resolved) != 3 {
		t.Fatalf("expected 3 resolved refs, got %d", len(resolved))
	}

	if resolved[0].ResolvedPath != "secret/data/staging/db" {
		t.Errorf("[0] ResolvedPath = %q, want %q", resolved[0].ResolvedPath, "secret/data/staging/db")
	}
	if resolved[0].Status != "pending_validation" {
		t.Errorf("[0] Status = %q, want pending_validation", resolved[0].Status)
	}

	if resolved[1].Status != "unresolved" {
		t.Errorf("[1] Status = %q, want unresolved", resolved[1].Status)
	}

	if resolved[2].Status != "pending_validation" {
		t.Errorf("[2] Status = %q, want pending_validation", resolved[2].Status)
	}

	if _, ok := unresolved["missing_var"]; !ok {
		t.Errorf("expected 'missing_var' in unresolved map, got %v", unresolved)
	}
}

func TestResolver_ResolveAll_Empty(t *testing.T) {
	resolver := NewResolver(map[string]string{})

	resolved, unresolved := resolver.ResolveAll(nil)
	if len(resolved) != 0 {
		t.Errorf("expected 0 resolved refs, got %d", len(resolved))
	}
	if len(unresolved) != 0 {
		t.Errorf("expected 0 unresolved vars, got %d", len(unresolved))
	}
}

func TestResolver_DetectVariables(t *testing.T) {
	resolver := NewResolver(nil)

	refs := []Reference{
		{Variables: []string{"env", "service"}},
		{Variables: []string{"env", "region"}},
		{Variables: nil},
		{Variables: []string{"service"}},
	}

	vars := resolver.DetectVariables(refs)
	sort.Strings(vars)

	want := []string{"env", "region", "service"}
	if len(vars) != len(want) {
		t.Fatalf("DetectVariables returned %v, want %v", vars, want)
	}
	for i, v := range vars {
		if v != want[i] {
			t.Errorf("DetectVariables()[%d] = %q, want %q", i, v, want[i])
		}
	}
}

func TestDetectVariables_PackageLevel(t *testing.T) {
	refs := []Reference{
		{Variables: []string{"cluster", "env"}},
		{Variables: []string{"env"}},
		{Variables: nil},
	}

	vars := DetectVariables(refs)
	sort.Strings(vars)

	want := []string{"cluster", "env"}
	if len(vars) != len(want) {
		t.Fatalf("DetectVariables returned %v, want %v", vars, want)
	}
	for i, v := range vars {
		if v != want[i] {
			t.Errorf("DetectVariables()[%d] = %q, want %q", i, v, want[i])
		}
	}
}
