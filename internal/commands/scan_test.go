package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/vaultspectre/internal/scanner"
)

func TestCountRefsNeedingResolution(t *testing.T) {
	tests := []struct {
		name string
		refs []scanner.Reference
		want int
	}{
		{
			name: "no refs",
			refs: nil,
			want: 0,
		},
		{
			name: "none needing resolution",
			refs: []scanner.Reference{
				{Status: "ok"},
				{Status: "pending_validation"},
			},
			want: 0,
		},
		{
			name: "some needing resolution",
			refs: []scanner.Reference{
				{Status: "needs_resolution"},
				{Status: "ok"},
				{Status: "needs_resolution"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countRefsNeedingResolution(tt.refs)
			if got != tt.want {
				t.Errorf("countRefsNeedingResolution() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCountResolvedRefs(t *testing.T) {
	tests := []struct {
		name string
		refs []scanner.Reference
		want int
	}{
		{
			name: "no refs",
			refs: nil,
			want: 0,
		},
		{
			name: "none resolved",
			refs: []scanner.Reference{
				{Path: "secret/data/a", ResolvedPath: "secret/data/a"},
				{Path: "secret/data/b"},
			},
			want: 0,
		},
		{
			name: "some resolved",
			refs: []scanner.Reference{
				{Path: "secret/data/{{ env }}/db", ResolvedPath: "secret/data/prod/db"},
				{Path: "secret/data/a", ResolvedPath: "secret/data/a"},
				{Path: "secret/data/{{ env }}/api", ResolvedPath: "secret/data/staging/api"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countResolvedRefs(tt.refs)
			if got != tt.want {
				t.Errorf("countResolvedRefs() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCountUnresolvedRefs(t *testing.T) {
	tests := []struct {
		name string
		refs []scanner.Reference
		want int
	}{
		{
			name: "no refs",
			refs: nil,
			want: 0,
		},
		{
			name: "mixed statuses",
			refs: []scanner.Reference{
				{Status: "needs_resolution"},
				{Status: "ok"},
				{Status: "pending_validation"},
				{Status: "needs_resolution"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countUnresolvedRefs(tt.refs)
			if got != tt.want {
				t.Errorf("countUnresolvedRefs() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLoadVariables_CLIFlags(t *testing.T) {
	vars, sources, err := loadVariables(
		[]string{"env=production", "service=api"},
		"", false, "",
	)
	if err != nil {
		t.Fatal(err)
	}

	if vars["env"] != "production" {
		t.Errorf("env = %q, want production", vars["env"])
	}
	if vars["service"] != "api" {
		t.Errorf("service = %q, want api", vars["service"])
	}
	if sources["env"] != "--var flag (CLI)" {
		t.Errorf("source = %q, want --var flag (CLI)", sources["env"])
	}
}

func TestLoadVariables_InvalidFormat(t *testing.T) {
	_, _, err := loadVariables([]string{"invalid_no_equals"}, "", false, "")
	if err == nil {
		t.Error("expected error for invalid --var format")
	}
}

func TestLoadVariables_VarFile(t *testing.T) {
	dir := t.TempDir()
	varFile := filepath.Join(dir, "vars.yml")
	content := "variables:\n  env: staging\n  region: us-east-1\n"
	if err := os.WriteFile(varFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, sources, err := loadVariables(nil, varFile, false, "")
	if err != nil {
		t.Fatal(err)
	}

	if vars["env"] != "staging" {
		t.Errorf("env = %q, want staging", vars["env"])
	}
	if vars["region"] != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", vars["region"])
	}
	if sources["env"] == "" {
		t.Error("expected source to be set for var-file variable")
	}
}

func TestLoadVariables_CLIPrecedence(t *testing.T) {
	dir := t.TempDir()
	varFile := filepath.Join(dir, "vars.yml")
	if err := os.WriteFile(varFile, []byte("variables:\n  env: staging\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, _, err := loadVariables([]string{"env=production"}, varFile, false, "")
	if err != nil {
		t.Fatal(err)
	}

	if vars["env"] != "production" {
		t.Errorf("CLI should take precedence: env = %q, want production", vars["env"])
	}
}

func TestLoadVarFile(t *testing.T) {
	dir := t.TempDir()
	varFile := filepath.Join(dir, "vars.yml")
	content := "variables:\n  db_host: localhost\n  db_port: \"5432\"\n"
	if err := os.WriteFile(varFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, err := loadVarFile(varFile)
	if err != nil {
		t.Fatal(err)
	}

	if vars["db_host"] != "localhost" {
		t.Errorf("db_host = %q, want localhost", vars["db_host"])
	}
	if vars["db_port"] != "5432" {
		t.Errorf("db_port = %q, want 5432", vars["db_port"])
	}
}

func TestLoadVarFile_NonExistent(t *testing.T) {
	_, err := loadVarFile("/nonexistent/path/vars.yml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseAnsibleVarsFile(t *testing.T) {
	dir := t.TempDir()
	varsFile := filepath.Join(dir, "group_vars.yml")
	content := "app_env: production\napp_port: \"8080\"\njinja_val: \"{{ some_var }}\"\nnested:\n  key: value\n"
	if err := os.WriteFile(varsFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	vars, err := parseAnsibleVarsFile(varsFile)
	if err != nil {
		t.Fatal(err)
	}

	if vars["app_env"] != "production" {
		t.Errorf("app_env = %q, want production", vars["app_env"])
	}
	if vars["app_port"] != "8080" {
		t.Errorf("app_port = %q, want 8080", vars["app_port"])
	}
	if _, exists := vars["jinja_val"]; exists {
		t.Error("jinja_val should be skipped")
	}
	// Nested maps should be skipped (not strings)
	if _, exists := vars["nested"]; exists {
		t.Error("nested map should not be extracted as string")
	}
}
