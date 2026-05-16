package commands

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestAuthFlagsForCI_Token(t *testing.T) {
	ciAuthMethod = "token"
	got := authFlagsForCI()
	if !strings.Contains(got, "VAULT_TOKEN") {
		t.Errorf("token auth flags should reference VAULT_TOKEN, got: %q", got)
	}
}

func TestAuthFlagsForCI_AppRole(t *testing.T) {
	ciAuthMethod = "approle"
	got := authFlagsForCI()
	if !strings.Contains(got, "approle") {
		t.Errorf("approle auth flags should reference approle, got: %q", got)
	}
	if !strings.Contains(got, "VAULT_ROLE_ID") {
		t.Errorf("approle auth flags should reference VAULT_ROLE_ID, got: %q", got)
	}
}

func TestAuthFlagsForCI_Kubernetes(t *testing.T) {
	ciAuthMethod = "kubernetes"
	got := authFlagsForCI()
	if !strings.Contains(got, "kubernetes") {
		t.Errorf("kubernetes auth flags should reference kubernetes, got: %q", got)
	}
}

func TestGitlabVarsForAuth_AllMethods(t *testing.T) {
	for _, method := range []string{"token", "approle", "kubernetes"} {
		ciAuthMethod = method
		got := gitlabVarsForAuth()
		if got == "" {
			t.Errorf("gitlabVarsForAuth(%q) returned empty string", method)
		}
	}
}

func TestGithubEnvForAuth_AllMethods(t *testing.T) {
	ciAuthMethod = "token"
	got := githubEnvForAuth()
	if !strings.Contains(got, "VAULT_TOKEN") {
		t.Errorf("token method should reference VAULT_TOKEN, got: %q", got)
	}

	ciAuthMethod = "approle"
	got = githubEnvForAuth()
	if !strings.Contains(got, "VAULT_ROLE_ID") {
		t.Errorf("approle method should reference VAULT_ROLE_ID, got: %q", got)
	}

	ciAuthMethod = "kubernetes"
	got = githubEnvForAuth()
	// kubernetes returns empty string — no extra env vars needed
	if got != "" {
		t.Errorf("kubernetes method should return empty string, got: %q", got)
	}
}

func TestRunCIInit_GitLab(t *testing.T) {
	ciFormat = "gitlab"
	ciAuthMethod = "token"
	ciStage = "validate"

	out := captureStdout(func() {
		err := runCIInit(ciInitCmd, nil)
		if err != nil {
			t.Errorf("runCIInit gitlab: %v", err)
		}
	})

	if !strings.Contains(out, "gitlab-ci.yml") {
		t.Error("GitLab output should mention .gitlab-ci.yml")
	}
	if !strings.Contains(out, "vaultspectre:scan") {
		t.Error("GitLab output should contain job name")
	}
}

func TestRunCIInit_GitHub(t *testing.T) {
	ciFormat = "github"
	ciAuthMethod = "token"
	ciStage = "validate"

	out := captureStdout(func() {
		err := runCIInit(ciInitCmd, nil)
		if err != nil {
			t.Errorf("runCIInit github: %v", err)
		}
	})

	if !strings.Contains(out, "vaultspectre.yml") {
		t.Error("GitHub output should mention vaultspectre.yml")
	}
	if !strings.Contains(out, "VaultSpectre Scan") {
		t.Error("GitHub output should contain workflow name")
	}
}

func TestRunCIInit_InvalidFormat(t *testing.T) {
	ciFormat = "jenkins"
	err := runCIInit(ciInitCmd, nil)
	if err == nil {
		t.Error("expected error for unsupported CI format")
	}
	if ExitCodeFromError(err) != ExitBadArgs {
		t.Errorf("expected ExitBadArgs, got %d", ExitCodeFromError(err))
	}
}

func TestPrintGitLabCI_ContainsKeyElements(t *testing.T) {
	ciAuthMethod = "token"
	ciStage = "security"
	out := captureStdout(printGitLabCI)
	if !strings.Contains(out, "security") {
		t.Error("GitLab CI output should use the stage name")
	}
	if !strings.Contains(out, "vaultspectre scan") {
		t.Error("GitLab CI output should contain vaultspectre scan command")
	}
}

func TestPrintGitHubActions_ContainsKeyElements(t *testing.T) {
	ciAuthMethod = "token"
	out := captureStdout(printGitHubActions)
	if !strings.Contains(out, "actions/checkout") {
		t.Error("GitHub Actions output should include checkout action")
	}
	if !strings.Contains(out, "vaultspectre scan") {
		t.Error("GitHub Actions output should contain vaultspectre scan command")
	}
}
