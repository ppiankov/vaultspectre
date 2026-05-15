package commands

import (
	"strings"
	"testing"

	"github.com/ppiankov/vaultspectre/internal/eso"
)

func TestEsoCmdRequiresEsoDir(t *testing.T) {
	esoDir = ""
	err := runEso(esoCmd, []string{})
	if err == nil {
		t.Fatal("expected error when --eso-dir is missing")
	}
	if !strings.Contains(err.Error(), "--eso-dir") {
		t.Errorf("error should mention --eso-dir, got: %v", err)
	}
	if ExitCodeFromError(err) != ExitBadArgs {
		t.Errorf("exit code: want ExitBadArgs (%d), got %d", ExitBadArgs, ExitCodeFromError(err))
	}
}

func TestEsoCmdOfflineMode(t *testing.T) {
	esoDir = "../eso/testdata"
	esoHelmValues = []string{}
	esoManifests = []string{}
	esoEnvValue = ""
	esoVaultListMount = ""
	esoFailOnFindings = false
	outputFormat = "text"
	vaultAddr = ""

	if err := runEso(esoCmd, []string{}); err != nil {
		t.Fatalf("offline eso run failed: %v", err)
	}
}

func TestSubstituteEnvInSecrets(t *testing.T) {
	originals := []*eso.ExternalSecret{
		{
			Name:       "my-es",
			TargetName: "my-secret",
			SourceFile: "test.yml",
			Data: []eso.DataEntry{
				{SecretKey: "KEY", RemoteRefKey: "secret/docflow/<ENV>/db", RemoteRefProperty: "password"},
			},
			DataFrom: []eso.DataFromEntry{
				{RemoteRefKey: "secret/docflow/<ENV>/all", PullAll: true},
			},
		},
	}

	result := substituteEnvInSecrets(originals, "<ENV>", "prod")

	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].Data[0].RemoteRefKey != "secret/docflow/prod/db" {
		t.Errorf("Data substitution failed: got %q", result[0].Data[0].RemoteRefKey)
	}
	if result[0].DataFrom[0].RemoteRefKey != "secret/docflow/prod/all" {
		t.Errorf("DataFrom substitution failed: got %q", result[0].DataFrom[0].RemoteRefKey)
	}
	// originals must be unchanged
	if originals[0].Data[0].RemoteRefKey != "secret/docflow/<ENV>/db" {
		t.Error("original ExternalSecret was mutated")
	}
}

func TestPlaceholderForAudit(t *testing.T) {
	esoEnvValue = ""
	if p := placeholderForAudit(); p != "<ENV>" {
		t.Errorf("without --env: got %q, want %q", p, "<ENV>")
	}
	esoEnvValue = "prod"
	if p := placeholderForAudit(); p == "<ENV>" {
		t.Error("with --env: should return sentinel, not <ENV>")
	}
	esoEnvValue = ""
}
