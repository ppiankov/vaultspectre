package eso

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDirectory_PostgresFixture(t *testing.T) {
	dir := filepath.Join("testdata")
	all, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	es := findByName(all, "external-db-postgres-secrets")
	if es == nil {
		t.Fatal("expected external-db-postgres-secrets, not found")
	}

	if es.Namespace != "docflow" {
		t.Errorf("namespace: got %q, want %q", es.Namespace, "docflow")
	}
	if es.TargetName != "db-postgres-secrets" {
		t.Errorf("target name: got %q, want %q", es.TargetName, "db-postgres-secrets")
	}
	if es.TargetNameMissing {
		t.Error("TargetNameMissing should be false when target.name is set")
	}
	if es.RefreshInterval != "1h" {
		t.Errorf("refresh interval: got %q, want %q", es.RefreshInterval, "1h")
	}
	if es.SecretStoreRef.Name != "vault-backend" {
		t.Errorf("store ref name: got %q, want %q", es.SecretStoreRef.Name, "vault-backend")
	}
	if es.SecretStoreRef.Kind != "ClusterSecretStore" {
		t.Errorf("store ref kind: got %q, want %q", es.SecretStoreRef.Kind, "ClusterSecretStore")
	}
	if len(es.Data) != 3 {
		t.Fatalf("data entries: got %d, want 3", len(es.Data))
	}

	// Spot-check first entry
	e := es.Data[0]
	if e.SecretKey != "DB_PASSWORD" {
		t.Errorf("data[0].SecretKey: got %q, want %q", e.SecretKey, "DB_PASSWORD")
	}
	if e.RemoteRefKey != "secret/docflow/prod/postgres" {
		t.Errorf("data[0].RemoteRefKey: got %q", e.RemoteRefKey)
	}
	if e.RemoteRefProperty != "password" {
		t.Errorf("data[0].RemoteRefProperty: got %q, want %q", e.RemoteRefProperty, "password")
	}
	if e.SourceLine == 0 {
		t.Error("data[0].SourceLine should be non-zero")
	}
	if !strings.HasSuffix(es.SourceFile, "external-db-postgres-secrets.yml") {
		t.Errorf("SourceFile: got %q", es.SourceFile)
	}
}

func TestParseDirectory_TargetNameMissing(t *testing.T) {
	dir := filepath.Join("testdata")
	all, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	es := findByName(all, "external-infra-secrets")
	if es == nil {
		t.Fatal("expected external-infra-secrets, not found")
	}
	if !es.TargetNameMissing {
		t.Error("TargetNameMissing should be true when spec.target is absent")
	}
	if es.TargetName != "" {
		t.Errorf("TargetName should be empty, got %q", es.TargetName)
	}
}

func TestParseDirectory_DataFrom(t *testing.T) {
	dir := filepath.Join("testdata")
	all, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	es := findByName(all, "external-kafka-secrets")
	if es == nil {
		t.Fatal("expected external-kafka-secrets, not found")
	}
	if len(es.DataFrom) != 1 {
		t.Fatalf("dataFrom entries: got %d, want 1", len(es.DataFrom))
	}
	df := es.DataFrom[0]
	if !df.PullAll {
		t.Error("DataFromEntry.PullAll should be true")
	}
	if df.RemoteRefKey != "secret/docflow/prod/kafka-tls" {
		t.Errorf("DataFromEntry.RemoteRefKey: got %q", df.RemoteRefKey)
	}
	if df.SourceLine == 0 {
		t.Error("DataFromEntry.SourceLine should be non-zero")
	}
}

func TestParseDirectory_MultiDoc(t *testing.T) {
	results, err := ParseDirectory(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	a := findByName(results, "secret-a")
	b := findByName(results, "secret-b")

	if a == nil {
		t.Fatal("expected secret-a from multi-doc.yml, not found")
	}
	if b == nil {
		t.Fatal("expected secret-b from multi-doc.yml, not found")
	}

	// secret-a has no target.name
	if !a.TargetNameMissing {
		t.Error("secret-a: TargetNameMissing should be true")
	}
	// secret-b has target.name
	if b.TargetNameMissing {
		t.Error("secret-b: TargetNameMissing should be false")
	}
	if b.TargetName != "k8s-secret-b" {
		t.Errorf("secret-b target name: got %q", b.TargetName)
	}
}

func TestParseDirectory_NonExternalSecretSkipped(t *testing.T) {
	results, err := ParseDirectory(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	// ConfigMap in not-an-external-secret.yml and the inline ConfigMap in multi-doc.yml
	// should both be absent
	for _, es := range results {
		if es.Name == "my-config" || es.Name == "should-be-skipped" {
			t.Errorf("non-ExternalSecret %q should have been silently skipped", es.Name)
		}
	}
}

func TestParseDirectory_ProvenanceSourceLine(t *testing.T) {
	results, err := ParseDirectory(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	pg := findByName(results, "external-db-postgres-secrets")
	if pg == nil {
		t.Fatal("external-db-postgres-secrets not found")
	}

	lines := make(map[int]bool)
	for _, e := range pg.Data {
		if e.SourceLine == 0 {
			t.Errorf("entry %q has SourceLine 0", e.SecretKey)
		}
		if lines[e.SourceLine] {
			t.Errorf("duplicate SourceLine %d across data entries", e.SourceLine)
		}
		lines[e.SourceLine] = true
	}
}

func TestParseDirectory_PlaceholderParsedVerbatim(t *testing.T) {
	results, err := ParseDirectory(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	es := findByName(results, "external-env-placeholder")
	if es == nil {
		t.Fatal("external-env-placeholder not found")
	}
	if len(es.Data) != 2 {
		t.Fatalf("expected 2 data entries, got %d", len(es.Data))
	}
	// Parser should preserve <ENV> verbatim — detection is WO-64's job
	for _, e := range es.Data {
		if !strings.Contains(e.RemoteRefKey, "<ENV>") {
			t.Errorf("expected <ENV> in RemoteRefKey, got %q", e.RemoteRefKey)
		}
	}
}

func TestParseReader_EmptyInput(t *testing.T) {
	results, err := parseReader(strings.NewReader(""), "empty.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestParseReader_OnlyNonMatchingDocs(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
`
	results, err := parseReader(strings.NewReader(yaml), "deploy.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-ExternalSecret doc, got %d", len(results))
	}
}

func TestParseReader_MinimalExternalSecret(t *testing.T) {
	yaml := `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: minimal
spec:
  secretStoreRef:
    name: my-store
    kind: SecretStore
  data:
    - secretKey: MY_KEY
      remoteRef:
        key: secret/path
        property: value
`
	results, err := parseReader(strings.NewReader(yaml), "minimal.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	es := results[0]
	if es.Name != "minimal" {
		t.Errorf("name: got %q", es.Name)
	}
	if !es.TargetNameMissing {
		t.Error("TargetNameMissing should be true")
	}
	if len(es.Data) != 1 {
		t.Fatalf("data entries: got %d", len(es.Data))
	}
	if es.Data[0].SecretKey != "MY_KEY" {
		t.Errorf("secretKey: got %q", es.Data[0].SecretKey)
	}
	if es.SourceFile != "minimal.yml" {
		t.Errorf("SourceFile: got %q", es.SourceFile)
	}
}

func TestParseReader_DataFromLegacyFormat(t *testing.T) {
	yaml := `
apiVersion: external-secrets.io/v1alpha1
kind: ExternalSecret
metadata:
  name: legacy
spec:
  secretStoreRef:
    name: my-store
    kind: SecretStore
  target:
    name: legacy-secret
  dataFrom:
    - key: secret/legacy/path
`
	results, err := parseReader(strings.NewReader(yaml), "legacy.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	es := results[0]
	if len(es.DataFrom) != 1 {
		t.Fatalf("dataFrom entries: got %d, want 1", len(es.DataFrom))
	}
	if es.DataFrom[0].RemoteRefKey != "secret/legacy/path" {
		t.Errorf("RemoteRefKey: got %q", es.DataFrom[0].RemoteRefKey)
	}
	if !es.DataFrom[0].PullAll {
		t.Error("PullAll should be true")
	}
}

func TestParseReader_DataFromFindSkipped(t *testing.T) {
	yaml := `
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: with-find
spec:
  secretStoreRef:
    name: my-store
    kind: SecretStore
  target:
    name: find-secret
  dataFrom:
    - find:
        path: secret/prod
        name:
          regexp: ".*"
    - extract:
        key: secret/prod/app
`
	results, err := parseReader(strings.NewReader(yaml), "find.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	es := results[0]
	// find entry has no key → skipped; only extract entry survives
	if len(es.DataFrom) != 1 {
		t.Fatalf("dataFrom entries: got %d, want 1 (find should be skipped)", len(es.DataFrom))
	}
	if es.DataFrom[0].RemoteRefKey != "secret/prod/app" {
		t.Errorf("RemoteRefKey: got %q", es.DataFrom[0].RemoteRefKey)
	}
}

// findByName returns the first ExternalSecret with the given metadata.name, or nil.
func findByName(all []*ExternalSecret, name string) *ExternalSecret {
	for _, es := range all {
		if es.Name == name {
			return es
		}
	}
	return nil
}
