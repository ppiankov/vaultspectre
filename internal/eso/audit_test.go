package eso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/ppiankov/vaultspectre/internal/vault"
)

// --- test helpers ---

func newAuditValidator(t *testing.T, handlers map[string]http.HandlerFunc) *vault.Validator {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handlers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
	}))
	t.Cleanup(srv.Close)

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	raw, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("create vault client: %v", err)
	}
	raw.SetToken("test-token")

	// Use vault package's exported Client constructor via reflection workaround:
	// We reach into the vault package through the public API by constructing a
	// vault.Config and using vault.NewClient.
	vc, err := vault.NewClient(vault.Config{
		Address: srv.URL,
		Token:   "test-token",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	return vault.NewValidator(vc)
}

func writeKVv2Props(w http.ResponseWriter, props map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data":     props,
			"metadata": map[string]interface{}{"version": 1},
		},
	})
}

func singleES(name, targetName, path, property, secretKey string) *ExternalSecret {
	es := &ExternalSecret{
		Name:       name,
		Namespace:  "default",
		TargetName: targetName,
		SourceFile: "test.yml",
	}
	if targetName == "" {
		es.TargetNameMissing = true
	}
	if path != "" {
		es.Data = []DataEntry{{
			SecretKey:         secretKey,
			RemoteRefKey:      path,
			RemoteRefProperty: property,
			SourceLine:        10,
		}}
	}
	return es
}

func hasFinding(findings []Finding, class FindingClass) bool {
	for _, f := range findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

func countFindings(findings []Finding, class FindingClass) int {
	n := 0
	for _, f := range findings {
		if f.Class == class {
			n++
		}
	}
	return n
}

// --- tests ---

func TestAudit_TargetNameMissing(t *testing.T) {
	es := singleES("my-es", "", "", "", "")
	findings, err := Audit(context.Background(), AuditInput{ExternalSecrets: []*ExternalSecret{es}})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOTargetNameMissing) {
		t.Error("expected ESO_TARGET_NAME_MISSING finding")
	}
	f := findings[0]
	if f.Severity != SeverityWarning {
		t.Errorf("severity: got %q, want %q", f.Severity, SeverityWarning)
	}
}

func TestAudit_EnvPlaceholderUnsubstituted(t *testing.T) {
	es := singleES("my-es", "my-secret", "secret/docflow/<ENV>/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{ExternalSecrets: []*ExternalSecret{es}})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOEnvPlaceholderUnsubstituted) {
		t.Error("expected ESO_ENV_PLACEHOLDER_UNSUBSTITUTED finding")
	}
	f := findingByClass(findings, ESOEnvPlaceholderUnsubstituted)
	if f.Severity != SeverityError {
		t.Errorf("severity: got %q, want %q", f.Severity, SeverityError)
	}
	if f.Source.Line != 10 {
		t.Errorf("source line: got %d, want 10", f.Source.Line)
	}
}

func TestAudit_EnvPlaceholderCustom(t *testing.T) {
	es := singleES("my-es", "my-secret", "secret/docflow/{ENVIRONMENT}/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		EnvPlaceholder:  "{ENVIRONMENT}",
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOEnvPlaceholderUnsubstituted) {
		t.Error("expected finding with custom placeholder")
	}
}

func TestAudit_DuplicateKey(t *testing.T) {
	es1 := singleES("es1", "shared-secret", "secret/path", "password", "DB_PASS")
	es2 := singleES("es2", "shared-secret", "secret/path2", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{ExternalSecrets: []*ExternalSecret{es1, es2}})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESODuplicateKey) {
		t.Error("expected ESO_DUPLICATE_KEY finding")
	}
	f := findingByClass(findings, ESODuplicateKey)
	if f.Severity != SeverityWarning {
		t.Errorf("severity: got %q, want warning", f.Severity)
	}
}

func TestAudit_VaultPathMissing(t *testing.T) {
	v := newAuditValidator(t, nil) // all paths return 404
	es := singleES("my-es", "my-secret", "secret/missing/path", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       v,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOVaultPathMissing) {
		t.Error("expected ESO_VAULT_PATH_MISSING finding")
	}
	f := findingByClass(findings, ESOVaultPathMissing)
	if f.Severity != SeverityError {
		t.Errorf("severity: got %q, want error", f.Severity)
	}
}

func TestAudit_VaultPropertyMissing(t *testing.T) {
	v := newAuditValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/db": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{"username": "admin"})
		},
	})
	es := singleES("my-es", "my-secret", "secret/prod/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       v,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOVaultPropertyMissing) {
		t.Error("expected ESO_VAULT_PROPERTY_MISSING finding")
	}
	f := findingByClass(findings, ESOVaultPropertyMissing)
	if f.Property != "password" {
		t.Errorf("finding property: got %q, want %q", f.Property, "password")
	}
}

func TestAudit_VaultPathMissingSkippedWhenPlaceholder(t *testing.T) {
	v := newAuditValidator(t, nil) // all paths return 404
	es := singleES("my-es", "my-secret", "secret/docflow/<ENV>/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       v,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	// Should emit placeholder finding but NOT a vault path-missing finding
	if !hasFinding(findings, ESOEnvPlaceholderUnsubstituted) {
		t.Error("expected ESO_ENV_PLACEHOLDER_UNSUBSTITUTED")
	}
	if hasFinding(findings, ESOVaultPathMissing) {
		t.Error("should not emit ESO_VAULT_PATH_MISSING for a placeholder path")
	}
}

func TestAudit_VaultOrphanedProperty(t *testing.T) {
	v := newAuditValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/db": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{
				"password":  "s3cr3t",
				"username":  "admin",
				"debug_key": "orphan",
			})
		},
	})
	es := singleES("my-es", "my-secret", "secret/prod/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       v,
		VaultListMount:  "secret",
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	orphaned := countFindings(findings, ESOVaultOrphanedProperty)
	if orphaned != 2 {
		t.Errorf("expected 2 orphaned property findings (username, debug_key), got %d", orphaned)
	}
	for _, f := range findings {
		if f.Class == ESOVaultOrphanedProperty && f.Severity != SeverityInfo {
			t.Errorf("orphaned property severity: got %q, want info", f.Severity)
		}
	}
}

func TestAudit_VaultOrphanedSkippedWithoutMount(t *testing.T) {
	v := newAuditValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/db": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{"password": "s3cr3t", "orphan": "value"})
		},
	})
	es := singleES("my-es", "my-secret", "secret/prod/db", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       v,
		VaultListMount:  "", // not set
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasFinding(findings, ESOVaultOrphanedProperty) {
		t.Error("ESO_VAULT_ORPHANED_PROPERTY should not fire when VaultListMount is empty")
	}
}

func TestAudit_K8sKeyUnused(t *testing.T) {
	es := &ExternalSecret{
		Name:       "my-es",
		Namespace:  "default",
		TargetName: "my-secret",
		SourceFile: "test.yml",
		Data: []DataEntry{
			{SecretKey: "DB_PASS", RemoteRefKey: "secret/prod/db", RemoteRefProperty: "password", SourceLine: 10},
			{SecretKey: "UNUSED_KEY", RemoteRefKey: "secret/prod/db", RemoteRefProperty: "unused", SourceLine: 14},
		},
	}
	consumers := &ConsumerScanResult{
		Consumers: []ConsumedKey{
			{SecretName: "my-secret", Key: "DB_PASS", ConsumerKind: "env", SourceFile: "deployment.yml", SourceLine: 20},
		},
	}
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Consumers:       consumers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOK8sKeyUnused) {
		t.Error("expected ESO_K8S_KEY_UNUSED finding for UNUSED_KEY")
	}
	f := findingByClass(findings, ESOK8sKeyUnused)
	if f.SecretKey != "UNUSED_KEY" {
		t.Errorf("unused key: got %q, want %q", f.SecretKey, "UNUSED_KEY")
	}
	if f.Severity != SeverityInfo {
		t.Errorf("severity: got %q, want info", f.Severity)
	}
}

func TestAudit_K8sKeyUnused_PullAllExempts(t *testing.T) {
	es := &ExternalSecret{
		Name:       "my-es",
		TargetName: "my-secret",
		SourceFile: "test.yml",
		Data: []DataEntry{
			{SecretKey: "DB_PASS", RemoteRefKey: "secret/prod/db", RemoteRefProperty: "password", SourceLine: 10},
		},
	}
	// Consumer uses envFrom (PullAll) — no individual key should be flagged as unused
	consumers := &ConsumerScanResult{
		Consumers: []ConsumedKey{
			{SecretName: "my-secret", PullAll: true, ConsumerKind: "envFrom", SourceFile: "deploy.yml", SourceLine: 5},
		},
	}
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Consumers:       consumers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasFinding(findings, ESOK8sKeyUnused) {
		t.Error("PullAll consumer should exempt all keys from UNUSED finding")
	}
}

func TestAudit_K8sKeyMissing(t *testing.T) {
	es := singleES("my-es", "my-secret", "secret/prod/db", "password", "DB_PASS")
	consumers := &ConsumerScanResult{
		Consumers: []ConsumedKey{
			{SecretName: "my-secret", Key: "DB_PASS", ConsumerKind: "env", SourceFile: "deploy.yml", SourceLine: 5},
			{SecretName: "my-secret", Key: "MISSING_KEY", ConsumerKind: "env", SourceFile: "deploy.yml", SourceLine: 9},
		},
	}
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Consumers:       consumers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !hasFinding(findings, ESOK8sKeyMissing) {
		t.Error("expected ESO_K8S_KEY_MISSING finding for MISSING_KEY")
	}
	f := findingByClass(findings, ESOK8sKeyMissing)
	if f.SecretKey != "MISSING_KEY" {
		t.Errorf("missing key: got %q, want %q", f.SecretKey, "MISSING_KEY")
	}
	if f.Severity != SeverityError {
		t.Errorf("severity: got %q, want error", f.Severity)
	}
}

func TestAudit_K8sKeyMissing_DataFromExempts(t *testing.T) {
	es := &ExternalSecret{
		Name:       "my-es",
		TargetName: "my-secret",
		SourceFile: "test.yml",
		DataFrom: []DataFromEntry{
			{RemoteRefKey: "secret/prod/all", PullAll: true, SourceLine: 10},
		},
	}
	// Consumer references a key not explicitly in Data — but DataFrom covers the whole Secret
	consumers := &ConsumerScanResult{
		Consumers: []ConsumedKey{
			{SecretName: "my-secret", Key: "ANY_KEY", ConsumerKind: "env", SourceFile: "deploy.yml", SourceLine: 5},
		},
	}
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Consumers:       consumers,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasFinding(findings, ESOK8sKeyMissing) {
		t.Error("DataFrom should exempt key from ESO_K8S_KEY_MISSING check")
	}
}

func TestAudit_ValidatorNilSkipsVaultChecks(t *testing.T) {
	es := singleES("my-es", "my-secret", "secret/totally/missing", "password", "DB_PASS")
	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es},
		Validator:       nil, // offline mode
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if hasFinding(findings, ESOVaultPathMissing) {
		t.Error("vault checks should be skipped when Validator is nil")
	}
	if hasFinding(findings, ESOVaultPropertyMissing) {
		t.Error("vault checks should be skipped when Validator is nil")
	}
}

func TestAudit_DeduplicatesVaultCalls(t *testing.T) {
	callCount := 0
	v := newAuditValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/db": func(w http.ResponseWriter, r *http.Request) {
			callCount++
			writeKVv2Props(w, map[string]interface{}{"password": "s3cr3t"})
		},
	})
	// Two ExternalSecrets referencing the same path+property
	es1 := singleES("es1", "secret-a", "secret/prod/db", "password", "DB_PASS")
	es2 := singleES("es2", "secret-b", "secret/prod/db", "password", "DB_PASS")
	_, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{es1, es2},
		Validator:       v,
	})
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 Vault call for deduplicated path+property, got %d", callCount)
	}
}

func TestAudit_EndToEnd_DocflowFixture(t *testing.T) {
	// Full docflow fixture: postgres ExternalSecret + kafka with dataFrom + missing infra path
	v := newAuditValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/docflow/prod/postgres": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{
				"password": "pgpass",
				"username": "pguser",
				"host":     "pg.internal",
			})
		},
		"/v1/secret/data/docflow/prod/kafka": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{
				"password": "kafkapass",
				"username": "kafkauser",
			})
		},
		// kafka-tls path exists
		"/v1/secret/data/docflow/prod/kafka-tls": func(w http.ResponseWriter, r *http.Request) {
			writeKVv2Props(w, map[string]interface{}{"ca.crt": "cert"})
		},
		// infra path is missing (returns 404 via default handler)
	})

	pgES := &ExternalSecret{
		Name: "external-db-postgres-secrets", Namespace: "docflow",
		TargetName: "db-postgres-secrets", SourceFile: "external-db-postgres-secrets.yml",
		Data: []DataEntry{
			{SecretKey: "DB_PASSWORD", RemoteRefKey: "secret/docflow/prod/postgres", RemoteRefProperty: "password", SourceLine: 10},
			{SecretKey: "DB_USER", RemoteRefKey: "secret/docflow/prod/postgres", RemoteRefProperty: "username", SourceLine: 13},
		},
	}
	kafkaES := &ExternalSecret{
		Name: "external-kafka-secrets", Namespace: "docflow",
		TargetName: "kafka-secrets", SourceFile: "external-kafka-secrets.yml",
		Data: []DataEntry{
			{SecretKey: "KAFKA_PASSWORD", RemoteRefKey: "secret/docflow/prod/kafka", RemoteRefProperty: "password", SourceLine: 10},
		},
		DataFrom: []DataFromEntry{
			{RemoteRefKey: "secret/docflow/prod/kafka-tls", PullAll: true, SourceLine: 14},
		},
	}
	infraES := &ExternalSecret{
		Name: "external-infra-secrets", Namespace: "docflow",
		TargetNameMissing: true, SourceFile: "external-infra-secrets.yml",
		Data: []DataEntry{
			{SecretKey: "INFRA_TOKEN", RemoteRefKey: "secret/docflow/prod/infra", RemoteRefProperty: "token", SourceLine: 10},
		},
	}

	consumers := &ConsumerScanResult{
		Consumers: []ConsumedKey{
			{SecretName: "db-postgres-secrets", Key: "DB_PASSWORD", ConsumerKind: "env", SourceFile: "values-docflow.yaml", SourceLine: 8},
			{SecretName: "db-postgres-secrets", Key: "DB_USER", ConsumerKind: "env", SourceFile: "values-docflow.yaml", SourceLine: 12},
			{SecretName: "kafka-secrets", Key: "KAFKA_PASSWORD", ConsumerKind: "env", SourceFile: "values-docflow.yaml", SourceLine: 16},
			// INFRA_TOKEN is NOT consumed → should appear as unused
		},
	}

	findings, err := Audit(context.Background(), AuditInput{
		ExternalSecrets: []*ExternalSecret{pgES, kafkaES, infraES},
		Consumers:       consumers,
		Validator:       v,
	})
	if err != nil {
		t.Fatalf("Audit end-to-end: %v", err)
	}

	// Expect: ESO_TARGET_NAME_MISSING for infra, ESO_VAULT_PATH_MISSING for infra token path,
	// ESO_K8S_KEY_UNUSED for INFRA_TOKEN
	if !hasFinding(findings, ESOTargetNameMissing) {
		t.Error("expected ESO_TARGET_NAME_MISSING for external-infra-secrets")
	}
	if !hasFinding(findings, ESOVaultPathMissing) {
		t.Error("expected ESO_VAULT_PATH_MISSING for secret/docflow/prod/infra")
	}
	if !hasFinding(findings, ESOK8sKeyUnused) {
		t.Error("expected ESO_K8S_KEY_UNUSED for INFRA_TOKEN")
	}
	// No false positives on postgres or kafka
	for _, f := range findings {
		if f.Class == ESOVaultPathMissing && f.Path == "secret/docflow/prod/postgres" {
			t.Errorf("false positive: ESO_VAULT_PATH_MISSING for postgres path")
		}
		if f.Class == ESOVaultPropertyMissing && (f.Path == "secret/docflow/prod/postgres" || f.Path == "secret/docflow/prod/kafka") {
			t.Errorf("false positive: ESO_VAULT_PROPERTY_MISSING for existing property at %s", f.Path)
		}
	}
}

func TestAudit_SeverityMapping(t *testing.T) {
	// Verify severity constants match the WO specification
	if SeverityError != "error" {
		t.Errorf("SeverityError: %q", SeverityError)
	}
	if SeverityWarning != "warning" {
		t.Errorf("SeverityWarning: %q", SeverityWarning)
	}
	if SeverityInfo != "info" {
		t.Errorf("SeverityInfo: %q", SeverityInfo)
	}
}

// findingByClass returns the first finding with the given class, or a zero value.
func findingByClass(findings []Finding, class FindingClass) Finding {
	for _, f := range findings {
		if f.Class == class {
			return f
		}
	}
	return Finding{}
}
