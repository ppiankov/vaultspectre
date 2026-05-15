package eso

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScanConsumers_Deployment(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "deployment.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	// env references from main container
	assertConsumedKey(t, result, "db-postgres-secrets", "DB_PASSWORD", "env")
	assertConsumedKey(t, result, "db-postgres-secrets", "DB_USER", "env")

	// envFrom main container
	assertConsumedKey(t, result, "infra-secrets", "", "envFrom")

	// sidecar container
	assertConsumedKey(t, result, "metrics-secrets", "token", "sidecar.env")

	// volume mount
	assertConsumedKey(t, result, "kerberos-keytab", "", "volume")
}

func TestScanConsumers_ReloaderAnnotation(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "deployment.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	if len(result.ReloaderReferences) != 2 {
		t.Fatalf("reloader references: got %d, want 2", len(result.ReloaderReferences))
	}
	names := make(map[string]bool)
	for _, ref := range result.ReloaderReferences {
		names[ref.SecretName] = true
		if ref.SourceLine == 0 {
			t.Errorf("ReloaderReference %q has SourceLine 0", ref.SecretName)
		}
	}
	if !names["db-postgres-secrets"] {
		t.Error("expected reloader reference to db-postgres-secrets")
	}
	if !names["kafka-secrets"] {
		t.Error("expected reloader reference to kafka-secrets")
	}
}

func TestScanConsumers_StatefulSetInitContainers(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "statefulset.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	assertConsumedKey(t, result, "krb5-secrets", "realm", "initContainer.env")
	assertConsumedKey(t, result, "krb5-all-secrets", "", "initContainer.envFrom")
	assertConsumedKey(t, result, "kafka-secrets", "KAFKA_PASSWORD", "env")
	assertConsumedKey(t, result, "kafka-secrets", "KAFKA_USERNAME", "env")
	assertConsumedKey(t, result, "worker-secrets", "", "envFrom")
}

func TestScanConsumers_CronJob(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "cronjob.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	assertConsumedKey(t, result, "report-secrets", "db_password", "env")
	assertConsumedKey(t, result, "smtp-secrets", "password", "env")

	if len(result.ReloaderReferences) != 1 || result.ReloaderReferences[0].SecretName != "report-secrets" {
		t.Errorf("expected 1 reloader reference to report-secrets, got %v", result.ReloaderReferences)
	}
}

func TestScanConsumers_HelmValuesDocflow(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "values-docflow.yaml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	assertConsumedKey(t, result, "db-postgres-secrets", "DB_PASSWORD", "env")
	assertConsumedKey(t, result, "db-postgres-secrets", "DB_USER", "env")
	assertConsumedKey(t, result, "kafka-secrets", "KAFKA_PASSWORD", "env")

	// Plain value (APP_ENV) should not appear as a consumed key
	for _, c := range result.Consumers {
		if c.SecretName == "" {
			t.Errorf("consumer with empty SecretName found: %+v", c)
		}
	}
}

func TestScanConsumers_MultiEnvValues(t *testing.T) {
	result, err := ScanConsumers([]string{
		filepath.Join("testdata", "consumers", "values-docflow.yaml"),
		filepath.Join("testdata", "consumers", "values-fftt.yaml"),
		filepath.Join("testdata", "consumers", "values-platform-tests.yaml"),
	})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}

	// fftt env
	assertConsumedKey(t, result, "db-postgres-secrets-fftt", "DB_PASSWORD", "env")

	// platform-tests — valid entry
	assertConsumedKey(t, result, "test-secrets", "api_key", "env")

	// template variable must be skipped
	for _, c := range result.Consumers {
		if strings.Contains(c.SecretName, "{{") {
			t.Errorf("template variable leaked into consumers: %q", c.SecretName)
		}
	}
}

func TestScanConsumers_SkipsConfigMap(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "not-a-workload.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}
	if len(result.Consumers) != 0 {
		t.Errorf("expected 0 consumers from ConfigMap, got %d", len(result.Consumers))
	}
}

func TestScanConsumers_Directory(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}
	if len(result.Consumers) == 0 {
		t.Error("expected consumers from directory scan, got 0")
	}
	// All entries must have provenance
	for _, c := range result.Consumers {
		if c.SourceFile == "" {
			t.Errorf("consumer %q/%q missing SourceFile", c.SecretName, c.Key)
		}
		if c.SourceLine == 0 {
			t.Errorf("consumer %q/%q has SourceLine 0", c.SecretName, c.Key)
		}
	}
}

func TestScanConsumers_VolumeIsPullAll(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "deployment.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}
	for _, c := range result.Consumers {
		if c.ConsumerKind == "volume" && !c.PullAll {
			t.Errorf("volume consumer %q should have PullAll=true", c.SecretName)
		}
	}
}

func TestScanConsumers_EnvFromIsPullAll(t *testing.T) {
	result, err := ScanConsumers([]string{filepath.Join("testdata", "consumers", "deployment.yml")})
	if err != nil {
		t.Fatalf("ScanConsumers: %v", err)
	}
	for _, c := range result.Consumers {
		if c.ConsumerKind == "envFrom" && !c.PullAll {
			t.Errorf("envFrom consumer %q should have PullAll=true", c.SecretName)
		}
	}
}

func TestScanConsumers_EmptyInput(t *testing.T) {
	result, err := ScanConsumers([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Consumers) != 0 || len(result.ReloaderReferences) != 0 {
		t.Error("expected empty result for empty input")
	}
}

func TestScanConsumerReader_TemplateVarsSkipped(t *testing.T) {
	yaml := `
replicaCount: 1
env:
  - name: STATIC
    valueFrom:
      secretKeyRef:
        name: real-secret
        key: my_key
  - name: DYNAMIC
    valueFrom:
      secretKeyRef:
        name: "{{ .Values.secretRef }}"
        key: my_key
`
	result := &ConsumerScanResult{}
	if err := scanConsumerReader(strings.NewReader(yaml), "test.yaml", result); err != nil {
		t.Fatalf("scanConsumerReader: %v", err)
	}
	if len(result.Consumers) != 1 {
		t.Fatalf("expected 1 consumer (template skipped), got %d", len(result.Consumers))
	}
	if result.Consumers[0].SecretName != "real-secret" {
		t.Errorf("unexpected consumer: %q", result.Consumers[0].SecretName)
	}
}

func TestScanConsumerReader_ReloaderCSVParsed(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
spec:
  template:
    metadata:
      annotations:
        secret.reloader.stakater.com/reload: "secret-a, secret-b , secret-c"
    spec:
      containers:
        - name: app
          image: app:latest
`
	result := &ConsumerScanResult{}
	if err := scanConsumerReader(strings.NewReader(yaml), "test.yaml", result); err != nil {
		t.Fatalf("scanConsumerReader: %v", err)
	}
	if len(result.ReloaderReferences) != 3 {
		t.Fatalf("expected 3 reloader references, got %d", len(result.ReloaderReferences))
	}
	names := make(map[string]bool)
	for _, ref := range result.ReloaderReferences {
		names[ref.SecretName] = true
	}
	for _, want := range []string{"secret-a", "secret-b", "secret-c"} {
		if !names[want] {
			t.Errorf("expected reloader reference %q", want)
		}
	}
}

// assertConsumedKey checks that a ConsumedKey with the given secretName, key, and consumerKind exists.
func assertConsumedKey(t *testing.T, result *ConsumerScanResult, secretName, key, consumerKind string) {
	t.Helper()
	for _, c := range result.Consumers {
		if c.SecretName == secretName && c.Key == key && c.ConsumerKind == consumerKind {
			return
		}
	}
	t.Errorf("expected ConsumedKey{SecretName:%q, Key:%q, ConsumerKind:%q} not found", secretName, key, consumerKind)
}
