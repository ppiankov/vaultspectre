package verify

import (
	"testing"
	"time"
)

func TestFormatVerifierOK(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"CLICKHOUSE_HOST":     "10.0.0.1",
		"CLICKHOUSE_PASSWORD": "secret",
		"CLICKHOUSE_USER":     "admin",
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusOK {
		t.Errorf("status = %s, want ok; details: %s", result.Status, result.Details)
	}
}

func TestFormatVerifierJsonBlobString(t *testing.T) {
	v := NewFormatVerifier()
	// json_blob stored as bare string instead of JSON object
	data := map[string]interface{}{
		"clickhouse": "not-a-json-object",
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusFormatError {
		t.Errorf("status = %s, want format_error", result.Status)
	}
	if result.Details == "" {
		t.Error("expected details for format error")
	}
}

func TestFormatVerifierJsonBlobValid(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"clickhouse": `{"host":"10.0.0.1","port":9000,"username":"admin","password":"secret"}`,
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusOK {
		t.Errorf("status = %s, want ok; details: %s", result.Status, result.Details)
	}
}

func TestFormatVerifierJsonBlobInvalid(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"clickhouse": `{"host":"10.0.0.1", broken json`,
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusFormatError {
		t.Errorf("status = %s, want format_error", result.Status)
	}
}

func TestFormatVerifierURIMissing(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"GRAFANA_URL": "not-a-url",
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusFormatError {
		t.Errorf("status = %s, want format_error for URI without scheme", result.Status)
	}
}

func TestFormatVerifierURIValid(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"GRAFANA_URL": "https://grafana.internal/d/api-latency",
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusOK {
		t.Errorf("status = %s, want ok; details: %s", result.Status, result.Details)
	}
}

func TestFormatVerifierEmptyJsonBlob(t *testing.T) {
	v := NewFormatVerifier()
	data := map[string]interface{}{
		"clickhouse": "",
	}
	result := v.Verify("kv/test", data, 5*time.Second)
	if result.Status != StatusFormatError {
		t.Errorf("status = %s, want format_error for empty json_blob", result.Status)
	}
}

func TestDetectCredentialType(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
		want string
	}{
		{
			name: "clickhouse standard",
			data: map[string]interface{}{"CLICKHOUSE_HOST": "h", "CLICKHOUSE_PASSWORD": "p", "CLICKHOUSE_USER": "u"},
			want: "clickhouse",
		},
		{
			name: "clickhouse stat",
			data: map[string]interface{}{"STAT_CLICKHOUSE_HOST": "h", "STAT_CLICKHOUSE_PASSWORD": "p"},
			want: "clickhouse_stat",
		},
		{
			name: "clickhouse blob",
			data: map[string]interface{}{"clickhouse": `{"host":"h"}`},
			want: "clickhouse_blob",
		},
		{
			name: "postgresql",
			data: map[string]interface{}{"POSTGRES_HOST": "h", "POSTGRES_PASSWORD": "p"},
			want: "postgresql",
		},
		{
			name: "database url",
			data: map[string]interface{}{"DATABASE_URL": "postgres://..."},
			want: "postgresql_url",
		},
		{
			name: "unknown",
			data: map[string]interface{}{"FOO": "bar", "BAZ": "qux"},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCredentialType(tt.data)
			if got != tt.want {
				t.Errorf("DetectCredentialType() = %q, want %q", got, tt.want)
			}
		})
	}
}
