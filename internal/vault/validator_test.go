package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestConvertToKVv2Path(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard kv v1 path gets /data/ inserted",
			path: "secret/prod/app",
			want: "secret/data/prod/app",
		},
		{
			name: "deeper kv v1 path",
			path: "secret/production/database/creds",
			want: "secret/data/production/database/creds",
		},
		{
			name: "custom mount with subpath",
			path: "kv/myapp/config",
			want: "kv/data/myapp/config",
		},
		{
			name: "already has /data/ segment unchanged",
			path: "secret/data/prod/app",
			want: "secret/data/prod/app",
		},
		{
			name: "already has /metadata/ segment unchanged",
			path: "secret/metadata/prod/app",
			want: "secret/metadata/prod/app",
		},
		{
			name: "sys/ prefix unchanged",
			path: "sys/mounts",
			want: "sys/mounts",
		},
		{
			name: "auth/ prefix unchanged",
			path: "auth/token/lookup-self",
			want: "auth/token/lookup-self",
		},
		{
			name: "cubbyhole/ prefix unchanged",
			path: "cubbyhole/my-secret",
			want: "cubbyhole/my-secret",
		},
		{
			name: "identity/ prefix unchanged",
			path: "identity/entity/name/app",
			want: "identity/entity/name/app",
		},
		{
			name: "single segment path unchanged",
			path: "secret",
			want: "secret",
		},
		{
			name: "empty string unchanged",
			path: "",
			want: "",
		},
		{
			name: "two segment path gets /data/ inserted",
			path: "secret/mykey",
			want: "secret/data/mykey",
		},
		{
			name: "path segment named data not treated as KV v2 marker",
			path: "kv/projects/data/int/myservice",
			want: "kv/data/projects/data/int/myservice",
		},
		{
			name: "deeper data segment not confused with KV v2",
			path: "secret/apps/data/config",
			want: "secret/data/apps/data/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToKVv2Path(tt.path)
			if got != tt.want {
				t.Errorf("convertToKVv2Path(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseKVv2Path(t *testing.T) {
	tests := []struct {
		name       string
		fullPath   string
		wantMount  string
		wantSecret string
	}{
		{
			name:       "standard kv v2 path",
			fullPath:   "secret/data/prod/api/key",
			wantMount:  "secret",
			wantSecret: "prod/api/key",
		},
		{
			name:       "simple kv v2 path",
			fullPath:   "kv/data/myapp",
			wantMount:  "kv",
			wantSecret: "myapp",
		},
		{
			name:       "fewer than 3 parts returns empty",
			fullPath:   "secret/data",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "single segment returns empty",
			fullPath:   "secret",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "no data segment returns empty",
			fullPath:   "secret/prod/api/key",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "empty string returns empty",
			fullPath:   "",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "deep secret path after data",
			fullPath:   "secret/data/a/b/c/d",
			wantMount:  "secret",
			wantSecret: "a/b/c/d",
		},
		{
			name:       "data as deeper segment not treated as KV v2 marker",
			fullPath:   "kv/projects/data/int/myservice",
			wantMount:  "",
			wantSecret: "",
		},
		{
			name:       "data in third position not matched",
			fullPath:   "secret/apps/data/config",
			wantMount:  "",
			wantSecret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotSecret := parseKVv2Path(tt.fullPath)
			if gotMount != tt.wantMount {
				t.Errorf("parseKVv2Path(%q) mount = %q, want %q", tt.fullPath, gotMount, tt.wantMount)
			}
			if gotSecret != tt.wantSecret {
				t.Errorf("parseKVv2Path(%q) secret = %q, want %q", tt.fullPath, gotSecret, tt.wantSecret)
			}
		})
	}
}

// --- ValidatePathProperty tests ---

// newTestValidator creates a Validator backed by a mock HTTP server.
// The handlers map is keyed by URL path (e.g. "/v1/secret/data/prod/app").
func newTestValidator(t *testing.T, handlers map[string]http.HandlerFunc) (*Validator, *httptest.Server) {
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

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	raw, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("create vault client: %v", err)
	}
	raw.SetToken("test-token")

	c := &Client{
		client:  raw,
		timeout: 5 * time.Second,
	}
	return NewValidator(c), srv
}

func writeVaultKVv2(w http.ResponseWriter, props map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data":     props,
			"metadata": map[string]interface{}{"version": 1},
		},
	})
}

func writeVaultKVv1(w http.ResponseWriter, props map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data":           props,
		"lease_duration": 2764800,
		"renewable":      false,
	})
}

func writeVaultPermissionDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []string{"permission denied"},
	})
}

func TestValidatePathProperty_OKKVv2(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv2(w, map[string]interface{}{"password": "s3cr3t", "username": "admin"})
		},
	})
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	if status != PropertyOK {
		t.Errorf("got %q, want %q", status, PropertyOK)
	}
}

func TestValidatePathProperty_OKKVv1(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv1(w, map[string]interface{}{"password": "s3cr3t", "username": "admin"})
		},
	})
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	if status != PropertyOK {
		t.Errorf("got %q, want %q", status, PropertyOK)
	}
}

func TestValidatePathProperty_PropertyMissingKVv2(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv2(w, map[string]interface{}{"username": "admin"})
		},
	})
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	if status != PropertyMissing {
		t.Errorf("got %q, want %q", status, PropertyMissing)
	}
}

func TestValidatePathProperty_PropertyMissingKVv1(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv1(w, map[string]interface{}{"username": "admin"})
		},
	})
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	if status != PropertyMissing {
		t.Errorf("got %q, want %q", status, PropertyMissing)
	}
}

func TestValidatePathProperty_PathMissing(t *testing.T) {
	v, srv := newTestValidator(t, nil)
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/missing", "password")
	if status != PropertyPathMissing {
		t.Errorf("got %q, want %q", status, PropertyPathMissing)
	}
}

func TestValidatePathProperty_AccessDenied(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultPermissionDenied(w)
		},
	})
	defer srv.Close()

	status := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	if status != PropertyAccessDenied {
		t.Errorf("got %q, want %q", status, PropertyAccessDenied)
	}
}

func TestValidatePathProperty_ContextCancelled(t *testing.T) {
	v, srv := newTestValidator(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	status := v.ValidatePathProperty(ctx, "secret/prod/app", "password")
	if status != PropertyNetworkError {
		t.Errorf("got %q, want %q", status, PropertyNetworkError)
	}
}

func TestValidatePathProperty_PropertyMissingDistinctFromPathMissing(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv2(w, map[string]interface{}{"username": "admin"})
		},
	})
	defer srv.Close()

	presentStatus := v.ValidatePathProperty(context.Background(), "secret/prod/app", "username")
	missingPropStatus := v.ValidatePathProperty(context.Background(), "secret/prod/app", "password")
	missingPathStatus := v.ValidatePathProperty(context.Background(), "secret/prod/nonexistent", "password")

	if presentStatus != PropertyOK {
		t.Errorf("present property: got %q, want %q", presentStatus, PropertyOK)
	}
	if missingPropStatus != PropertyMissing {
		t.Errorf("missing property: got %q, want %q", missingPropStatus, PropertyMissing)
	}
	if missingPathStatus != PropertyPathMissing {
		t.Errorf("missing path: got %q, want %q", missingPathStatus, PropertyPathMissing)
	}
	if missingPropStatus == missingPathStatus {
		t.Error("PROPERTY_MISSING and PATH_MISSING must be distinct status values")
	}
}

func TestExtractProperties_KVv2(t *testing.T) {
	secret := &vaultapi.Secret{
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"password": "s3cr3t",
			},
			"metadata": map[string]interface{}{"version": 1},
		},
	}
	props := extractProperties(secret)
	if props == nil {
		t.Fatal("expected non-nil properties")
	}
	if _, ok := props["password"]; !ok {
		t.Error("expected 'password' in KV v2 properties")
	}
	if _, ok := props["metadata"]; ok {
		t.Error("metadata should not be in extracted properties")
	}
}

func TestExtractProperties_KVv1(t *testing.T) {
	secret := &vaultapi.Secret{
		Data: map[string]interface{}{
			"password": "s3cr3t",
			"username": "admin",
		},
	}
	props := extractProperties(secret)
	if props == nil {
		t.Fatal("expected non-nil properties")
	}
	if _, ok := props["password"]; !ok {
		t.Error("expected 'password' in KV v1 properties")
	}
}

func TestExtractProperties_Nil(t *testing.T) {
	if extractProperties(nil) != nil {
		t.Error("expected nil for nil secret")
	}
	if extractProperties(&vaultapi.Secret{}) != nil {
		t.Error("expected nil for secret with nil Data")
	}
}

// --- ValidatePath tests ---

func TestValidatePath_OKKVv1(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/mykey": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv1(w, map[string]interface{}{"password": "s3cr3t"})
		},
	})
	defer srv.Close()

	status, err := v.ValidatePath("secret/mykey")
	if err != nil {
		t.Fatalf("ValidatePath: %v", err)
	}
	if status != "ok" {
		t.Errorf("got %q, want %q", status, "ok")
	}
}

func TestValidatePath_OKKVv2(t *testing.T) {
	// Path given in KV v1 form; data lives at the KV v2 /data/ path
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/kv/data/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv2(w, map[string]interface{}{"password": "s3cr3t"})
		},
	})
	defer srv.Close()

	status, err := v.ValidatePath("kv/prod/app")
	if err != nil {
		t.Fatalf("ValidatePath: %v", err)
	}
	if status != "ok" {
		t.Errorf("got %q, want %q", status, "ok")
	}
}

func TestValidatePath_Missing(t *testing.T) {
	v, srv := newTestValidator(t, nil) // all 404
	defer srv.Close()

	status, err := v.ValidatePath("secret/totally/missing")
	if err != nil {
		t.Fatalf("ValidatePath: %v", err)
	}
	if status != "missing" {
		t.Errorf("got %q, want %q", status, "missing")
	}
}

func TestValidatePath_AccessDenied(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultPermissionDenied(w)
		},
	})
	defer srv.Close()

	status, err := v.ValidatePath("secret/prod/app")
	if err != nil {
		t.Fatalf("ValidatePath: %v", err)
	}
	if status != "access_denied" {
		t.Errorf("got %q, want %q", status, "access_denied")
	}
}

// --- NewValidatorWithAudit ---

func TestNewValidatorWithAudit_NonNil(t *testing.T) {
	cfg := vaultapi.DefaultConfig()
	raw, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	c := &Client{client: raw, timeout: 5 * time.Second}
	v := NewValidatorWithAudit(c, nil)
	if v == nil {
		t.Error("NewValidatorWithAudit returned nil")
	}
}

// --- ListProperties tests ---

func TestListProperties_KVv2(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/data/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv2(w, map[string]interface{}{"password": "s3cr3t", "username": "admin"})
		},
	})
	defer srv.Close()

	keys, err := v.ListProperties("secret/prod/app")
	if err != nil {
		t.Fatalf("ListProperties: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d: %v", len(keys), keys)
	}
	keySet := map[string]bool{}
	for _, k := range keys {
		keySet[k] = true
	}
	if !keySet["password"] || !keySet["username"] {
		t.Errorf("expected password+username, got %v", keys)
	}
}

func TestListProperties_KVv1(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultKVv1(w, map[string]interface{}{"token": "abc123"})
		},
	})
	defer srv.Close()

	keys, err := v.ListProperties("secret/prod/app")
	if err != nil {
		t.Fatalf("ListProperties: %v", err)
	}
	if len(keys) != 1 || keys[0] != "token" {
		t.Errorf("expected [token], got %v", keys)
	}
}

func TestListProperties_MissingPath(t *testing.T) {
	v, srv := newTestValidator(t, nil)
	defer srv.Close()

	keys, err := v.ListProperties("secret/totally/missing")
	if err != nil {
		t.Fatalf("ListProperties: %v", err)
	}
	if keys != nil {
		t.Errorf("expected nil for missing path, got %v", keys)
	}
}

func TestListProperties_PermissionDenied(t *testing.T) {
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/prod/app": func(w http.ResponseWriter, r *http.Request) {
			writeVaultPermissionDenied(w)
		},
	})
	defer srv.Close()

	keys, err := v.ListProperties("secret/prod/app")
	if err != nil {
		t.Fatalf("ListProperties: unexpected error: %v", err)
	}
	if keys != nil {
		t.Errorf("expected nil for permission-denied path, got %v", keys)
	}
}

// --- CheckStaleness tests ---

func TestCheckStaleness_NoData(t *testing.T) {
	v, srv := newTestValidator(t, nil)
	defer srv.Close()

	// Non-KV-v2 path → no metadata; no audit analyzer → error
	_, _, err := v.CheckStaleness("secret/mykey", 90)
	if err == nil {
		t.Error("expected error when no staleness data is available")
	}
}

func TestCheckStaleness_FreshMetadata(t *testing.T) {
	recentTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/metadata/prod/app": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"updated_time": recentTime,
					"version":      1,
				},
			})
		},
	})
	defer srv.Close()

	isStale, timeStr, err := v.CheckStaleness("secret/data/prod/app", 90)
	if err != nil {
		t.Fatalf("CheckStaleness: %v", err)
	}
	if isStale {
		t.Error("expected not stale for secret updated 1 day ago with 90-day threshold")
	}
	if timeStr == "" {
		t.Error("expected non-empty time string")
	}
}

func TestCheckStaleness_StaleMetadata(t *testing.T) {
	staleTime := time.Now().Add(-100 * 24 * time.Hour).Format(time.RFC3339)
	v, srv := newTestValidator(t, map[string]http.HandlerFunc{
		"/v1/secret/metadata/prod/app": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"updated_time": staleTime,
					"version":      1,
				},
			})
		},
	})
	defer srv.Close()

	isStale, _, err := v.CheckStaleness("secret/data/prod/app", 90)
	if err != nil {
		t.Fatalf("CheckStaleness: %v", err)
	}
	if !isStale {
		t.Error("expected stale for secret updated 100 days ago with 90-day threshold")
	}
}
