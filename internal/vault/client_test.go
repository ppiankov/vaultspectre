package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		Address: srv.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", client.timeout, defaultTimeout)
	}
}

func TestNewClient_CustomTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		Address: srv.URL,
		Token:   "test-token",
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", client.timeout)
	}
}

func TestNewClient_WithNamespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewClient(Config{
		Address:   srv.URL,
		Token:     "test-token",
		Namespace: "admin/team1",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.GetClient().Namespace() != "admin/team1" {
		t.Errorf("namespace = %q, want admin/team1", client.GetClient().Namespace())
	}
}

func TestClient_Read_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/data/myapp" {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"password": "s3cret",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	secret, err := client.Read("secret/data/myapp")
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if secret == nil {
		t.Fatal("Read() returned nil secret")
	}
	if secret.Data == nil {
		t.Fatal("Read() returned nil data")
	}
}

func TestClient_Read_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	secret, err := client.Read("secret/data/nonexistent")
	if err != nil {
		t.Fatalf("Read() error = %v (404 should return nil secret, not error)", err)
	}
	if secret != nil {
		t.Error("Read() should return nil for 404")
	}
}

func TestClient_GetMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/secret/metadata/myapp" {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"created_time":    "2024-01-01T00:00:00Z",
					"updated_time":    "2024-06-01T00:00:00Z",
					"current_version": 3,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	secret, err := client.GetMetadata("secret", "myapp")
	if err != nil {
		t.Fatalf("GetMetadata() error = %v", err)
	}
	if secret == nil {
		t.Fatal("GetMetadata() returned nil")
	}
}

func TestClient_GetClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewClient(Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	underlying := client.GetClient()
	if underlying == nil {
		t.Fatal("GetClient() returned nil")
	}
}
