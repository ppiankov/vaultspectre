package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSlackNotifier_Notify_SendsMessage(t *testing.T) {
	var received slackMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewSlackNotifier(srv.URL)
	err := notifier.Notify(Event{
		New: []Finding{
			{Path: "secret/data/prod/db", Status: "missing", File: "deploy.yml"},
		},
		Total:    1,
		RepoPath: "/app",
	})
	if err != nil {
		t.Fatalf("Notify() error = %v", err)
	}

	if !strings.Contains(received.Text, "1 new finding") {
		t.Errorf("message missing new finding count: %q", received.Text)
	}
	if !strings.Contains(received.Text, "secret/data/prod/db") {
		t.Errorf("message missing finding path: %q", received.Text)
	}
	if !strings.Contains(received.Text, "/app") {
		t.Errorf("message missing repo path: %q", received.Text)
	}
}

func TestSlackNotifier_Notify_SkipsEmptyEvent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()

	notifier := NewSlackNotifier(srv.URL)
	err := notifier.Notify(Event{Total: 5})
	if err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if called {
		t.Error("should not call webhook when no new/resolved findings")
	}
}

func TestSlackNotifier_Notify_ResolvedFindings(t *testing.T) {
	var received slackMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewSlackNotifier(srv.URL)
	err := notifier.Notify(Event{
		Resolved: []Finding{
			{Path: "secret/data/staging/api", Status: "missing", File: "app.yml"},
		},
		Total: 0,
	})
	if err != nil {
		t.Fatalf("Notify() error = %v", err)
	}

	if !strings.Contains(received.Text, "1 resolved") {
		t.Errorf("message missing resolved count: %q", received.Text)
	}
}

func TestSlackNotifier_Notify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	notifier := NewSlackNotifier(srv.URL)
	err := notifier.Notify(Event{
		New:   []Finding{{Path: "x", Status: "missing", File: "y"}},
		Total: 1,
	})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestSlackNotifier_Notify_ConnectionError(t *testing.T) {
	notifier := NewSlackNotifier("http://localhost:1") // port 1 should refuse
	err := notifier.Notify(Event{
		New:   []Finding{{Path: "x", Status: "missing", File: "y"}},
		Total: 1,
	})
	if err == nil {
		t.Error("expected error for connection failure")
	}
}
