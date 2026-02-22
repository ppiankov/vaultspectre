package vault

import (
	"fmt"
	"testing"
	"time"
)

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"permission denied", fmt.Errorf("permission denied"), false},
		{"403", fmt.Errorf("403 Forbidden"), false},
		{"429 rate limit", fmt.Errorf("429 Too Many Requests"), true},
		{"500 internal", fmt.Errorf("500 Internal Server Error"), true},
		{"502 bad gateway", fmt.Errorf("502 Bad Gateway"), true},
		{"503 unavailable", fmt.Errorf("503 Service Unavailable"), true},
		{"504 timeout", fmt.Errorf("504 Gateway Timeout"), true},
		{"connection refused", fmt.Errorf("connection refused"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"no such host", fmt.Errorf("no such host"), true},
		{"EOF", fmt.Errorf("unexpected EOF"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableError(tt.err)
			if got != tt.want {
				t.Errorf("isRetryableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"permission denied", fmt.Errorf("permission denied"), true},
		{"403 forbidden", fmt.Errorf("403 Forbidden"), true},
		{"401 unauthorized", fmt.Errorf("401 Unauthorized"), true},
		{"503 unavailable", fmt.Errorf("503 Service Unavailable"), false},
		{"connection refused", fmt.Errorf("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthError(tt.err)
			if got != tt.want {
				t.Errorf("isAuthError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestWithRetry_Success(t *testing.T) {
	calls := 0
	err := withRetry(30*time.Second, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestWithRetry_AuthErrorFailsFast(t *testing.T) {
	calls := 0
	err := withRetry(30*time.Second, func() error {
		calls++
		return fmt.Errorf("permission denied")
	})
	if err == nil {
		t.Error("expected error")
	}
	if calls != 1 {
		t.Errorf("auth error should fail fast: expected 1 call, got %d", calls)
	}
}

func TestWithRetry_NonRetryableFailsFast(t *testing.T) {
	calls := 0
	err := withRetry(30*time.Second, func() error {
		calls++
		return fmt.Errorf("invalid path format")
	})
	if err == nil {
		t.Error("expected error")
	}
	if calls != 1 {
		t.Errorf("non-retryable should fail fast: expected 1 call, got %d", calls)
	}
}

func TestWithRetry_RetryableRetriesUpToMax(t *testing.T) {
	calls := 0
	err := withRetry(30*time.Second, func() error {
		calls++
		return fmt.Errorf("503 Service Unavailable")
	})
	if err == nil {
		t.Error("expected error after retries exhausted")
	}
	// 1 initial + 3 retries = 4 total
	if calls != maxRetries+1 {
		t.Errorf("expected %d calls (1 + %d retries), got %d", maxRetries+1, maxRetries, calls)
	}
}

func TestWithRetry_RetryableSucceedsOnRetry(t *testing.T) {
	calls := 0
	err := withRetry(30*time.Second, func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("503 Service Unavailable")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected success on third attempt, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestWithRetry_TimeoutStopsRetries(t *testing.T) {
	calls := 0
	// Very short timeout — should stop retrying quickly
	err := withRetry(1*time.Millisecond, func() error {
		calls++
		return fmt.Errorf("503 Service Unavailable")
	})
	if err == nil {
		t.Error("expected error")
	}
	// With 1ms timeout, should get at most 1-2 calls (first attempt always runs)
	if calls > 2 {
		t.Errorf("timeout should limit retries: expected <=2 calls, got %d", calls)
	}
}
