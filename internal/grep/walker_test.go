package grep

import (
	"errors"
	"strings"
	"testing"
)

func TestIsPermissionError_Denied(t *testing.T) {
	if !isPermissionError(errors.New("permission denied")) {
		t.Error("should be permission error for 'permission denied'")
	}
	if !isPermissionError(errors.New("403 Forbidden")) {
		t.Error("should be permission error for '403'")
	}
}

func TestIsPermissionError_Other(t *testing.T) {
	if isPermissionError(errors.New("connection refused")) {
		t.Error("connection refused should not be a permission error")
	}
	if isPermissionError(errors.New("timeout")) {
		t.Error("timeout should not be a permission error")
	}
}

func TestSanitizeError_Short(t *testing.T) {
	err := errors.New("short error message")
	got := sanitizeError(err)
	if got != "short error message" {
		t.Errorf("got %q, want original message", got)
	}
}

func TestSanitizeError_LongTruncated(t *testing.T) {
	long := strings.Repeat("x", 250)
	err := errors.New(long)
	got := sanitizeError(err)
	if len(got) > 220 {
		t.Errorf("sanitized message should be truncated, got len=%d", len(got))
	}
	if !strings.HasSuffix(got, "[truncated]") {
		t.Error("truncated message should end with [truncated]")
	}
}
