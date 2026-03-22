package commands

import (
	"fmt"
	"testing"
)

func TestExitCodeFromError_Nil(t *testing.T) {
	if got := ExitCodeFromError(nil); got != ExitSuccess {
		t.Errorf("ExitCodeFromError(nil) = %d, want %d", got, ExitSuccess)
	}
}

func TestExitCodeFromError_ExitCodeError(t *testing.T) {
	tests := []struct {
		code int
		want int
	}{
		{ExitBadArgs, ExitBadArgs},
		{ExitNetwork, ExitNetwork},
		{ExitFindings, ExitFindings},
		{ExitError, ExitError},
	}

	for _, tt := range tests {
		err := newExitError(tt.code, "test error")
		got := ExitCodeFromError(err)
		if got != tt.want {
			t.Errorf("ExitCodeFromError(code=%d) = %d, want %d", tt.code, got, tt.want)
		}
	}
}

func TestExitCodeFromError_GenericError(t *testing.T) {
	err := fmt.Errorf("generic error")
	if got := ExitCodeFromError(err); got != ExitError {
		t.Errorf("ExitCodeFromError(generic) = %d, want %d", got, ExitError)
	}
}

func TestExitCodeError_Error(t *testing.T) {
	err := newExitError(ExitFindings, "found %d issues", 3)
	if err.Error() != "found 3 issues" {
		t.Errorf("Error() = %q, want %q", err.Error(), "found 3 issues")
	}
}

func TestExitCodeError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("inner")
	err := &ExitCodeError{Code: ExitNetwork, Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap() should return inner error")
	}
}
