package commands

import "fmt"

// Exit codes for CI pipeline clarity
const (
	ExitSuccess  = 0 // No issues found
	ExitError    = 1 // Internal/unexpected error
	ExitBadArgs  = 2 // Invalid arguments or config
	ExitNotFound = 3 // Grep: no matches found
	ExitNetwork  = 5 // Network/connectivity error (Vault unreachable)
	ExitFindings = 6 // Findings detected (missing/stale/invalid secrets)
)

// ExitCodeError wraps an error with a specific exit code
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error {
	return e.Err
}

// ExitCodeFromError extracts the exit code from an error, defaulting to ExitError
func ExitCodeFromError(err error) int {
	if err == nil {
		return ExitSuccess
	}
	if ece, ok := err.(*ExitCodeError); ok {
		return ece.Code
	}
	return ExitError
}

func newExitError(code int, format string, args ...interface{}) *ExitCodeError {
	return &ExitCodeError{Code: code, Err: fmt.Errorf(format, args...)}
}
