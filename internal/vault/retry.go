package vault

import (
	"log/slog"
	"strings"
	"time"
)

const (
	maxRetries = 3
	baseDelay  = 500 * time.Millisecond
	maxDelay   = 5 * time.Second
)

// isRetryableError returns true if the error is transient and should be retried.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()

	// Rate limiting
	if strings.Contains(msg, "429") {
		return true
	}
	// Server errors
	if strings.Contains(msg, "500") || strings.Contains(msg, "502") ||
		strings.Contains(msg, "503") || strings.Contains(msg, "504") {
		return true
	}
	// Network errors
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "EOF") {
		return true
	}
	return false
}

// isAuthError returns true if the error is an auth/permission error that should fail fast.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "401")
}

// withRetry executes fn with exponential backoff retries for transient errors.
// Auth errors and non-retryable errors fail immediately.
func withRetry(timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	delay := baseDelay

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Auth errors fail fast
		if isAuthError(lastErr) {
			return lastErr
		}

		// Non-retryable errors fail immediately
		if !isRetryableError(lastErr) {
			return lastErr
		}

		// Don't retry after max attempts
		if attempt >= maxRetries {
			break
		}

		// Check timeout deadline
		if timeout > 0 && time.Now().Add(delay).After(deadline) {
			break
		}

		slog.Warn("vault API call failed, retrying",
			"attempt", attempt+1,
			"max_retries", maxRetries,
			"delay", delay,
			"error", lastErr,
		)

		time.Sleep(delay)
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	return lastErr
}
