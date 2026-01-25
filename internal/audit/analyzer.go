package audit

import "time"

// Analyzer analyzes audit log access patterns
type Analyzer struct {
	accessMap AccessMap
}

// NewAnalyzer creates a new audit log analyzer
func NewAnalyzer(accessMap AccessMap) *Analyzer {
	return &Analyzer{accessMap: accessMap}
}

// GetLastAccess returns last access time for a given secret path
// Returns zero time if path not found in audit logs
func (a *Analyzer) GetLastAccess(path string) (time.Time, int, bool) {
	if info, exists := a.accessMap[path]; exists {
		return info.LastAccessTime, info.AccessCount, true
	}
	return time.Time{}, 0, false
}

// IsStale checks if a secret hasn't been accessed in thresholdDays
func (a *Analyzer) IsStale(path string, thresholdDays int) (bool, int) {
	if info, exists := a.accessMap[path]; exists {
		return info.DaysSinceAccess > thresholdDays, info.DaysSinceAccess
	}
	// Not found in audit logs = potentially very stale (no access recorded)
	return true, -1 // -1 indicates unknown
}

// GetAccessInfo returns full access information for a path
func (a *Analyzer) GetAccessInfo(path string) (*AccessInfo, bool) {
	info, exists := a.accessMap[path]
	return info, exists
}

// GetTotalPaths returns count of unique paths accessed
func (a *Analyzer) GetTotalPaths() int {
	return len(a.accessMap)
}
