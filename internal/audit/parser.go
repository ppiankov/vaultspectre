package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Parser parses Vault audit log files
type Parser struct {
	filePath string
}

// NewParser creates a new audit log parser
func NewParser(filePath string) *Parser {
	return &Parser{filePath: filePath}
}

// Parse reads audit log file and returns access information per path
// windowDays: only include access within last N days (0 = all time)
func (p *Parser) Parse(windowDays int) (AccessMap, error) {
	file, err := os.Open(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer func() { _ = file.Close() }()

	accessMap := make(AccessMap)
	scanner := bufio.NewScanner(file)

	// Set scanner buffer size for large log lines
	const maxCapacity = 1024 * 1024 // 1MB per line
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	cutoffTime := time.Time{}
	if windowDays > 0 {
		cutoffTime = time.Now().AddDate(0, 0, -windowDays)
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()

		// Parse JSON line
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Log warning but continue (some lines might be malformed)
			continue
		}

		// Only process request entries (not responses)
		if entry.Type != "request" {
			continue
		}

		// Only process read operations
		if entry.Request == nil || entry.Request.Operation != "read" {
			continue
		}

		// Skip if outside time window
		if !cutoffTime.IsZero() && entry.Time.Before(cutoffTime) {
			continue
		}

		// Update access map
		path := entry.Request.Path
		if info, exists := accessMap[path]; exists {
			info.AccessCount++
			if entry.Time.After(info.LastAccessTime) {
				info.LastAccessTime = entry.Time
			}
			if entry.Time.Before(info.FirstAccessTime) {
				info.FirstAccessTime = entry.Time
			}
			// Track unique source IPs
			if !contains(info.SourceIPs, entry.Request.RemoteAddress) {
				info.SourceIPs = append(info.SourceIPs, entry.Request.RemoteAddress)
			}
		} else {
			accessMap[path] = &AccessInfo{
				Path:            path,
				LastAccessTime:  entry.Time,
				FirstAccessTime: entry.Time,
				AccessCount:     1,
				SourceIPs:       []string{entry.Request.RemoteAddress},
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading audit log: %w", err)
	}

	// Calculate days since access for all paths
	now := time.Now()
	for _, info := range accessMap {
		info.DaysSinceAccess = int(now.Sub(info.LastAccessTime).Hours() / 24)
		info.UniqueClients = len(info.SourceIPs)
	}

	return accessMap, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
