package grep

// MatchedKey represents a single key match within a secret.
type MatchedKey struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"` // Only populated when show-values is true
	Type  string `json:"type"`            // "string", "json_blob", etc.
}

// PathMatch represents a Vault path that matched the grep criteria.
type PathMatch struct {
	Path string       `json:"path"`
	Keys []MatchedKey `json:"keys"`
}

// GrepResult holds the full grep output.
type GrepResult struct {
	Matches      []PathMatch `json:"matches"`
	TotalScanned int         `json:"total_scanned"`
	TotalSkipped int         `json:"total_skipped"` // Permission denied
	MatchCount   int         `json:"match_count"`
}
