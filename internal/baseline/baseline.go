package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/ppiankov/vaultspectre/internal/scanner"
)

// Entry represents a single suppressed finding in the shared baseline schema.
type Entry struct {
	ID           string     `json:"id"`                   // Deterministic hash
	Tool         string     `json:"tool"`                 // "vaultspectre" or "clickspectre"
	RuleID       string     `json:"rule_id"`              // e.g. "vault/missing", "vault/stale"
	Resource     string     `json:"resource"`             // Vault path or table name
	Reason       string     `json:"reason,omitempty"`     // Why suppressed
	SuppressedAt time.Time  `json:"suppressed_at"`        // When suppressed
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // Auto-expire (nil = never)
}

// Baseline holds suppressed findings. Supports both legacy (fingerprints-only)
// and shared (entries with metadata) formats.
type Baseline struct {
	SchemaVersion int      `json:"schema_version"`         // 2 = shared schema, 0/missing = legacy
	Version       string   `json:"version"`                // Tool version that created the baseline
	Entries       []Entry  `json:"entries,omitempty"`      // Shared schema entries
	Fingerprints  []string `json:"fingerprints,omitempty"` // Legacy: kept for migration
	lookup        map[string]bool
}

// Load reads a baseline file. Detects legacy vs shared format.
// Returns empty baseline if file doesn't exist.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{SchemaVersion: 2, lookup: make(map[string]bool)}, nil
		}
		return nil, err
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid baseline file: %w", err)
	}

	// Detect legacy format: has fingerprints but no schema_version or entries
	if b.SchemaVersion == 0 && len(b.Fingerprints) > 0 && len(b.Entries) == 0 {
		slog.Warn("legacy baseline format detected, migrating to shared schema",
			"path", path, "fingerprints", len(b.Fingerprints))
		b = migrateLegacy(b)

		// Back up old file
		bakPath := path + ".bak"
		if cpErr := os.WriteFile(bakPath, data, 0o644); cpErr == nil {
			slog.Info("backed up legacy baseline", "path", bakPath)
		}
	}

	b.buildLookup()
	return &b, nil
}

// Save writes the baseline to a file in shared schema format.
func (b *Baseline) Save(path string) error {
	b.SchemaVersion = 2
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Fingerprint generates a SHA-256 fingerprint for a finding (status + path).
func Fingerprint(status, path string) string {
	h := sha256.Sum256([]byte(status + ":" + path))
	return fmt.Sprintf("%x", h)
}

// IsKnown returns true if the finding is suppressed and not expired.
func (b *Baseline) IsKnown(status, path string) bool {
	fp := Fingerprint(status, path)
	if !b.lookup[fp] {
		return false
	}

	// Check expiry
	for _, e := range b.Entries {
		if e.ID == fp && e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
			return false // Expired
		}
	}
	return true
}

// Filter removes known findings from references, returning only new ones.
// Returns filtered references and count of suppressed findings.
func (b *Baseline) Filter(refs []scanner.Reference) ([]scanner.Reference, int) {
	var filtered []scanner.Reference
	suppressed := 0

	for _, ref := range refs {
		if isActionableStatus(ref.Status) && b.IsKnown(ref.Status, ref.Path) {
			suppressed++
			continue
		}
		filtered = append(filtered, ref)
	}

	return filtered, suppressed
}

// FromRefs creates a new baseline from current scan references.
// expiresIn is optional — if > 0, entries auto-expire after this duration.
func FromRefs(refs []scanner.Reference, version string, expiresIn ...time.Duration) *Baseline {
	seen := make(map[string]bool)
	var entries []Entry
	now := time.Now()

	var expiry *time.Time
	if len(expiresIn) > 0 && expiresIn[0] > 0 {
		t := now.Add(expiresIn[0])
		expiry = &t
	}

	for _, ref := range refs {
		if !isActionableStatus(ref.Status) {
			continue
		}
		fp := Fingerprint(ref.Status, ref.Path)
		if seen[fp] {
			continue
		}
		seen[fp] = true

		entries = append(entries, Entry{
			ID:           fp,
			Tool:         "vaultspectre",
			RuleID:       "vault/" + ref.Status,
			Resource:     ref.Path,
			SuppressedAt: now,
			ExpiresAt:    expiry,
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

	// Also maintain fingerprints for cross-tool compatibility
	fingerprints := make([]string, len(entries))
	for i, e := range entries {
		fingerprints[i] = e.ID
	}

	b := &Baseline{
		SchemaVersion: 2,
		Version:       version,
		Entries:       entries,
		Fingerprints:  fingerprints,
		lookup:        seen,
	}
	return b
}

func (b *Baseline) buildLookup() {
	b.lookup = make(map[string]bool, len(b.Entries)+len(b.Fingerprints))
	for _, e := range b.Entries {
		b.lookup[e.ID] = true
	}
	for _, fp := range b.Fingerprints {
		b.lookup[fp] = true
	}
}

func migrateLegacy(old Baseline) Baseline {
	now := time.Now()
	entries := make([]Entry, len(old.Fingerprints))
	for i, fp := range old.Fingerprints {
		entries[i] = Entry{
			ID:           fp,
			Tool:         "vaultspectre",
			RuleID:       "vault/unknown",
			Resource:     "(migrated from legacy baseline)",
			SuppressedAt: now,
		}
	}

	return Baseline{
		SchemaVersion: 2,
		Version:       old.Version,
		Entries:       entries,
		Fingerprints:  old.Fingerprints,
	}
}

func isActionableStatus(status string) bool {
	switch status {
	case "missing", "access_denied", "invalid", "error":
		return true
	}
	return false
}
