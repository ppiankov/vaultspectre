package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/ppiankov/vaultspectre/internal/scanner"
)

// Baseline holds fingerprints of known findings that should be suppressed.
type Baseline struct {
	Version      string   `json:"version"`
	Fingerprints []string `json:"fingerprints"`
	lookup       map[string]bool
}

// Load reads a baseline file. Returns empty baseline if file doesn't exist.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{lookup: make(map[string]bool)}, nil
		}
		return nil, err
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid baseline file: %w", err)
	}

	b.lookup = make(map[string]bool, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		b.lookup[fp] = true
	}

	return &b, nil
}

// Save writes the baseline to a file.
func (b *Baseline) Save(path string) error {
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

// IsKnown returns true if the finding fingerprint is in the baseline.
func (b *Baseline) IsKnown(status, path string) bool {
	return b.lookup[Fingerprint(status, path)]
}

// Filter removes known findings from references, returning only new ones.
// Returns filtered references and count of suppressed findings.
func (b *Baseline) Filter(refs []scanner.Reference) ([]scanner.Reference, int) {
	var filtered []scanner.Reference
	suppressed := 0

	for _, ref := range refs {
		// Only filter actionable statuses (not ok, pending, etc.)
		if isActionableStatus(ref.Status) && b.IsKnown(ref.Status, ref.Path) {
			suppressed++
			continue
		}
		filtered = append(filtered, ref)
	}

	return filtered, suppressed
}

// FromRefs creates a new baseline from current scan references.
func FromRefs(refs []scanner.Reference, version string) *Baseline {
	seen := make(map[string]bool)
	var fingerprints []string

	for _, ref := range refs {
		if !isActionableStatus(ref.Status) {
			continue
		}
		fp := Fingerprint(ref.Status, ref.Path)
		if !seen[fp] {
			seen[fp] = true
			fingerprints = append(fingerprints, fp)
		}
	}

	sort.Strings(fingerprints)

	return &Baseline{
		Version:      version,
		Fingerprints: fingerprints,
		lookup:       seen,
	}
}

func isActionableStatus(status string) bool {
	switch status {
	case "missing", "access_denied", "invalid", "error":
		return true
	}
	return false
}
