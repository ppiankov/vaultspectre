package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
)

// spectre/v1 envelope types

type spectreEnvelope struct {
	Schema    string           `json:"schema"`
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Timestamp string           `json:"timestamp"`
	Target    spectreTarget    `json:"target"`
	Findings  []spectreFinding `json:"findings"`
	Summary   spectreSummary   `json:"summary"`
}

type spectreTarget struct {
	Type    string `json:"type"`
	URIHash string `json:"uri_hash"`
}

type spectreFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

type spectreSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// SpectreHubReporter generates spectre/v1 JSON envelope output
type SpectreHubReporter struct {
	writer io.Writer
}

// NewSpectreHubReporter creates a new SpectreHub reporter
func NewSpectreHubReporter(w io.Writer) *SpectreHubReporter {
	return &SpectreHubReporter{writer: w}
}

// Generate generates a spectre/v1 JSON envelope
func (r *SpectreHubReporter) Generate(data Data) error {
	var findings []spectreFinding
	var summary spectreSummary

	// Convert secrets to findings (skip OK status)
	for path, info := range data.Secrets {
		severity, findingID := mapStatusToFinding(info.Status)
		if findingID == "" {
			continue // skip ok status
		}

		findings = append(findings, spectreFinding{
			ID:       findingID,
			Severity: severity,
			Location: path,
			Message:  findingMessage(findingID, path),
		})

		switch severity {
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}
	}

	// Add stale secrets as separate findings (a secret can be OK but stale)
	for path, info := range data.Secrets {
		if info.IsStale && info.Status == "ok" {
			findings = append(findings, spectreFinding{
				ID:       "STALE_SECRET",
				Severity: "low",
				Location: path,
				Message:  findingMessage("STALE_SECRET", path),
			})
			summary.Low++
		}
	}

	summary.Total = len(findings)

	hash := sha256.Sum256([]byte(data.Config.VaultAddr))

	envelope := spectreEnvelope{
		Schema:    "spectre/v1",
		Tool:      data.Tool,
		Version:   data.Version,
		Timestamp: data.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Target: spectreTarget{
			Type:    "vault",
			URIHash: fmt.Sprintf("sha256:%x", hash),
		},
		Findings: findings,
		Summary:  summary,
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(envelope)
}

// mapStatusToFinding maps a secret status to (severity, finding_id).
// Returns empty strings for statuses that should be skipped.
func mapStatusToFinding(status string) (string, string) {
	switch status {
	case "missing":
		return "high", "MISSING_SECRET"
	case "access_denied":
		return "medium", "ACCESS_DENIED"
	case "invalid":
		return "medium", "INVALID_PATH"
	case "error":
		return "medium", "ERROR"
	case "dynamic":
		return "info", "DYNAMIC_PATH"
	default:
		return "", ""
	}
}

func findingMessage(id, path string) string {
	switch id {
	case "MISSING_SECRET":
		return fmt.Sprintf("Secret referenced in code but not found in Vault: %s", path)
	case "ACCESS_DENIED":
		return fmt.Sprintf("Secret exists but current token lacks permission: %s", path)
	case "INVALID_PATH":
		return fmt.Sprintf("Malformed or invalid Vault path: %s", path)
	case "STALE_SECRET":
		return fmt.Sprintf("Secret has not been accessed recently: %s", path)
	case "DYNAMIC_PATH":
		return fmt.Sprintf("Dynamic path cannot be validated statically: %s", path)
	case "ERROR":
		return fmt.Sprintf("Error validating secret path: %s", path)
	default:
		return path
	}
}
