package report

import (
	"encoding/json"
	"io"
)

// SARIF 2.1.0 structures

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	Properties       sarifRuleProps  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// Rule definitions
var sarifRules = []sarifRule{
	{
		ID:               "vaultspectre/MISSING_SECRET",
		ShortDescription: sarifMessage{Text: "Secret path referenced in code does not exist in Vault"},
		DefaultConfig:    sarifRuleConfig{Level: "error"},
		Properties:       sarifRuleProps{Tags: []string{"security", "vault"}},
	},
	{
		ID:               "vaultspectre/STALE_SECRET",
		ShortDescription: sarifMessage{Text: "Secret has not been accessed or modified within threshold"},
		DefaultConfig:    sarifRuleConfig{Level: "warning"},
		Properties:       sarifRuleProps{Tags: []string{"security", "vault"}},
	},
	{
		ID:               "vaultspectre/ACCESS_DENIED",
		ShortDescription: sarifMessage{Text: "Token lacks permission to read this secret path"},
		DefaultConfig:    sarifRuleConfig{Level: "warning"},
		Properties:       sarifRuleProps{Tags: []string{"security", "vault"}},
	},
	{
		ID:               "vaultspectre/INVALID_PATH",
		ShortDescription: sarifMessage{Text: "Secret path is malformed or structurally invalid"},
		DefaultConfig:    sarifRuleConfig{Level: "error"},
		Properties:       sarifRuleProps{Tags: []string{"security", "vault"}},
	},
	{
		ID:               "vaultspectre/ERROR",
		ShortDescription: sarifMessage{Text: "Error occurred while validating secret path"},
		DefaultConfig:    sarifRuleConfig{Level: "warning"},
		Properties:       sarifRuleProps{Tags: []string{"security", "vault"}},
	},
}

// statusToRuleID maps vaultspectre status to SARIF rule ID.
func statusToRuleID(status string) string {
	switch status {
	case "missing":
		return "vaultspectre/MISSING_SECRET"
	case "access_denied":
		return "vaultspectre/ACCESS_DENIED"
	case "invalid":
		return "vaultspectre/INVALID_PATH"
	case "error":
		return "vaultspectre/ERROR"
	default:
		return ""
	}
}

// statusToLevel maps vaultspectre status to SARIF level.
func statusToLevel(status string) string {
	switch status {
	case "missing", "invalid":
		return "error"
	case "access_denied", "error":
		return "warning"
	default:
		return "note"
	}
}

// SARIFReporter generates SARIF 2.1.0 reports
type SARIFReporter struct {
	writer io.Writer
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter(w io.Writer) *SARIFReporter {
	return &SARIFReporter{writer: w}
}

// Generate generates a SARIF 2.1.0 report
func (r *SARIFReporter) Generate(data Data) error {
	var results []sarifResult

	// Convert findings to SARIF results
	for _, ref := range data.References {
		ruleID := statusToRuleID(ref.Status)
		if ruleID == "" {
			continue // Skip ok, dynamic, needs_resolution, etc.
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  statusToLevel(ref.Status),
			Message: sarifMessage{
				Text: buildMessage(ref.Status, ref.Path, ref.ErrorMsg),
			},
		}

		if ref.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: ref.File},
				},
			}
			if ref.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: ref.Line}
			}
			result.Locations = []sarifLocation{loc}
		}

		results = append(results, result)
	}

	// Also emit stale secrets as findings
	for _, ref := range data.References {
		if !ref.IsStale {
			continue
		}
		result := sarifResult{
			RuleID: "vaultspectre/STALE_SECRET",
			Level:  "warning",
			Message: sarifMessage{
				Text: "Secret " + ref.Path + " is stale: " + ref.LastAccessed,
			},
		}
		if ref.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: ref.File},
				},
			}
			if ref.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: ref.Line}
			}
			result.Locations = []sarifLocation{loc}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "vaultspectre",
						Version:        data.Version,
						InformationURI: "https://github.com/ppiankov/vaultspectre",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func buildMessage(status, path, errMsg string) string {
	switch status {
	case "missing":
		return "Secret path " + path + " is referenced in code but does not exist in Vault"
	case "access_denied":
		return "Token lacks permission to read " + path
	case "invalid":
		return "Secret path " + path + " is malformed or structurally invalid"
	case "error":
		msg := "Error validating " + path
		if errMsg != "" {
			msg += ": " + errMsg
		}
		return msg
	default:
		return "Issue with " + path
	}
}
