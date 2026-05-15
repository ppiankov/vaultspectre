package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ppiankov/vaultspectre/internal/eso"
)

// ESOReportData is the input to ESO reporters.
type ESOReportData struct {
	Tool      string
	Version   string
	Timestamp time.Time
	ESODir    string
	Findings  []eso.Finding
}

// ESOTextReporter writes human-readable grouped output.
type ESOTextReporter struct {
	writer io.Writer
}

// NewESOTextReporter creates a text reporter for ESO findings.
func NewESOTextReporter(w io.Writer) *ESOTextReporter {
	return &ESOTextReporter{writer: w}
}

// Generate writes the ESO findings to the writer.
func (r *ESOTextReporter) Generate(data ESOReportData) error {
	w := r.writer
	fmt.Fprintf(w, "=== ESO Audit: %s ===\n\n", data.ESODir)

	groups := groupBySeverity(data.Findings)
	for _, sev := range []eso.Severity{eso.SeverityError, eso.SeverityWarning, eso.SeverityInfo} {
		fs := groups[sev]
		if len(fs) == 0 {
			continue
		}
		noun := "findings"
		if len(fs) == 1 {
			noun = "finding"
		}
		fmt.Fprintf(w, "%s (%d %s):\n", strings.ToUpper(string(sev)), len(fs), noun)
		for _, f := range fs {
			loc := f.Source.File
			if f.Source.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Source.Line)
			}
			if loc == "" {
				loc = "<unknown>"
			}
			fmt.Fprintf(w, "  [%s] %s\n", f.Class, loc)
			fmt.Fprintf(w, "    %s\n", f.Message)
			if f.Remediation != "" {
				fmt.Fprintf(w, "    Remediation: %s\n", f.Remediation)
			}
			fmt.Fprintln(w)
		}
	}

	nerr, nwarn, ninfo := countBySeverity(data.Findings)
	fmt.Fprintf(w, "Summary: %d error, %d warning, %d info\n", nerr, nwarn, ninfo)
	return nil
}

// ESOJSONReporter writes JSON output for ESO findings.
type ESOJSONReporter struct {
	writer io.Writer
}

// NewESOJSONReporter creates a JSON reporter for ESO findings.
func NewESOJSONReporter(w io.Writer) *ESOJSONReporter {
	return &ESOJSONReporter{writer: w}
}

type esoJSONEnvelope struct {
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	Timestamp string         `json:"timestamp"`
	ESODir    string         `json:"eso_dir"`
	Summary   esoJSONSummary `json:"summary"`
	Findings  []esoJSONFind  `json:"findings"`
}

type esoJSONSummary struct {
	Total   int `json:"total"`
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
}

type esoJSONFind struct {
	Class       string        `json:"class"`
	Severity    string        `json:"severity"`
	Message     string        `json:"message"`
	Path        string        `json:"path,omitempty"`
	Property    string        `json:"property,omitempty"`
	SecretName  string        `json:"secret_name,omitempty"`
	SecretKey   string        `json:"secret_key,omitempty"`
	Source      esoJSONSource `json:"source"`
	Remediation string        `json:"remediation,omitempty"`
}

type esoJSONSource struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

// Generate writes the ESO findings as JSON.
func (r *ESOJSONReporter) Generate(data ESOReportData) error {
	nerr, nwarn, ninfo := countBySeverity(data.Findings)
	finds := make([]esoJSONFind, len(data.Findings))
	for i, f := range data.Findings {
		finds[i] = esoJSONFind{
			Class:       string(f.Class),
			Severity:    string(f.Severity),
			Message:     f.Message,
			Path:        f.Path,
			Property:    f.Property,
			SecretName:  f.SecretName,
			SecretKey:   f.SecretKey,
			Source:      esoJSONSource{File: f.Source.File, Line: f.Source.Line},
			Remediation: f.Remediation,
		}
	}
	env := esoJSONEnvelope{
		Tool:      data.Tool,
		Version:   data.Version,
		Timestamp: data.Timestamp.UTC().Format(time.RFC3339),
		ESODir:    data.ESODir,
		Summary:   esoJSONSummary{Total: len(data.Findings), Error: nerr, Warning: nwarn, Info: ninfo},
		Findings:  finds,
	}
	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// ESOSARIFReporter writes SARIF 2.1.0 output for ESO findings.
type ESOSARIFReporter struct {
	writer io.Writer
}

// NewESOSARIFReporter creates a SARIF reporter for ESO findings.
func NewESOSARIFReporter(w io.Writer) *ESOSARIFReporter {
	return &ESOSARIFReporter{writer: w}
}

var esoSARIFRules = []sarifRule{
	{ID: "vaultspectre/ESO_VAULT_PATH_MISSING", ShortDescription: sarifMessage{Text: "ESO references Vault path that does not exist"}, DefaultConfig: sarifRuleConfig{Level: "error"}},
	{ID: "vaultspectre/ESO_VAULT_PROPERTY_MISSING", ShortDescription: sarifMessage{Text: "Vault path exists but referenced property is absent"}, DefaultConfig: sarifRuleConfig{Level: "error"}},
	{ID: "vaultspectre/ESO_VAULT_ORPHANED_PROPERTY", ShortDescription: sarifMessage{Text: "Vault property not referenced by any ExternalSecret"}, DefaultConfig: sarifRuleConfig{Level: "note"}},
	{ID: "vaultspectre/ESO_K8S_KEY_UNUSED", ShortDescription: sarifMessage{Text: "ExternalSecret produces a Secret key no consumer references"}, DefaultConfig: sarifRuleConfig{Level: "note"}},
	{ID: "vaultspectre/ESO_K8S_KEY_MISSING", ShortDescription: sarifMessage{Text: "Consumer references a Secret key no ExternalSecret produces"}, DefaultConfig: sarifRuleConfig{Level: "error"}},
	{ID: "vaultspectre/ESO_TARGET_NAME_MISSING", ShortDescription: sarifMessage{Text: "ExternalSecret has no spec.target.name"}, DefaultConfig: sarifRuleConfig{Level: "warning"}},
	{ID: "vaultspectre/ESO_DUPLICATE_KEY", ShortDescription: sarifMessage{Text: "Same secretKey produced by multiple ExternalSecrets"}, DefaultConfig: sarifRuleConfig{Level: "warning"}},
	{ID: "vaultspectre/ESO_ENV_PLACEHOLDER_UNSUBSTITUTED", ShortDescription: sarifMessage{Text: "Unsubstituted environment placeholder in Vault path"}, DefaultConfig: sarifRuleConfig{Level: "error"}},
	{ID: "vaultspectre/ESO_RELOADER_TARGET_MISSING", ShortDescription: sarifMessage{Text: "Reloader annotation references Secret no ExternalSecret produces"}, DefaultConfig: sarifRuleConfig{Level: "error"}},
	{ID: "vaultspectre/ESO_REFRESH_INTERVAL_AGGRESSIVE", ShortDescription: sarifMessage{Text: "ExternalSecret refreshInterval is below recommended threshold"}, DefaultConfig: sarifRuleConfig{Level: "warning"}},
	{ID: "vaultspectre/ESO_VAULT_DUPLICATE_SOURCE", ShortDescription: sarifMessage{Text: "Same Vault path+property pulled by multiple ExternalSecrets"}, DefaultConfig: sarifRuleConfig{Level: "warning"}},
}

func esoSeverityToSARIFLevel(sev eso.Severity) string {
	switch sev {
	case eso.SeverityError:
		return "error"
	case eso.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// Generate writes the ESO findings as SARIF 2.1.0.
func (r *ESOSARIFReporter) Generate(data ESOReportData) error {
	var results []sarifResult
	for _, f := range data.Findings {
		result := sarifResult{
			RuleID:  "vaultspectre/" + string(f.Class),
			Level:   esoSeverityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}
		if f.Source.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Source.File},
				},
			}
			if f.Source.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Source.Line}
			}
			result.Locations = []sarifLocation{loc}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "vaultspectre",
					Version:        data.Version,
					InformationURI: "https://github.com/ppiankov/vaultspectre",
					Rules:          esoSARIFRules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ESOSpectreHubReporter writes spectre/v1 envelope output for ESO findings.
type ESOSpectreHubReporter struct {
	writer io.Writer
}

// NewESOSpectreHubReporter creates a SpectreHub reporter for ESO findings.
func NewESOSpectreHubReporter(w io.Writer) *ESOSpectreHubReporter {
	return &ESOSpectreHubReporter{writer: w}
}

// Generate writes ESO findings as a spectre/v1 envelope.
func (r *ESOSpectreHubReporter) Generate(data ESOReportData) error {
	var findings []spectreFinding
	var summary spectreSummary

	for _, f := range data.Findings {
		sev := esoSeverityToSpectreSeverity(f.Severity)
		loc := f.Source.File
		if f.Source.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Source.Line)
		}
		findings = append(findings, spectreFinding{
			ID:       string(f.Class),
			Severity: sev,
			Location: loc,
			Message:  f.Message,
		})
		switch sev {
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
	summary.Total = len(findings)

	envelope := spectreEnvelope{
		Schema:    "spectre/v1",
		Tool:      data.Tool,
		Version:   data.Version,
		Timestamp: data.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Target:    spectreTarget{Type: "eso", URIHash: "eso:" + data.ESODir},
		Findings:  findings,
		Summary:   summary,
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func esoSeverityToSpectreSeverity(sev eso.Severity) string {
	switch sev {
	case eso.SeverityError:
		return "high"
	case eso.SeverityWarning:
		return "medium"
	default:
		return "info"
	}
}

// helpers

func groupBySeverity(findings []eso.Finding) map[eso.Severity][]eso.Finding {
	m := make(map[eso.Severity][]eso.Finding)
	for _, f := range findings {
		m[f.Severity] = append(m[f.Severity], f)
	}
	// Sort within each group by file:line for deterministic output
	for sev := range m {
		sort.Slice(m[sev], func(i, j int) bool {
			a, b := m[sev][i], m[sev][j]
			if a.Source.File != b.Source.File {
				return a.Source.File < b.Source.File
			}
			return a.Source.Line < b.Source.Line
		})
	}
	return m
}

func countBySeverity(findings []eso.Finding) (nerr, nwarn, ninfo int) {
	for _, f := range findings {
		switch f.Severity {
		case eso.SeverityError:
			nerr++
		case eso.SeverityWarning:
			nwarn++
		default:
			ninfo++
		}
	}
	return
}
