package report

import (
	"encoding/json"
	"io"
)

// JSONReporter generates JSON reports
type JSONReporter struct {
	writer io.Writer
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{writer: w}
}

// Generate generates a JSON report
func (r *JSONReporter) Generate(data Data) error {
	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}
