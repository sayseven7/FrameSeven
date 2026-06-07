// Package report defines the scan result structure and renders it as
// human-readable text and as structured JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// Report is the full result of a scan.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Target        string            `json:"target"`
	StartedAt     time.Time         `json:"started_at"`
	Duration      string            `json:"duration"`
	Surface       recon.Surface     `json:"surface"`
	Findings      []finding.Finding `json:"findings"`
	Errors        []ScanErrorV1     `json:"errors,omitempty"`
}

// ScanErrorV1 records a module that could not complete part of its scan.
type ScanErrorV1 struct {
	Module  string `json:"module"`
	Message string `json:"message"`
}

// New builds a report, sorting findings by severity.
func New(schemaVersion, target string, startedAt time.Time, duration time.Duration, surface recon.Surface, findings []finding.Finding, errors []ScanErrorV1) Report {
	finding.SortBySeverity(findings)

	return Report{
		SchemaVersion: schemaVersion,
		Target:        target,
		StartedAt:     startedAt,
		Duration:      duration.Round(time.Millisecond).String(),
		Surface:       surface,
		Findings:      findings,
		Errors:        errors,
	}
}

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(rep)
}

// WriteText renders a human-readable report grouped from most to least severe.
func WriteText(w io.Writer, rep Report) {
	fmt.Fprintf(w, "frameseven scan report\n")
	fmt.Fprintf(w, "target:   %s\n", rep.Target)
	fmt.Fprintf(w, "started:  %s\n", rep.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "duration: %s\n\n", rep.Duration)

	if len(rep.Errors) > 0 {
		fmt.Fprintf(w, "scan status: incomplete\n")
		fmt.Fprintf(w, "errors: %d\n", len(rep.Errors))

		for _, scanErr := range rep.Errors {
			fmt.Fprintf(w, "  - %s: %s\n", scanErr.Module, scanErr.Message)
		}

		fmt.Fprintf(w, "\n")
	}

	writeSurface(w, rep.Surface)

	fmt.Fprintf(w, "findings: %d\n", len(rep.Findings))
	fmt.Fprintf(w, "%s\n\n", countsBySeverity(rep.Findings))

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "No findings.\n")
		return
	}

	for i, f := range rep.Findings {
		writeFinding(w, i+1, f)
	}
}

func writeSurface(w io.Writer, s recon.Surface) {
	fmt.Fprintf(w, "surface\n")
	fmt.Fprintf(w, "  host:            %s\n", s.Host)
	fmt.Fprintf(w, "  technologies:    %d\n", len(s.Technologies))
	fmt.Fprintf(w, "  endpoints:       %d\n", len(s.Endpoints))
	fmt.Fprintf(w, "  parameters:      %d\n", len(s.Params))
	fmt.Fprintf(w, "  sensitive files: %d\n\n", len(s.SensitiveFiles))
}

func writeFinding(w io.Writer, n int, f finding.Finding) {
	fmt.Fprintf(w, "[%d] [%s] %s\n", n, f.Severity, f.Title)
	fmt.Fprintf(w, "    module: %s", f.Module)

	if f.CVSS > 0 {
		fmt.Fprintf(w, " | CVSS: %.1f", f.CVSS)
	}

	if f.CWE != "" {
		fmt.Fprintf(w, " | %s", f.CWE)
	}

	if f.OWASP != "" {
		fmt.Fprintf(w, " | %s", f.OWASP)
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "    %s\n", f.Description)

	writePoC(w, f.Evidence)

	if len(f.NextSteps) > 0 {
		fmt.Fprintf(w, "    next steps:\n")
		for _, step := range f.NextSteps {
			fmt.Fprintf(w, "      - %s\n", step)
		}
	}

	fmt.Fprintf(w, "\n")
}

func writePoC(w io.Writer, e finding.Evidence) {
	if e.Request == "" && e.Response == "" && e.Extracted == "" {
		return
	}

	fmt.Fprintf(w, "    proof of concept:\n")

	if e.Request != "" {
		fmt.Fprintf(w, "      request:\n%s\n", indent(e.Request, "        "))
	}

	if e.Response != "" {
		fmt.Fprintf(w, "      response:\n%s\n", indent(e.Response, "        "))
	}

	if e.Extracted != "" {
		fmt.Fprintf(w, "      extracted:\n%s\n", indent(e.Extracted, "        "))
	}
}

func countsBySeverity(findings []finding.Finding) string {
	counts := map[finding.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	order := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}

	out := ""
	for _, sev := range order {
		out += fmt.Sprintf("  %s: %d", sev, counts[sev])
	}

	return out
}

func indent(s, prefix string) string {
	out := ""
	for _, line := range splitLines(s) {
		out += prefix + line + "\n"
	}

	return trimTrailingNewline(out)
}

func splitLines(s string) []string {
	var lines []string
	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}

	lines = append(lines, s[start:])

	return lines
}

func trimTrailingNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}

	return s
}
