package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func sampleReport() Report {
	surface := recon.Surface{Host: "example.com"}

	findings := []finding.Finding{
		{Title: "Low issue", Module: "misconfig", Severity: finding.Low},
		{
			Title:       "SQLi",
			Module:      "sqli",
			Severity:    finding.Critical,
			CVSS:        9.8,
			CWE:         "CWE-89",
			OWASP:       "A03:2025 - Injection",
			Description: "injectable",
			Evidence:    finding.Evidence{Extracted: "db: shop\nuser: root"},
			NextSteps:   []string{"use prepared statements"},
		},
	}

	return New("https://example.com", time.Unix(0, 0).UTC(), 2*time.Second, surface, findings)
}

func TestNewSortsFindings(t *testing.T) {
	rep := sampleReport()

	if rep.Findings[0].Severity != finding.Critical {
		t.Fatalf("expected critical first, got %v", rep.Findings[0].Severity)
	}
}

func TestWriteTextContainsKeyFields(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, sampleReport())

	out := buf.String()

	for _, want := range []string{"SQLi", "CVSS: 9.8", "CWE-89", "A03:2025", "use prepared statements", "db: shop"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q\n%s", want, out)
		}
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer

	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, `"target": "https://example.com"`) {
		t.Errorf("json missing target\n%s", out)
	}

	if !strings.Contains(out, `"cvss": 9.8`) {
		t.Errorf("json missing cvss\n%s", out)
	}
}
