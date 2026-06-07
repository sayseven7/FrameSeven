package report

import (
	"bytes"
	"os"
	"path/filepath"
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

	errors := []ScanErrorV1{
		{Module: "recon", Message: "request failed"},
	}

	return New("v1", "https://example.com", time.Unix(0, 0).UTC(), 2*time.Second, surface, findings, errors)
}

func TestNewSortsFindings(t *testing.T) {
	rep := sampleReport()

	if rep.SchemaVersion != "v1" {
		t.Fatalf("schema version = %q, want v1", rep.SchemaVersion)
	}

	if rep.Findings[0].Severity != finding.Critical {
		t.Fatalf("expected critical first, got %v", rep.Findings[0].Severity)
	}
}

func TestWriteTextContainsKeyFields(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, sampleReport())

	out := buf.String()

	for _, want := range []string{"scan status: incomplete", "recon: request failed", "SQLi", "CVSS: 9.8", "CWE-89", "A03:2025", "use prepared statements", "db: shop"} {
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

	if !strings.Contains(out, `"schema_version": "v1"`) {
		t.Errorf("json missing schema version\n%s", out)
	}

	if !strings.Contains(out, `"cvss": 9.8`) {
		t.Errorf("json missing cvss\n%s", out)
	}
}

func TestWriteHTMLContainsEscapedFinding(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Title = `<script>alert("x")</script>`

	var buf bytes.Buffer
	if err := WriteHTML(&buf, rep); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, `<script>alert`) {
		t.Fatalf("HTML contains unescaped finding title:\n%s", out)
	}

	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("HTML missing escaped finding title:\n%s", out)
	}

	for _, want := range []string{"Executive overview", "Severity distribution", "Attack surface", "Finding index", `id="finding-1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q\n%s", want, out)
		}
	}
}

func TestWriteMarkdownContainsFindingsAndErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"# frameseven Scan Report", "## Findings", "SQLi", "request failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown report missing %q\n%s", want, out)
		}
	}
}

func TestWriteFilesCreatesAllFormats(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")

	files, err := WriteFiles(dir, sampleReport())
	if err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}

	for _, path := range []string{files.HTML, files.Markdown, files.JSON} {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s was not created: %v", path, err)
			continue
		}

		if info.Size() == 0 {
			t.Errorf("%s is empty", path)
		}
	}
}
