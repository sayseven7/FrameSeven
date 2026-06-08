package mcp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
)

func TestListTools(t *testing.T) {
	_, output, err := V1ListTools(context.Background(), nil, listToolsInput{})
	if err != nil {
		t.Fatalf("V1ListTools: %v", err)
	}

	if len(output.Tools) == 0 {
		t.Fatal("expected at least one tool")
	}

	var found bool
	for _, tool := range output.Tools {
		if tool.Name == "ratelimit" && tool.EnabledByDefault {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ratelimit to be present and enabled by default")
	}
}

func TestNormalizeTools(t *testing.T) {
	_, output, err := V1NormalizeTools(context.Background(), nil, normalizeToolsInput{
		Tools: []string{"sqli", "misconfig"},
	})
	if err != nil {
		t.Fatalf("V1NormalizeTools: %v", err)
	}

	if strings.Join(output.SelectedTools, ",") != "recon,sqli,misconfig" {
		t.Fatalf("selected tools = %v", output.SelectedTools)
	}

	if output.DefaultProfile {
		t.Fatal("expected default_profile = false with explicit tools")
	}
}

func TestV1ScanToolRequiresActiveScanAcceptance(t *testing.T) {
	handler := V1ScanTool("recon")

	_, _, err := handler(context.Background(), nil, scanToolInput{
		ActiveScanAccepted: false,
	})
	if err == nil {
		t.Fatal("expected error when active_scan_accepted is false")
	}
}

func TestBuildScanToolOutput(t *testing.T) {
	output := buildScanToolOutput("recon", []string{"recon"}, reportFixture())

	if output.RequestedTool != "recon" {
		t.Errorf("requested_tool = %q", output.RequestedTool)
	}

	if len(output.SelectedTools) != 1 || output.SelectedTools[0] != "recon" {
		t.Errorf("selected_tools = %v", output.SelectedTools)
	}

	if output.FindingsCount == 0 {
		t.Errorf("expected findings to be summarized")
	}
}

func TestV1ReportRequiresActiveScanAcceptance(t *testing.T) {
	_, _, err := V1Report(context.Background(), nil, reportToolInput{
		ActiveScanAccepted: false,
	})
	if err == nil {
		t.Fatal("expected error when active_scan_accepted is false")
	}
}

func TestV1ReportRejectsUnknownFormat(t *testing.T) {
	_, _, err := V1Report(context.Background(), nil, reportToolInput{
		Target:             "http://example.com",
		ActiveScanAccepted: true,
		Format:             "xml",
	})
	if err == nil {
		t.Fatal("expected error for unknown report format")
	}
}

func TestNormalizeReportFormat(t *testing.T) {
	cases := map[string]string{
		"":         reportFormatText,
		"text":     reportFormatText,
		"MarkDown": reportFormatMarkdown,
		"md":       reportFormatMarkdown,
		"html":     reportFormatHTML,
		"pdf":      reportFormatPDF,
		"both":     reportFormatBoth,
		"all":      reportFormatAll,
	}

	for in, want := range cases {
		got, err := normalizeReportFormat(in)
		if err != nil {
			t.Fatalf("normalizeReportFormat(%q): %v", in, err)
		}

		if got != want {
			t.Errorf("normalizeReportFormat(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := normalizeReportFormat("xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestBuildReportToolOutput(t *testing.T) {
	out, err := buildReportToolOutput([]string{"recon"}, reportFormatAll, reportFixture())
	if err != nil {
		t.Fatalf("buildReportToolOutput: %v", err)
	}

	if out.Status != "complete" {
		t.Errorf("status = %q, want complete", out.Status)
	}

	if out.FindingsCount != 1 {
		t.Errorf("findings_count = %d, want 1", out.FindingsCount)
	}

	if !strings.Contains(out.ReportText, "Test Finding") {
		t.Errorf("report_text missing finding: %q", out.ReportText)
	}

	if !strings.Contains(out.ReportMarkdown, "# frameseven Scan Report") {
		t.Errorf("report_markdown missing header: %q", out.ReportMarkdown)
	}

	if !strings.Contains(out.ReportHTML, "Web application security report") {
		t.Errorf("report_html missing heading: %q", out.ReportHTML)
	}

	pdf, err := base64.StdEncoding.DecodeString(out.ReportPDF)
	if err != nil {
		t.Fatalf("report_pdf_base64 is not base64: %v", err)
	}

	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Errorf("report_pdf_base64 missing PDF header")
	}
}

func TestBuildReportToolOutputTextOnly(t *testing.T) {
	out, err := buildReportToolOutput([]string{"recon"}, reportFormatText, reportFixture())
	if err != nil {
		t.Fatalf("buildReportToolOutput: %v", err)
	}

	if out.ReportText == "" {
		t.Error("expected report_text to be rendered")
	}

	if out.ReportMarkdown != "" {
		t.Error("expected report_markdown to be empty for text format")
	}
}

func reportFixture() report.Report {
	return report.Report{
		SchemaVersion: "v1",
		Duration:      "10s",
		Findings: []finding.Finding{
			{
				Title:    "Test Finding",
				Module:   "recon",
				Severity: finding.High,
				Evidence: finding.Evidence{Extracted: "evidence"},
			},
		},
		StartedAt: time.Now(),
	}
}
