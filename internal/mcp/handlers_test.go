package mcp

import (
	"context"
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
