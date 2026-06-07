package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestListModules(t *testing.T) {
	_, output, err := V1ListModules(context.Background(), nil, listModulesInput{})
	if err != nil {
		t.Fatalf("ListModules: %v", err)
	}

	if output.Version != "v1" {
		t.Fatalf("version = %q, want v1", output.Version)
	}

	if len(output.Modules) == 0 {
		t.Fatal("expected modules")
	}

	if output.Modules[0].Name != "recon" {
		t.Fatalf("first module = %q, want recon", output.Modules[0].Name)
	}
}

func TestNormalizeModules(t *testing.T) {
	_, output, err := V1NormalizeModules(context.Background(), nil, normalizeModulesInput{
		Modules: []string{"sqli", "misconfig"},
	})
	if err != nil {
		t.Fatalf("NormalizeModules: %v", err)
	}

	if strings.Join(output.SelectedModules, ",") != "recon,sqli,misconfig" {
		t.Fatalf("selected modules = %v", output.SelectedModules)
	}

	if output.ActiveScanStarted {
		t.Fatal("MCP normalize tool must not start an active scan")
	}
}

func TestV1ScanModuleRequiresActiveScanAcceptance(t *testing.T) {
	handler := V1ScanModule("recon")

	_, _, err := handler(context.Background(), nil, scanModuleInput{
		Target: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected active scan acceptance error")
	}
}

func TestBuildScanModuleOutput(t *testing.T) {
	output := buildScanModuleOutput("recon", []string{"recon"}, reportFixture())

	if output.Version != "v1" {
		t.Fatalf("version = %q, want v1", output.Version)
	}

	if output.RequestedModule != "recon" {
		t.Fatalf("requested module = %q, want recon", output.RequestedModule)
	}

	if output.FindingsCount != 1 || len(output.Findings) != 1 {
		t.Fatalf("findings = %+v", output.Findings)
	}
}

func reportFixture() report.Report {
	return report.Report{
		SchemaVersion: "v1",
		Target:        "https://example.com",
		Duration:      "1ms",
		Surface:       recon.Surface{Host: "example.com"},
		Findings: []finding.Finding{
			{
				Title:       "Example finding",
				Module:      "recon",
				Severity:    finding.Info,
				Description: "Example description",
				Evidence: finding.Evidence{
					Extracted: "example evidence",
				},
			},
		},
	}
}
