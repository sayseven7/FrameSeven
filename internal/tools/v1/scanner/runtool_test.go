package scanner

import (
	"net/http"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestRunToolIsolatesPanic(t *testing.T) {
	panicking := Tool{
		Name: "boom",
		Run: func(*config.Config, *http.Client, *recon.Surface) []finding.Finding {
			panic("kaboom")
		},
	}

	findings, scanErr := runTool(panicking, nil, nil, nil)
	if findings != nil {
		t.Errorf("expected no findings from a panicking tool, got %d", len(findings))
	}

	if scanErr == nil {
		t.Fatal("expected a scan error from a panicking tool")
	}

	if scanErr.Module != "boom" {
		t.Errorf("scan error module = %q, want boom", scanErr.Module)
	}
}

func TestRunToolPassesThroughFindings(t *testing.T) {
	ok := Tool{
		Name: "ok",
		Run: func(*config.Config, *http.Client, *recon.Surface) []finding.Finding {
			return []finding.Finding{{Title: "x", Module: "ok", Severity: finding.Info}}
		},
	}

	findings, scanErr := runTool(ok, nil, nil, nil)
	if scanErr != nil {
		t.Fatalf("unexpected scan error: %+v", scanErr)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestRunToolTimesOut(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.ToolTimeout = 10 * time.Millisecond

	slow := Tool{
		Name: "slow",
		Run: func(*config.Config, *http.Client, *recon.Surface) []finding.Finding {
			time.Sleep(100 * time.Millisecond)

			return nil
		},
	}

	findings, scanErr := runTool(slow, &cfg, nil, nil)
	if findings != nil {
		t.Errorf("expected no findings from a timed-out tool, got %d", len(findings))
	}

	if scanErr == nil {
		t.Fatal("expected a scan error from a timed-out tool")
	}

	if scanErr.Module != "slow" {
		t.Errorf("scan error module = %q, want slow", scanErr.Module)
	}
}
