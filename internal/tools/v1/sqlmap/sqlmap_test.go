package sqlmap

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
)

func TestRunReturnsInfoFinding(t *testing.T) {
	findings := Run(nil, nil, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != finding.Info {
		t.Errorf("severity = %q, want INFO", findings[0].Severity)
	}
}
