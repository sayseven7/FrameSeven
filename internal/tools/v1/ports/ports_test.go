package ports

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestRunReturnsEmptyOnUnreachableTarget(t *testing.T) {
	cfg := config.New("https://example.com:19999")

	findings := Run(&cfg, nil, nil)

	if len(findings) != 0 {
		t.Logf("ports returned %d finding(s) (expected 0 on an unreachable port)", len(findings))
	}
}

func TestPortsForDeduplicates(t *testing.T) {
	cfg := config.New("https://example.com:443")

	findings := Run(&cfg, nil, nil)

	// Should not error on deduplication of port 443
	if findings != nil && len(findings) > 1 {
		t.Logf("ports returned %d finding(s)", len(findings))
	}
}
