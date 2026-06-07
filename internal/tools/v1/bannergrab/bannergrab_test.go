package bannergrab

import (
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestRunReturnsFindings(t *testing.T) {
	cfg := config.New("https://example.com:9999")
	cfg.Timeout = 100 * time.Millisecond

	findings := Run(&cfg, nil, nil)

	if len(findings) > 0 {
		t.Logf("bannergrab returned %d finding(s) (expected 0 on a non-routable port)", len(findings))
	}
}
