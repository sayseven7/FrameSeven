package subdomain

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestCandidateListHasMinimumSize(t *testing.T) {
	if len(candidates) < 100 {
		t.Fatalf("candidates = %d, want at least 100", len(candidates))
	}
}

func TestAllCandidatesAddsCustomLabels(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.CustomPayloads = []string{"custom-api", "https://bad.example", "custom-api"}

	selected := allCandidates(&cfg)
	var found bool
	for _, candidate := range selected {
		if candidate == "custom-api" {
			found = true
		}

		if candidate == "https://bad.example" {
			t.Fatalf("absolute URL should not be accepted as a subdomain label")
		}
	}

	if !found {
		t.Fatalf("custom-api was not added to candidates")
	}
}
