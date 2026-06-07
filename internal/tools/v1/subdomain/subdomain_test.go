package subdomain

import "testing"

func TestCandidateListHasMinimumSize(t *testing.T) {
	if len(candidates) < 100 {
		t.Fatalf("candidates = %d, want at least 100", len(candidates))
	}
}
