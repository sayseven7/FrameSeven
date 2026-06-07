package finding

import "testing"

func TestSeverityRank(t *testing.T) {
	if Critical.Rank() <= High.Rank() {
		t.Fatalf("expected critical to outrank high")
	}

	if Info.Rank() >= Low.Rank() {
		t.Fatalf("expected info to rank below low")
	}

	if Severity("BOGUS").Rank() != 0 {
		t.Fatalf("expected unknown severity to rank 0")
	}
}

func TestSortBySeverity(t *testing.T) {
	findings := []Finding{
		{Title: "b", Module: "m1", Severity: Low},
		{Title: "a", Module: "m1", Severity: Critical},
		{Title: "a", Module: "m2", Severity: Critical},
		{Title: "c", Module: "m1", Severity: Medium},
	}

	SortBySeverity(findings)

	if findings[0].Severity != Critical || findings[0].Module != "m1" {
		t.Fatalf("expected critical/m1 first, got %+v", findings[0])
	}

	if findings[1].Severity != Critical || findings[1].Module != "m2" {
		t.Fatalf("expected critical/m2 second, got %+v", findings[1])
	}

	if findings[3].Severity != Low {
		t.Fatalf("expected low last, got %+v", findings[3])
	}
}
