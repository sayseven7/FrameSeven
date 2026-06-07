package cve

import (
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const fixture = `{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-41773",
        "descriptions": [
          {"lang": "es", "value": "ignorar"},
          {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8}}
          ]
        },
        "weaknesses": [
          {"description": [{"value": "CWE-22"}]}
        ]
      }
    }
  ]
}`

func TestParseNVD(t *testing.T) {
	findings := parseNVD([]byte(fixture), "Apache 2.4.49")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]

	if f.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", f.CVSS)
	}

	if f.Severity != finding.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}

	if f.CWE != "CWE-22" {
		t.Errorf("CWE = %q, want CWE-22", f.CWE)
	}

	if f.Description != "Path traversal in Apache HTTP Server 2.4.49" {
		t.Errorf("description = %q", f.Description)
	}
}

func TestParseNVDInvalid(t *testing.T) {
	if got := parseNVD([]byte("not json"), "x"); got != nil {
		t.Fatalf("expected nil on invalid JSON, got %+v", got)
	}
}

func TestVersionKeyword(t *testing.T) {
	if got := versionKeyword(recon.Technology{Name: "Apache", Version: "2.4.49"}); got != "Apache 2.4.49" {
		t.Errorf("got %q", got)
	}

	if got := versionKeyword(recon.Technology{Name: "nginx"}); got != "" {
		t.Errorf("expected empty without version, got %q", got)
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := map[float64]finding.Severity{
		9.8: finding.Critical,
		7.5: finding.High,
		5.0: finding.Medium,
		2.0: finding.Low,
		0:   finding.Info,
	}

	for score, want := range cases {
		if got := severityFromScore(score); got != want {
			t.Errorf("severityFromScore(%v) = %v, want %v", score, got, want)
		}
	}
}
