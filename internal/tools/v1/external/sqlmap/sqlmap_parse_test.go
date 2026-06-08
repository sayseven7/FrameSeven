package sqlmap

import (
	"strings"
	"testing"
)

const vulnerableOutput = `
[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 120 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=2 AND 1234=1234
---
[INFO] the back-end DBMS is Microsoft SQL Server
`

const cleanOutput = `
[INFO] testing connection to the target URL
[WARNING] all tested parameters do not appear to be injectable
`

func TestParseInjectionExtractsBlock(t *testing.T) {
	got := parseInjection(vulnerableOutput)
	if !strings.Contains(got, "Parameter: id (GET)") {
		t.Errorf("expected parameter line, got %q", got)
	}

	if !strings.Contains(got, "Payload: id=2 AND 1234=1234") {
		t.Errorf("expected payload line, got %q", got)
	}
}

func TestParseInjectionEmptyWhenClean(t *testing.T) {
	if got := parseInjection(cleanOutput); got != "" {
		t.Errorf("expected empty injection, got %q", got)
	}
}

func TestVulnerableFindingIsCritical(t *testing.T) {
	f := vulnerable("http://t/", "Parameter: id")
	if f.CWE != "CWE-89" || f.CVSS != 9.8 {
		t.Errorf("unexpected metadata: cwe=%q cvss=%v", f.CWE, f.CVSS)
	}
}
