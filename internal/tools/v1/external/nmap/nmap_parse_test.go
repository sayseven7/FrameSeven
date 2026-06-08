package nmap

import (
	"strings"
	"testing"

	"github.com/sayseven7/frameseven/internal/finding"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Microsoft IIS httpd" version="8.5"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParsePortsKeepsOnlyOpen(t *testing.T) {
	ports, err := parsePorts(sampleXML)
	if err != nil {
		t.Fatalf("parsePorts returned error: %v", err)
	}

	if len(ports) != 2 {
		t.Fatalf("expected 2 open ports, got %d", len(ports))
	}

	if ports[0].Number != "80" || !strings.Contains(ports[0].Service, "IIS") {
		t.Errorf("unexpected first port: %+v", ports[0])
	}
}

func TestParsePortsRejectsGarbage(t *testing.T) {
	if _, err := parsePorts("not xml at all <<<"); err == nil {
		t.Fatal("expected an error parsing invalid XML")
	}
}

func TestSummaryWithNoPortsIsInfo(t *testing.T) {
	f := summary("example.com", nil)
	if f.Severity != finding.Info {
		t.Errorf("severity = %q, want INFO", f.Severity)
	}

	if !strings.Contains(f.Evidence.Extracted, "none") {
		t.Errorf("expected 'none' in evidence, got %q", f.Evidence.Extracted)
	}
}

func TestRunWithNilConfigDoesNotPanic(t *testing.T) {
	findings := Run(nil, nil, nil)
	if len(findings) != 1 || findings[0].Severity != finding.Info {
		t.Fatalf("expected 1 INFO finding, got %+v", findings)
	}
}
