// Package nmap runs Nmap for Framework v1 and maps its results into findings.
// Execution is fail-safe: a missing binary, a failed run, or unparseable output
// is reported as an informational finding instead of blocking the scan.
package nmap

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/external"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const binary = "nmap"

// commonPorts is the curated, light port set scanned by default. Keeping the
// set small bounds scan time and avoids surprising the operator with a full
// 65k-port sweep.
const commonPorts = "21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8000,8080,8443,9200,27017"

// Run executes Nmap against the target host and returns findings describing the
// open ports it discovered. Any failure degrades to an informational finding so
// the remainder of the scan is never blocked.
func Run(cfg *config.Config, _ *http.Client, surface *recon.Surface) []finding.Finding {
	host := targetHost(cfg, surface)
	if host == "" {
		return []finding.Finding{external.Unavailable(binary, "no target host was configured")}
	}

	if _, err := exec.LookPath(binary); err != nil {
		return []finding.Finding{external.NotFound(binary)}
	}

	timeout := external.Budget(cfg.Timeout)
	res, err := external.Execute(timeout, binary, "-Pn", "-T4", "-oX", "-", "-p", commonPorts, host)
	if err != nil {
		reason := "the Nmap process exited with an error"
		if res.TimedOut {
			reason = fmt.Sprintf("the Nmap process exceeded the %s budget", timeout)
		}

		return []finding.Finding{external.Failed(binary, reason, firstNonEmpty(res.Stderr, res.Stdout))}
	}

	ports, parseErr := parsePorts(res.Stdout)
	if parseErr != nil {
		return []finding.Finding{external.Failed(binary, "the Nmap XML output could not be parsed", firstNonEmpty(parseErr.Error(), res.Stdout))}
	}

	return []finding.Finding{summary(host, ports)}
}

// targetHost resolves the bare hostname to scan, preferring the recon surface
// and falling back to the configured target URL.
func targetHost(cfg *config.Config, surface *recon.Surface) string {
	if surface != nil && strings.TrimSpace(surface.Host) != "" {
		return surface.Host
	}

	if cfg == nil {
		return ""
	}

	u, err := url.Parse(cfg.Target)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

// openPort is one parsed open TCP port and its detected service.
type openPort struct {
	Number  string
	Service string
}

// xmlRun mirrors the subset of Nmap's -oX schema we consume.
type xmlRun struct {
	Hosts []struct {
		Ports struct {
			Ports []struct {
				PortID   string `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func parsePorts(out string) ([]openPort, error) {
	var run xmlRun
	if err := xml.Unmarshal([]byte(out), &run); err != nil {
		return nil, err
	}

	var open []openPort
	for _, host := range run.Hosts {
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			open = append(open, openPort{
				Number:  port.PortID,
				Service: serviceLabel(port.Service.Name, port.Service.Product, port.Service.Version),
			})
		}
	}

	return open, nil
}

func serviceLabel(name, product, version string) string {
	parts := make([]string, 0, 3)
	for _, p := range []string{name, product, version} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}

	if len(parts) == 0 {
		return "unknown"
	}

	return strings.Join(parts, " ")
}

// summary turns the parsed ports into a single finding. With no open ports it
// still returns an informational finding so the operator always gets a result.
func summary(host string, ports []openPort) finding.Finding {
	if len(ports) == 0 {
		return finding.Finding{
			Title:       "Nmap found no open ports in the common set",
			Module:      binary,
			Severity:    finding.Info,
			OWASP:       "A05:2025 - Security Misconfiguration",
			CWE:         "CWE-200",
			Description: "Nmap scanned the common web-facing TCP ports on " + host + " and none were open.",
			Evidence: finding.Evidence{
				Extracted: "host: " + host + "\nopen ports: none",
			},
			NextSteps: []string{
				"Widen the port range with a dedicated, authorized scan if deeper coverage is needed.",
			},
		}
	}

	var lines []string
	for _, p := range ports {
		lines = append(lines, fmt.Sprintf("%s/tcp\t%s", p.Number, p.Service))
	}

	return finding.Finding{
		Title:       fmt.Sprintf("Nmap found %d open port(s)", len(ports)),
		Module:      binary,
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "Nmap identified open TCP ports on " + host + ". Confirm each exposed service is intentional and in scope.",
		Evidence: finding.Evidence{
			Extracted: "host: " + host + "\n" + strings.Join(lines, "\n"),
		},
		NextSteps: []string{
			"Confirm each open service is intentionally exposed.",
			"Close or firewall ports that are not required.",
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}

	return ""
}
