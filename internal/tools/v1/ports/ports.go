// Package ports performs light TCP checks against common web-facing ports.
package ports

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
)

var commonPorts = []int{80, 443, 8000, 8080, 8443, 3000}

// Run checks the target port and common web ports with TCP connect attempts.
func Run(cfg *config.Config) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	host := base.Hostname()
	if host == "" {
		return nil
	}

	timeout := cfg.Timeout
	if timeout <= 0 || timeout > 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}

	var open []string
	for _, port := range portsFor(base) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
		if err != nil {
			continue
		}

		_ = conn.Close()
		open = append(open, strconv.Itoa(port))
	}

	if len(open) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Open web-facing TCP ports found",
		Module:      "ports",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "One or more common web-facing TCP ports accepted connections.",
		Evidence: finding.Evidence{
			Extracted: "open ports: " + strings.Join(open, ", "),
		},
		NextSteps: []string{
			"Confirm each open service is in scope and intentionally exposed.",
			"Use a dedicated service scanner for deeper enumeration when authorized.",
		},
	}}
}

func portsFor(base *url.URL) []int {
	seen := map[int]bool{}
	var ports []int

	add := func(port int) {
		if port <= 0 || seen[port] {
			return
		}

		seen[port] = true
		ports = append(ports, port)
	}

	if base.Port() != "" {
		if port, err := strconv.Atoi(base.Port()); err == nil {
			add(port)
		}
	} else if base.Scheme == "https" {
		add(443)
	} else {
		add(80)
	}

	for _, port := range commonPorts {
		add(port)
	}

	return ports
}
