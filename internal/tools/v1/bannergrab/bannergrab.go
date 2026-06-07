// Package bannergrab checks lightweight service banners for selected TCP services.
package bannergrab

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

type service struct {
	name        string
	port        string
	title       string
	description string
	nextSteps   []string
}

var services = []service{
	{
		name:        "ftp",
		port:        "21",
		title:       "FTP service banner observed",
		description: "An FTP service returned a banner on TCP 21.",
		nextSteps: []string{
			"Confirm the FTP service is in scope before deeper enumeration.",
			"Prefer configuration and banner checks before any authentication testing.",
		},
	},
	{
		name:        "ssh",
		port:        "22",
		title:       "SSH service banner observed",
		description: "An SSH service returned a banner on TCP 22.",
		nextSteps: []string{
			"Confirm the SSH service is in scope before deeper enumeration.",
			"Do not perform password guessing unless an engagement explicitly authorizes it.",
		},
	},
	{
		name:        "smtp",
		port:        "25",
		title:       "SMTP service banner observed",
		description: "An SMTP service returned a banner on TCP 25.",
		nextSteps: []string{
			"Confirm the SMTP service is in scope before deeper enumeration.",
			"Avoid user enumeration or brute force unless explicitly authorized.",
		},
	},
}

// Run records banners exposed by a small set of common TCP services.
func Run(cfg *config.Config, _ *http.Client, _ *recon.Surface) []finding.Finding {
	var findings []finding.Finding

	for _, svc := range services {
		banner := readBanner(cfg, svc.port)
		if banner == "" {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       svc.title,
			Module:      "bannergrab",
			Severity:    finding.Info,
			OWASP:       "A05:2025 - Security Misconfiguration",
			CWE:         "CWE-200",
			Description: svc.description,
			Evidence: finding.Evidence{
				Extracted: svc.name + ": " + banner,
			},
			NextSteps: svc.nextSteps,
		})
	}

	return findings
}

func readBanner(cfg *config.Config, port string) string {
	base, err := url.Parse(cfg.Target)
	if err != nil || base.Hostname() == "" {
		return ""
	}

	timeout := cfg.Timeout
	if timeout <= 0 || timeout > 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(base.Hostname(), port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	return strings.TrimSpace(string(buf[:n]))
}
