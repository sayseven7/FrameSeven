// Package crawler expands endpoint discovery by visiting already discovered
// same-origin pages and extracting additional links and form actions.
package crawler

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

const maxPages = 10

var linkRe = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"']+)["']`)

// Run fetches discovered same-origin endpoints and reports new links.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	known := map[string]bool{cfg.Target: true}
	for _, endpoint := range surface.Endpoints {
		known[endpoint] = true
	}

	var discovered []string
	var firstDump string

	for i, endpoint := range surface.Endpoints {
		if i >= maxPages {
			break
		}

		dump, body := fetch(cfg, client, endpoint)
		if body == "" {
			continue
		}

		if firstDump == "" {
			firstDump = dump
		}

		for _, match := range linkRe.FindAllStringSubmatch(body, -1) {
			ref, err := base.Parse(strings.TrimSpace(match[1]))
			if err != nil || ref.Hostname() != base.Hostname() {
				continue
			}

			ref.Fragment = ""
			value := ref.String()
			if known[value] {
				continue
			}

			known[value] = true
			discovered = append(discovered, value)
		}
	}

	if len(discovered) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Crawler discovered additional same-origin endpoints",
		Module:      "crawler",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "Additional links or form actions were discovered by visiting known same-origin endpoints.",
		Evidence: finding.Evidence{
			Request:   firstDump,
			Extracted: strings.Join(discovered, "\n"),
		},
		NextSteps: []string{
			"Review crawler-discovered endpoints for new parameters.",
			"Increase crawl depth only when scope and rate limits are clear.",
		},
	}}
}

func fetch(cfg *config.Config, client *http.Client, target string) (string, string) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return "", ""
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return string(dump), ""
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return string(dump), string(body)
}
