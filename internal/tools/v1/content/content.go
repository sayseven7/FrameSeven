// Package content discovers common web content paths. It reports surface data,
// not sensitive-file exposure.
package content

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

var paths = []string{
	"/login",
	"/api",
	"/assets/",
	"/static/",
	"/uploads/",
	"/docs/",
	"/health",
	"/status",
}

type response struct {
	status int
	body   string
	dump   string
}

// Run checks a small official v1 seed list of common content paths.
func Run(cfg *config.Config, client *http.Client, _ *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	soft404 := get(cfg, client, resolve(base, "/frameseven-content-probe-404"))

	var found []string
	var first *response

	for _, path := range paths {
		resp := get(cfg, client, resolve(base, path))
		if resp == nil || resp.status < 200 || resp.status >= 400 {
			continue
		}

		if looksSoft404(resp, soft404) {
			continue
		}

		found = append(found, path+" ("+strconv.Itoa(resp.status)+")")
		if first == nil {
			first = resp
		}
	}

	if len(found) == 0 || first == nil {
		return nil
	}

	return []finding.Finding{{
		Title:       "Common content paths discovered",
		Module:      "content",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "Common application paths responded successfully and may expand the target surface.",
		Evidence: finding.Evidence{
			Request:   first.dump,
			Response:  trim(first.body, 300),
			Extracted: strings.Join(found, "\n"),
		},
		NextSteps: []string{
			"Review discovered paths and feed relevant endpoints into targeted modules.",
			"Add soft-404 detection before increasing the content wordlist.",
		},
	}}
}

func resolve(base *url.URL, path string) string {
	ref, err := base.Parse(path)
	if err != nil {
		return ""
	}

	return ref.String()
}

func get(cfg *config.Config, client *http.Client, target string) *response {
	if target == "" {
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
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

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func looksSoft404(resp, missing *response) bool {
	if resp == nil || missing == nil {
		return false
	}

	return resp.status == missing.status && comparableSize(resp.body, missing.body)
}

func comparableSize(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}

	smaller := len(a)
	if len(b) < smaller {
		smaller = len(b)
	}

	return diff <= smaller/3
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}

	return s
}
