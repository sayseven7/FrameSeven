// Package access tests broken access control: sensitive endpoints reachable
// without authentication, and IDOR by enumerating numeric identifiers.
package access

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// adminPaths are endpoints that should normally require authentication.
var adminPaths = []string{
	"/admin",
	"/admin/",
	"/administrator",
	"/dashboard",
	"/api/admin",
	"/api/users",
	"/actuator",
	"/actuator/env",
	"/manager/html",
	"/console",
	"/config",
	"/metrics",
	"/cpanel",
	"/wp-admin/",
}

type response struct {
	status int
	body   string
	dump   string
}

// Run probes unauthenticated access and IDOR.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	findings = append(findings, unauthEndpoints(cfg, client, base)...)
	findings = append(findings, idor(cfg, client, surface)...)

	return findings
}

func unauthEndpoints(cfg *config.Config, client *http.Client, base *url.URL) []finding.Finding {
	var findings []finding.Finding
	reported := map[string]bool{}

	for _, path := range adminPaths {
		ref, err := base.Parse(path)
		if err != nil {
			continue
		}

		normalized := strings.TrimRight(path, "/")
		if reported[normalized] {
			continue
		}

		resp := get(cfg, client, ref.String())
		if resp == nil {
			continue
		}

		reported[normalized] = true

		switch resp.status {
		case http.StatusOK:
			findings = append(findings, finding.Finding{
				Title:       "Sensitive endpoint reachable without authentication: " + path,
				Module:      "access",
				Severity:    finding.High,
				OWASP:       "A01:2025 - Broken Access Control",
				CWE:         "CWE-284",
				CVSS:        7.5,
				Description: "An administrative or internal endpoint returned 200 without any authentication.",
				Evidence: finding.Evidence{
					Request:   resp.dump,
					Response:  trim(resp.body, 400),
					Extracted: path,
				},
				NextSteps: []string{
					"Require authentication and authorization on this endpoint.",
					"Verify access checks are enforced server-side, not only in the UI.",
				},
			})
		case http.StatusUnauthorized, http.StatusForbidden:
			findings = append(findings, finding.Finding{
				Title:       "Administrative interface candidate discovered: " + path,
				Module:      "access",
				Severity:    finding.Info,
				OWASP:       "A01:2025 - Broken Access Control",
				CWE:         "CWE-200",
				Description: "An administrative path exists and returned an authentication or authorization response.",
				Evidence: finding.Evidence{
					Request:   resp.dump,
					Response:  trim(resp.body, 400),
					Extracted: path + " (" + strconv.Itoa(resp.status) + ")",
				},
				NextSteps: []string{
					"Confirm this interface is intentionally exposed.",
					"Keep authorization checks server-side and monitor access attempts.",
				},
			})
		}
	}

	return findings
}

var idRe = regexp.MustCompile(`^\d+$`)

// emailRe matches an email address, a strong indicator of per-user data.
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// sensitiveKeywords are lower-case markers that suggest a response body holds
// data scoped to a specific user or account rather than public content.
var sensitiveKeywords = []string{
	"password", "passwd",
	"private", "ssn", "social security",
	"credit card", "card number", "cardnumber", "cvv",
	"api_key", "apikey", "access_token", "auth_token", "secret",
	"account number", "accountnumber", "iban", "routing number",
	"date of birth", "dateofbirth", "birthdate", "phone number",
}

func idor(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		value := u.Query().Get(p.Name)
		if !idRe.MatchString(value) {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		if f, ok := probeIDOR(cfg, client, p, value); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func probeIDOR(cfg *config.Config, client *http.Client, p recon.Param, value string) (finding.Finding, bool) {
	id, _ := strconv.Atoi(value)

	base := getParam(cfg, client, p, value)
	if base == nil || base.status != http.StatusOK {
		return finding.Finding{}, false
	}

	for _, delta := range []int{1, -1, 2} {
		neighbor := id + delta
		if neighbor < 0 {
			continue
		}

		resp := getParam(cfg, client, p, strconv.Itoa(neighbor))
		if resp == nil || resp.status != http.StatusOK {
			continue
		}

		// An adjacent identifier returning a distinct object of comparable size
		// only proves the parameter is an *enumerable* object reference. Public
		// content (news articles, products, blog posts) behaves identically and
		// is not a vulnerability. A real IDOR requires the object to expose data
		// belonging to another user/account, so we only raise a High-severity
		// finding when the body carries user- or account-bound data; otherwise
		// it is reported as informational for manual review.
		if resp.body == base.body || !comparableSize(base.body, resp.body) {
			continue
		}

		extracted := p.Name + "=" + value + " -> " + p.Name + "=" + strconv.Itoa(neighbor)

		if marker, ok := sensitiveMarker(resp.body); ok {
			return finding.Finding{
				Title:       "Possible IDOR in parameter '" + p.Name + "'",
				Module:      "access",
				Severity:    finding.High,
				OWASP:       "A01:2025 - Broken Access Control",
				CWE:         "CWE-639",
				CVSS:        7.1,
				Description: "Changing the identifier returns another object whose body contains user- or account-bound data (" + marker + "), suggesting access to records owned by other users without an ownership check.",
				Evidence: finding.Evidence{
					Request:   resp.dump,
					Response:  trim(resp.body, 400),
					Extracted: extracted,
				},
				NextSteps: []string{
					"Manually confirm the returned record belongs to a different user or account.",
					"Enforce object-level authorization tied to the authenticated user.",
					"Prefer unguessable identifiers and verify ownership on every access.",
				},
			}, true
		}

		return finding.Finding{
			Title:       "Enumerable object reference in parameter '" + p.Name + "'",
			Module:      "access",
			Severity:    finding.Info,
			OWASP:       "A01:2025 - Broken Access Control",
			CWE:         "CWE-639",
			Description: "Adjacent identifier values return distinct HTTP 200 objects, so the parameter is enumerable. This is not on its own an IDOR: public content (articles, products, news) behaves the same way. It is only a vulnerability if the objects expose data restricted to other users or accounts.",
			Evidence: finding.Evidence{
				Request:   resp.dump,
				Response:  trim(resp.body, 400),
				Extracted: extracted,
			},
			NextSteps: []string{
				"Manually verify whether the returned objects contain data owned by other users/accounts (e.g. profiles, orders, messages).",
				"If the data is private, enforce object-level authorization and prefer unguessable identifiers.",
			},
		}, true
	}

	return finding.Finding{}, false
}

// sensitiveMarker reports whether a response body carries data that looks
// user- or account-bound. Its presence is what separates a genuine IDOR
// candidate from ordinary enumerable public content. It returns a short label
// describing the first marker found.
func sensitiveMarker(body string) (string, bool) {
	if emailRe.MatchString(body) {
		return "email address", true
	}

	lower := strings.ToLower(body)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return kw, true
		}
	}

	return "", false
}

func comparableSize(a, b string) bool {
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}

	ratio := float64(la) / float64(lb)

	return ratio > 0.5 && ratio < 2
}

func getParam(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, value)
	u.RawQuery = q.Encode()

	return get(cfg, client, u.String())
}

func get(cfg *config.Config, client *http.Client, target string) *response {
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

func trim(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}

	return strings.TrimSpace(s)
}
