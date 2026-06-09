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
	findings = append(findings, pathIDOR(cfg, client, surface)...)
	findings = append(findings, collectionIDOR(cfg, client, surface)...)

	return findings
}

func unauthEndpoints(cfg *config.Config, client *http.Client, base *url.URL) []finding.Finding {
	var findings []finding.Finding
	reported := map[string]bool{}

	for _, path := range allAdminPaths(cfg) {
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

func allAdminPaths(cfg *config.Config) []string {
	seen := map[string]bool{}
	var selected []string

	for _, path := range adminPaths {
		selected = appendAdminPath(selected, seen, path)
	}

	for _, payload := range cfg.NormalizedCustomPayloads() {
		if strings.Contains(payload, "://") {
			continue
		}

		path := payload
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		selected = appendAdminPath(selected, seen, path)
	}

	return selected
}

func appendAdminPath(paths []string, seen map[string]bool, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" || seen[path] {
		return paths
	}

	seen[path] = true

	return append(paths, path)
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

	resource := resourceFromParam(p)

	for _, delta := range []int{1, -1, 2} {
		neighbor := id + delta
		if neighbor < 0 {
			continue
		}

		resp := getParam(cfg, client, p, strconv.Itoa(neighbor))

		severity, marker, ok := classifyNeighbor(resource, base, resp)
		if !ok {
			continue
		}

		extracted := p.Name + "=" + value + " -> " + p.Name + "=" + strconv.Itoa(neighbor)
		title := idorTitle(severity, "parameter '"+p.Name+"'")

		return buildIDOR(severity, title, extracted, marker, resp), true
	}

	return finding.Finding{}, false
}

// maxPathIDORTemplates bounds how many distinct path templates are probed so a
// large captured surface cannot blow up the access tool's runtime.
const maxPathIDORTemplates = 50

// pathIDOR tests broken object-level authorization on REST routes whose object
// identifier sits in a numeric path segment, for example /rest/basket/6 or
// /api/Users/1. These are the common SPA/API IDOR shapes that the query-string
// IDOR check cannot reach. Requests run with the captured session, so a
// successful read of another object proves a missing ownership check.
func pathIDOR(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range surface.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		segments := strings.Split(u.Path, "/")
		for i, segment := range segments {
			if !idRe.MatchString(segment) {
				continue
			}

			template := u.Host + "|" + pathTemplate(segments, i)
			if tested[template] {
				continue
			}

			if len(tested) >= maxPathIDORTemplates {
				return findings
			}

			tested[template] = true

			if f, ok := probePathIDOR(cfg, client, u, segments, i); ok {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func probePathIDOR(cfg *config.Config, client *http.Client, u *url.URL, segments []string, idx int) (finding.Finding, bool) {
	value := segments[idx]

	id, err := strconv.Atoi(value)
	if err != nil {
		return finding.Finding{}, false
	}

	base := get(cfg, client, withSegment(u, segments, idx, value))
	if base == nil || base.status != http.StatusOK {
		return finding.Finding{}, false
	}

	template := pathTemplate(segments, idx)
	resource := precedingSegment(segments, idx)

	for _, delta := range []int{1, -1, 2} {
		neighbor := id + delta
		if neighbor < 0 {
			continue
		}

		resp := get(cfg, client, withSegment(u, segments, idx, strconv.Itoa(neighbor)))

		severity, marker, ok := classifyNeighbor(resource, base, resp)
		if !ok {
			continue
		}

		extracted := template + ": " + value + " -> " + strconv.Itoa(neighbor)
		title := idorTitle(severity, "path '"+template+"'")

		return buildIDOR(severity, title, extracted, marker, resp), true
	}

	return finding.Finding{}, false
}

// pathTemplate renders the path with the segment at idx replaced by {id}, used
// to deduplicate probes and to label findings, e.g. /rest/basket/{id}.
func pathTemplate(segments []string, idx int) string {
	replaced := make([]string, len(segments))
	copy(replaced, segments)
	replaced[idx] = "{id}"

	return strings.Join(replaced, "/")
}

// withSegment returns the URL string with the path segment at idx set to value.
func withSegment(u *url.URL, segments []string, idx int, value string) string {
	replaced := make([]string, len(segments))
	copy(replaced, segments)
	replaced[idx] = value

	clone := *u
	clone.Path = strings.Join(replaced, "/")

	return clone.String()
}

// ownerRoots are substrings that mark a resource as user- or account-owned.
// When a candidate reference targets one of these, an adjacent identifier that
// returns another 200 object (instead of 403/404) is a missing ownership check,
// not merely an enumerable public reference.
var ownerRoots = []string{
	"user", "account", "customer",
	"basket", "cart", "order", "invoice", "receipt",
	"card", "wallet", "payment", "transaction",
	"address", "profile", "contact", "phone", "email",
	"message", "ticket", "document", "report",
	"booking", "reservation", "subscription", "passport",
}

// isOwnedResource reports whether name references a user-owned object type.
func isOwnedResource(name string) bool {
	lower := strings.ToLower(name)
	for _, root := range ownerRoots {
		if strings.Contains(lower, root) {
			return true
		}
	}

	return false
}

// looksStructured reports whether a body is a JSON object or array, the usual
// shape of an API resource. It separates a real object from an SPA's HTML
// fallback that many apps return with 200 for unknown identifiers.
func looksStructured(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}

	return trimmed[0] == '{' || trimmed[0] == '['
}

// classifyNeighbor decides whether a neighbor object reference is a real IDOR
// (High), an enumerable-but-public reference (Info), or nothing. The decision
// follows ownership semantics rather than blind id enumeration: a user-owned
// resource that returns a distinct 200 object under the authenticated session is
// a broken ownership check, regardless of whether the body happens to contain an
// email. A neighbor that returns 403/404 (ownership enforced) yields nothing.
func classifyNeighbor(resource string, base, neighbor *response) (finding.Severity, string, bool) {
	if neighbor == nil || neighbor.status != http.StatusOK {
		return "", "", false
	}

	if base != nil && neighbor.body == base.body {
		return "", "", false
	}

	structured := looksStructured(neighbor.body)
	sized := base != nil && comparableSize(base.body, neighbor.body)

	// Guard against the app's generic 200 fallback: require either a structured
	// object or a distinct response of comparable size to the baseline.
	if !structured && !sized {
		return "", "", false
	}

	marker, sensitive := sensitiveMarker(neighbor.body)

	if isOwnedResource(resource) {
		if marker == "" {
			marker = strings.TrimSpace(resource) + " object owned by another user"
		}

		return finding.High, marker, true
	}

	if sensitive {
		return finding.High, marker, true
	}

	return finding.Info, "", true
}

// buildIDOR assembles an access-control finding for a confirmed object reference.
func buildIDOR(severity finding.Severity, title, extracted, marker string, resp *response) finding.Finding {
	f := finding.Finding{
		Title:    title,
		Module:   "access",
		Severity: severity,
		OWASP:    "A01:2025 - Broken Access Control",
		CWE:      "CWE-639",
		Evidence: finding.Evidence{
			Request:   resp.dump,
			Response:  trim(resp.body, 400),
			Extracted: extracted,
		},
	}

	if severity == finding.High {
		f.CVSS = 7.1
		f.Description = "Under the authenticated session, changing the object identifier returned another object (" + marker + ") with HTTP 200 instead of 403/404, so the server is not enforcing object-level ownership."
		f.NextSteps = []string{
			"Confirm the returned record belongs to a different user or account.",
			"Enforce object-level authorization tied to the authenticated user on every request.",
			"Prefer unguessable identifiers and verify ownership server-side.",
		}

		return f
	}

	f.Description = "Adjacent identifier values return distinct HTTP 200 objects, so the reference is enumerable. On its own this is not an IDOR: public content (products, articles) behaves the same way. It is a vulnerability only if the objects expose data restricted to other users or accounts."
	f.NextSteps = []string{
		"Manually verify whether the returned objects contain data owned by other users/accounts (e.g. baskets, orders, profiles).",
		"If the data is private, enforce object-level authorization and prefer unguessable identifiers.",
	}

	return f
}

// idorTitle builds a finding title from the severity and the reference subject.
func idorTitle(severity finding.Severity, subject string) string {
	if severity == finding.High {
		return "Possible IDOR in " + subject
	}

	return "Enumerable object reference in " + subject
}

// resourceFromParam derives a resource label for ownership analysis from a
// parameter name and its endpoint path.
func resourceFromParam(p recon.Param) string {
	resource := p.Name
	if u, err := url.Parse(p.Endpoint); err == nil {
		resource += " " + lastPathSegment(u.Path)
	}

	return resource
}

// precedingSegment returns the path segment just before idx, the resource that
// owns the identifier (e.g. "basket" in /rest/basket/6).
func precedingSegment(segments []string, idx int) string {
	for i := idx - 1; i >= 0; i-- {
		if segments[i] != "" {
			return segments[i]
		}
	}

	return ""
}

// lastPathSegment returns the final non-empty segment of a path.
func lastPathSegment(path string) string {
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] != "" {
			return segments[i]
		}
	}

	return ""
}

// hasNumericSegment reports whether any path segment is purely numeric.
func hasNumericSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if idRe.MatchString(segment) {
			return true
		}
	}

	return false
}

// collectionIDOR probes user-owned collection endpoints (e.g. /api/Addresss,
// /api/Cards) by requesting sequential item identifiers. When several ids return
// distinct 200 objects under the authenticated session, the server is not
// scoping the collection to the current user. This reaches item endpoints that
// an SPA never calls directly, which passive capture alone would miss.
func collectionIDOR(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, endpoint := range surface.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || hasNumericSegment(u.Path) {
			continue
		}

		resource := lastPathSegment(u.Path)
		if !isOwnedResource(resource) {
			continue
		}

		key := u.Host + "|" + u.Path
		if tested[key] {
			continue
		}

		if len(tested) >= maxPathIDORTemplates {
			break
		}

		tested[key] = true

		if f, ok := probeCollectionItems(cfg, client, u, resource); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

func probeCollectionItems(cfg *config.Config, client *http.Client, u *url.URL, resource string) (finding.Finding, bool) {
	basePath := strings.TrimRight(u.Path, "/")

	var objects []*response
	for _, id := range []string{"1", "2", "3"} {
		clone := *u
		clone.Path = basePath + "/" + id

		resp := get(cfg, client, clone.String())
		if resp == nil || resp.status != http.StatusOK || !looksStructured(resp.body) {
			continue
		}

		objects = append(objects, resp)
	}

	// Two or more sequential ids returning distinct structured objects under our
	// session means the collection is not scoped to the authenticated user.
	if len(objects) < 2 || objects[0].body == objects[len(objects)-1].body {
		return finding.Finding{}, false
	}

	other := objects[len(objects)-1]

	marker, _ := sensitiveMarker(other.body)
	if marker == "" {
		marker = resource + " objects belonging to other users"
	}

	template := basePath + "/{id}"
	extracted := basePath + "/1 .. /3 -> distinct " + resource + " objects (HTTP 200)"

	return buildIDOR(finding.High, idorTitle(finding.High, "path '"+template+"'"), extracted, marker, other), true
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
