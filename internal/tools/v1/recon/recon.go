// Package recon maps the attack surface of a target: DNS, response headers,
// technologies in use, sensitive files, and reachable endpoints/parameters.
// Its Surface output feeds every other scanner module.
package recon

import (
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
)

// Param is a single input point discovered on the target.
type Param struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
}

// Technology is a product (optionally with version) detected on the target.
type Technology struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source"`
}

// DNSInfo holds the DNS records resolved for the target host.
type DNSInfo struct {
	A     []string `json:"a,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

// Surface is the mapped attack surface, shared with the test modules.
type Surface struct {
	BaseURL        string            `json:"base_url"`
	Host           string            `json:"host"`
	Headers        map[string]string `json:"headers"`
	Technologies   []Technology      `json:"technologies"`
	DNS            DNSInfo           `json:"dns"`
	Endpoints      []string          `json:"endpoints"`
	Params         []Param           `json:"params"`
	SensitiveFiles []string          `json:"sensitive_files"`
}

// sensitiveFiles maps a probe path to a signature that must appear in the
// response body to confirm the file is real (avoids soft-404 false positives).
// An empty signature means "any 200 response counts".
var sensitiveFiles = map[string]string{
	"/.git/HEAD":         "ref:",
	"/.git/config":       "[core]",
	"/.env":              "=",
	"/.svn/entries":      "",
	"/.htaccess":         "",
	"/robots.txt":        "",
	"/.DS_Store":         "",
	"/backup.zip":        "",
	"/config.php.bak":    "",
	"/wp-config.php.bak": "",
	"/phpinfo.php":       "phpinfo()",
	"/server-status":     "Apache Server Status",
}

// Run maps the surface of the target.
func Run(cfg *config.Config, client *http.Client) (Surface, []finding.Finding) {
	surface := Surface{
		BaseURL: cfg.Target,
		Headers: map[string]string{},
	}

	var findings []finding.Finding

	base, err := url.Parse(cfg.Target)
	if err != nil {
		return surface, findings
	}

	surface.Host = base.Hostname()
	surface.DNS = resolveDNS(base.Hostname())

	dump, body, resp := fetch(cfg, client, http.MethodGet, cfg.Target)
	if resp == nil {
		return surface, findings
	}

	for name := range resp.Header {
		surface.Headers[name] = resp.Header.Get(name)
	}

	surface.Technologies = fingerprint(resp.Header, body)
	surface.Endpoints, surface.Params = discover(base, body)

	if len(surface.Technologies) > 0 {
		findings = append(findings, technologyFinding(surface.Technologies, dump))
	}

	findings = append(findings, probeSensitiveFiles(cfg, client, base, &surface)...)

	return surface, findings
}

func resolveDNS(host string) DNSInfo {
	info := DNSInfo{}

	if host == "" {
		return info
	}

	if addrs, err := net.LookupHost(host); err == nil {
		info.A = addrs
	}

	if cname, err := net.LookupCNAME(host); err == nil && cname != host+"." {
		info.CNAME = cname
	}

	if mx, err := net.LookupMX(host); err == nil {
		for _, m := range mx {
			info.MX = append(info.MX, m.Host)
		}
	}

	if ns, err := net.LookupNS(host); err == nil {
		for _, n := range ns {
			info.NS = append(info.NS, n.Host)
		}
	}

	if txt, err := net.LookupTXT(host); err == nil {
		info.TXT = txt
	}

	return info
}

var (
	metaGeneratorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	versionTailRe   = regexp.MustCompile(`^(.*?)[/ ]v?(\d+(?:\.\d+)+)`)
)

// bodyMarkers maps a substring in the response body to a technology name.
var bodyMarkers = map[string]string{
	"wp-content":      "WordPress",
	"Drupal.settings": "Drupal",
	"/sites/default/": "Drupal",
	"Joomla!":         "Joomla",
	"__NEXT_DATA__":   "Next.js",
	"ng-version":      "Angular",
	"data-reactroot":  "React",
	"csrf-token":      "Laravel",
}

// cookieMarkers maps a cookie name to the technology it implies.
var cookieMarkers = map[string]string{
	"PHPSESSID":         "PHP",
	"JSESSIONID":        "Java",
	"ASP.NET_SessionId": "ASP.NET",
	"laravel_session":   "Laravel",
	"csrftoken":         "Django",
}

// fingerprint extracts technologies from response headers and body. It is the
// pure, testable core of detection.
func fingerprint(headers http.Header, body string) []Technology {
	var techs []Technology
	seen := map[string]bool{}

	add := func(name, version, source string) {
		key := strings.ToLower(name)
		if name == "" || seen[key] {
			return
		}

		seen[key] = true
		techs = append(techs, Technology{Name: name, Version: version, Source: source})
	}

	if server := headers.Get("Server"); server != "" {
		name, version := splitProductVersion(server)
		add(name, version, "Server header")
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		name, version := splitProductVersion(powered)
		add(name, version, "X-Powered-By header")
	}

	if m := metaGeneratorRe.FindStringSubmatch(body); m != nil {
		name, version := splitProductVersion(m[1])
		add(name, version, "meta generator")
	}

	for _, c := range headers["Set-Cookie"] {
		for marker, name := range cookieMarkers {
			if strings.Contains(c, marker) {
				add(name, "", "cookie")
			}
		}
	}

	for marker, name := range bodyMarkers {
		if strings.Contains(body, marker) {
			add(name, "", "body marker")
		}
	}

	return techs
}

// splitProductVersion turns values like "Apache/2.4.49 (Ubuntu)" or
// "WordPress 5.8" into ("Apache", "2.4.49") / ("WordPress", "5.8").
func splitProductVersion(s string) (string, string) {
	s = strings.TrimSpace(s)

	if m := versionTailRe.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}

	if idx := strings.IndexAny(s, " /"); idx > 0 {
		return strings.TrimSpace(s[:idx]), ""
	}

	return s, ""
}

var (
	hrefRe       = regexp.MustCompile(`(?i)(?:href|src|action)=["']([^"']+)["']`)
	inputNameRe  = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']+)["']`)
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["']`)
)

// discover extracts endpoints and parameters from the homepage HTML, keeping
// only links on the same host as the target.
func discover(base *url.URL, body string) ([]string, []Param) {
	endpoints := map[string]bool{}
	params := map[string]Param{}

	addParamsFromURL := func(u *url.URL) {
		q := u.Query()
		clean := *u
		for name := range q {
			key := name + "|" + clean.Path
			params[key] = Param{Name: name, Endpoint: u.String(), Method: http.MethodGet}
		}
	}

	if len(base.Query()) > 0 {
		addParamsFromURL(base)
	}

	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		ref, err := base.Parse(strings.TrimSpace(m[1]))
		if err != nil {
			continue
		}

		if ref.Hostname() != base.Hostname() {
			continue
		}

		ref.Fragment = ""
		endpoints[ref.String()] = true

		if len(ref.Query()) > 0 {
			addParamsFromURL(ref)
		}
	}

	inputs := inputNameRe.FindAllStringSubmatch(body, -1)
	if len(inputs) > 0 {
		action := base.String()

		if m := formActionRe.FindStringSubmatch(body); m != nil && m[1] != "" {
			if ref, err := base.Parse(m[1]); err == nil {
				action = ref.String()
			}
		}

		for _, in := range inputs {
			key := in[1] + "|form"
			params[key] = Param{Name: in[1], Endpoint: action, Method: http.MethodGet}
		}
	}

	return mapKeys(endpoints), paramValues(params)
}

func probeSensitiveFiles(cfg *config.Config, client *http.Client, base *url.URL, surface *Surface) []finding.Finding {
	var findings []finding.Finding

	for path, signature := range sensitiveFiles {
		ref, err := base.Parse(path)
		if err != nil {
			continue
		}

		dump, body, resp := fetch(cfg, client, http.MethodGet, ref.String())
		if resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}

		if signature != "" && !strings.Contains(body, signature) {
			continue
		}

		surface.SensitiveFiles = append(surface.SensitiveFiles, path)

		findings = append(findings, finding.Finding{
			Title:       "Exposed sensitive file: " + path,
			Module:      "recon",
			Severity:    finding.Medium,
			OWASP:       "A05:2025 - Security Misconfiguration",
			CWE:         "CWE-538",
			CVSS:        5.3,
			Description: "A file that should not be publicly reachable returned content over HTTP.",
			Evidence: finding.Evidence{
				Request:   dump,
				Response:  snippet(body, 400),
				Extracted: path,
			},
			NextSteps: []string{
				"Remove the file from the web root or block it at the server level.",
				"Review the file for leaked secrets, source code, or configuration.",
			},
		})
	}

	return findings
}

func technologyFinding(techs []Technology, requestDump string) finding.Finding {
	var parts []string
	for _, t := range techs {
		if t.Version != "" {
			parts = append(parts, t.Name+" "+t.Version)
		} else {
			parts = append(parts, t.Name)
		}
	}

	return finding.Finding{
		Title:       "Technology stack disclosed",
		Module:      "recon",
		Severity:    finding.Info,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-200",
		Description: "Server responses disclose the technologies and versions in use, which aids targeted attacks.",
		Evidence: finding.Evidence{
			Request:   requestDump,
			Extracted: strings.Join(parts, ", "),
		},
		NextSteps: []string{
			"Strip or obfuscate version banners (Server, X-Powered-By, generator).",
			"Feed the detected versions into the CVE module to check for known issues.",
		},
	}
}

// fetch performs a request and returns the raw request dump (PoC), the response
// body as a string, and the response. The response body is fully read and
// closed. On error all three are zero/nil.
func fetch(cfg *config.Config, client *http.Client, method, target string) (string, string, *http.Response) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return "", "", nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return string(dump), string(body), resp
}

func snippet(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}

	return s
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func paramValues(m map[string]Param) []Param {
	values := make([]Param, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}

	return values
}
