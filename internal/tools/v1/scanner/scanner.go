// Package scanner orchestrates a full scan: it maps the surface with recon and
// then runs every test and enrichment module against it, returning a report.
package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/cve"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/access"
	"github.com/sayseven7/frameseven/internal/tools/v1/bannergrab"
	"github.com/sayseven7/frameseven/internal/tools/v1/content"
	"github.com/sayseven7/frameseven/internal/tools/v1/crawler"
	"github.com/sayseven7/frameseven/internal/tools/v1/lfi"
	"github.com/sayseven7/frameseven/internal/tools/v1/misconfig"
	"github.com/sayseven7/frameseven/internal/tools/v1/nmap"
	"github.com/sayseven7/frameseven/internal/tools/v1/ports"
	"github.com/sayseven7/frameseven/internal/tools/v1/ratelimit"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
	"github.com/sayseven7/frameseven/internal/tools/v1/sqli"
	"github.com/sayseven7/frameseven/internal/tools/v1/sqlmap"
	"github.com/sayseven7/frameseven/internal/tools/v1/ssrf"
	"github.com/sayseven7/frameseven/internal/tools/v1/subdomain"
)

// Module describes one scanner module exposed by Framework v1.
type Module struct {
	Name             string
	Description      string
	EnabledByDefault bool
}

// Modules is the ordered Framework v1 scanner module catalog.
var Modules = []Module{
	{"recon", "DNS, technology, endpoint, parameter, and sensitive-file discovery", true},
	{"sqli", "SQL injection detection and data extraction", true},
	{"access", "Unauthenticated endpoint, admin path, and IDOR checks", true},
	{"ssrf", "Internal service and cloud metadata SSRF checks", true},
	{"lfi", "Local file inclusion and path traversal checks", true},
	{"misconfig", "Security header, HTTP method, CORS, and TLS checks", true},
	{"ratelimit", "Request burst and rate-limit behavior checks", true},
	{"cve", "NVD CVE lookup for detected product versions", true},
	{"crawler", "Same-origin link and form discovery beyond the landing page", false},
	{"content", "Common content and directory discovery", false},
	{"subdomain", "Common DNS subdomain discovery", false},
	{"ports", "Light TCP checks for common web-facing ports", false},
	{"nmap", "Nmap integration availability check", false},
	{"sqlmap", "sqlmap integration availability check", false},
	{"bannergrab", "FTP, SSH, and SMTP service banner checks", false},
}

// Scan runs the full pipeline and returns a report.
func Scan(cfg *config.Config) report.Report {
	started := time.Now()
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", log.Ltime)
	}
	cfg.Logger = logger

	recorder := &requestErrorRecorder{}
	client := newClient(cfg, recorder)

	var findings []finding.Finding
	var scanErrors []report.ScanErrorV1
	selected, err := NormalizeModules(cfg.SelectedModules)
	if err != nil {
		scanErrors = append(scanErrors, report.ScanErrorV1{
			Module:  "scanner",
			Message: err.Error(),
		})

		return report.New("v1", cfg.Target, started, time.Since(started), recon.Surface{}, findings, scanErrors)
	}

	enabled := selectedModules(selected)

	surface := recon.Surface{}

	steps := []moduleStep{
		{
			name:     "recon",
			activity: "mapping the target attack surface",
			run: func() []finding.Finding {
				var reconFindings []finding.Finding
				surface, reconFindings = recon.Run(cfg, client)

				return reconFindings
			},
		},
		{
			name:     "sqli",
			activity: "testing SQL injection vectors",
			run: func() []finding.Finding {
				return sqli.Run(cfg, client, surface)
			},
		},
		{
			name:     "access",
			activity: "testing unauthenticated access and IDOR behavior",
			run: func() []finding.Finding {
				return access.Run(cfg, client, surface)
			},
		},
		{
			name:     "ssrf",
			activity: "testing server-side request forgery vectors",
			run: func() []finding.Finding {
				return ssrf.Run(cfg, client, surface)
			},
		},
		{
			name:     "lfi",
			activity: "testing file inclusion and path traversal vectors",
			run: func() []finding.Finding {
				return lfi.Run(cfg, client, surface)
			},
		},
		{
			name:     "misconfig",
			activity: "checking HTTP and TLS configuration",
			run: func() []finding.Finding {
				return misconfig.Run(cfg, client)
			},
		},
		{
			name:     "ratelimit",
			activity: "checking request rate-limit behavior",
			run: func() []finding.Finding {
				return ratelimit.Run(cfg, client)
			},
		},
		{
			name:     "cve",
			activity: "looking up CVEs for detected products",
			run: func() []finding.Finding {
				return cve.Run(cfg, client, surface)
			},
		},
		{
			name:     "crawler",
			activity: "crawling same-origin links discovered by recon",
			run: func() []finding.Finding {
				return crawler.Run(cfg, client, surface)
			},
		},
		{
			name:     "content",
			activity: "checking common content paths",
			run: func() []finding.Finding {
				return content.Run(cfg, client)
			},
		},
		{
			name:     "subdomain",
			activity: "resolving common subdomain candidates",
			run: func() []finding.Finding {
				return subdomain.Run(cfg)
			},
		},
		{
			name:     "ports",
			activity: "checking common web-facing TCP ports",
			run: func() []finding.Finding {
				return ports.Run(cfg)
			},
		},
		{
			name:     "nmap",
			activity: "checking Nmap integration availability",
			run: func() []finding.Finding {
				return nmap.Run()
			},
		},
		{
			name:     "sqlmap",
			activity: "checking sqlmap integration availability",
			run: func() []finding.Finding {
				return sqlmap.Run()
			},
		},
		{
			name:     "bannergrab",
			activity: "checking FTP, SSH, and SMTP service banners",
			run: func() []finding.Finding {
				return bannergrab.Run(cfg)
			},
		},
	}

	for _, step := range steps {
		if !enabled[step.name] {
			continue
		}

		moduleStarted := startModule(logger, step.name, step.activity)
		moduleFindings := step.run()
		findings = append(findings, moduleFindings...)
		moduleErrors := recorder.Take(step.name)
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, step.name, moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	logger.Printf(
		"INFO  scan completed in %s with %d finding(s) and %d error(s)",
		time.Since(started).Round(time.Millisecond),
		len(findings),
		len(scanErrors),
	)

	return report.New("v1", cfg.Target, started, time.Since(started), surface, findings, scanErrors)
}

type moduleStep struct {
	name     string
	activity string
	run      func() []finding.Finding
}

// ModuleNames returns every Framework v1 module name in execution order.
func ModuleNames() []string {
	names := make([]string, 0, len(Modules))
	for _, module := range Modules {
		names = append(names, module.Name)
	}

	return names
}

// DefaultModuleNames returns every Framework v1 module enabled by default.
func DefaultModuleNames() []string {
	var names []string
	for _, module := range Modules {
		if module.EnabledByDefault {
			names = append(names, module.Name)
		}
	}

	return names
}

// NormalizeModules validates module names and includes required dependencies.
// Empty input means every default Framework v1 module is enabled.
func NormalizeModules(names []string) ([]string, error) {
	if len(names) == 0 {
		return DefaultModuleNames(), nil
	}

	valid := map[string]bool{}
	for _, module := range Modules {
		valid[module.Name] = true
	}

	seen := map[string]bool{}
	var selected []string

	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}

		if !valid[name] {
			return nil, fmt.Errorf("unknown scanner module %q", raw)
		}

		if !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}

	if len(selected) == 0 {
		return nil, errors.New("at least one scanner module must be selected")
	}

	return includeRequiredModules(selected), nil
}

func includeRequiredModules(selected []string) []string {
	needsRecon := false
	for _, name := range selected {
		switch name {
		case "sqli", "access", "ssrf", "lfi", "cve", "crawler":
			needsRecon = true
		}
	}

	if !needsRecon || slices.Contains(selected, "recon") {
		return selected
	}

	return append([]string{"recon"}, selected...)
}

func selectedModules(names []string) map[string]bool {
	enabled := map[string]bool{}
	for _, name := range names {
		enabled[name] = true
	}

	return enabled
}

// newClient builds the shared HTTP client. TLS verification is disabled so the
// scan can reach targets with invalid certificates; the misconfig module
// reports certificate problems separately.
func newClient(cfg *config.Config, recorder *requestErrorRecorder) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - a scanner must reach hosts with invalid certs
	}

	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &recordingTransport{
			base:     transport,
			recorder: recorder,
			logger:   cfg.Logger,
			verbose:  cfg.Verbose,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 || sameOrigin(via[0].URL, req.URL) {
				return nil
			}

			err := errors.New("redirect blocked because it leaves the original origin")
			recorder.Record(err)

			return err
		},
	}
}

type recordingTransport struct {
	base     http.RoundTripper
	recorder *requestErrorRecorder
	logger   *log.Logger
	verbose  bool
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	started := time.Now()
	if t.verbose {
		t.logger.Printf("DEBUG HTTP request %s %s", req.Method, req.URL.Redacted())
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.recorder.Record(err)
		if t.verbose {
			t.logger.Printf(
				"DEBUG HTTP request failed %s %s after %s: %v",
				req.Method,
				req.URL.Redacted(),
				time.Since(started).Round(time.Millisecond),
				err,
			)
		}

		return nil, err
	}

	if t.verbose {
		t.logger.Printf(
			"DEBUG HTTP response %s %s -> %d in %s",
			req.Method,
			req.URL.Redacted(),
			resp.StatusCode,
			time.Since(started).Round(time.Millisecond),
		)
	}

	return resp, nil
}

func startModule(logger *log.Logger, name, activity string) time.Time {
	logger.Printf("INFO  [%s] started: %s", name, activity)

	return time.Now()
}

func finishModule(logger *log.Logger, name string, started time.Time, findings, scanErrors int) {
	logger.Printf(
		"INFO  [%s] completed in %s: %d finding(s), %d error(s)",
		name,
		time.Since(started).Round(time.Millisecond),
		findings,
		scanErrors,
	)
}

type requestErrorRecorder struct {
	mu     sync.Mutex
	errors []error
}

func (r *requestErrorRecorder) Record(err error) {
	if err == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.errors = append(r.errors, err)
}

func (r *requestErrorRecorder) Take(module string) []report.ScanErrorV1 {
	r.mu.Lock()
	defer r.mu.Unlock()

	errors := r.errors
	r.errors = nil

	out := make([]report.ScanErrorV1, 0, len(errors))
	seen := map[string]bool{}

	for _, err := range errors {
		message := err.Error()
		if seen[message] {
			continue
		}

		seen[message] = true
		out = append(out, report.ScanErrorV1{
			Module:  module,
			Message: message,
		})
	}

	return out
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Hostname() == b.Hostname() && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}

	if u.Scheme == "https" {
		return "443"
	}

	if u.Scheme == "http" {
		return "80"
	}

	return ""
}
