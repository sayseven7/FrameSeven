// Package scanner orchestrates a full scan: it maps the surface with recon and
// then runs every test and enrichment tool against it, returning a report.
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
	"github.com/sayseven7/frameseven/internal/tools/v1/external/nmap"
	"github.com/sayseven7/frameseven/internal/tools/v1/external/sqlmap"
	"github.com/sayseven7/frameseven/internal/tools/v1/lfi"
	"github.com/sayseven7/frameseven/internal/tools/v1/misconfig"
	"github.com/sayseven7/frameseven/internal/tools/v1/ports"
	"github.com/sayseven7/frameseven/internal/tools/v1/ratelimit"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
	"github.com/sayseven7/frameseven/internal/tools/v1/sqli"
	"github.com/sayseven7/frameseven/internal/tools/v1/ssrf"
	"github.com/sayseven7/frameseven/internal/tools/v1/subdomain"
)

// RunFunc is the common signature for every Framework v1 scanner tool.
type RunFunc func(*config.Config, *http.Client, *recon.Surface) []finding.Finding

// Tool describes one scanner tool exposed by Framework v1.
type Tool struct {
	Name             string
	Description      string
	Activity         string
	EnabledByDefault bool
	Run              RunFunc
}

// Tools is the ordered Framework v1 scanner tool catalog.
var Tools = []Tool{
	{Name: "recon", Description: "DNS, technology, endpoint, parameter, and sensitive-file discovery", Activity: "mapping the target attack surface", EnabledByDefault: true, Run: recon.Run},
	{Name: "sqli", Description: "SQL injection detection and data extraction", Activity: "testing SQL injection vectors", EnabledByDefault: true, Run: sqli.Run},
	{Name: "access", Description: "Unauthenticated endpoint, admin path, and IDOR checks", Activity: "testing unauthenticated access and IDOR behavior", EnabledByDefault: true, Run: access.Run},
	{Name: "ssrf", Description: "Internal service and cloud metadata SSRF checks", Activity: "testing server-side request forgery vectors", EnabledByDefault: true, Run: ssrf.Run},
	{Name: "lfi", Description: "Local file inclusion and path traversal checks", Activity: "testing file inclusion and path traversal vectors", EnabledByDefault: true, Run: lfi.Run},
	{Name: "misconfig", Description: "Security header, HTTP method, CORS, and TLS checks", Activity: "checking HTTP and TLS configuration", EnabledByDefault: true, Run: misconfig.Run},
	{Name: "ratelimit", Description: "Request burst and rate-limit behavior checks", Activity: "checking request rate-limit behavior", EnabledByDefault: true, Run: ratelimit.Run},
	{Name: "cve", Description: "NVD CVE lookup for detected product versions", Activity: "looking up CVEs for detected products", EnabledByDefault: true, Run: cve.Run},
	{Name: "crawler", Description: "Same-origin link and form discovery beyond the landing page", Activity: "crawling same-origin links discovered by recon", EnabledByDefault: false, Run: crawler.Run},
	{Name: "content", Description: "Common content and directory discovery", Activity: "checking common content paths", EnabledByDefault: false, Run: content.Run},
	{Name: "subdomain", Description: "Common DNS subdomain discovery", Activity: "resolving common subdomain candidates", EnabledByDefault: false, Run: subdomain.Run},
	{Name: "ports", Description: "Light TCP checks for common web-facing ports", Activity: "checking common web-facing TCP ports", EnabledByDefault: false, Run: ports.Run},
	{Name: "nmap", Description: "Nmap common-port scan (fail-safe external execution)", Activity: "running an Nmap scan of common web-facing ports", EnabledByDefault: false, Run: nmap.Run},
	{Name: "sqlmap", Description: "sqlmap SQL injection test (fail-safe external execution)", Activity: "running a sqlmap SQL injection test", EnabledByDefault: false, Run: sqlmap.Run},
	{Name: "bannergrab", Description: "FTP, SSH, and SMTP service banner checks", Activity: "checking FTP, SSH, and SMTP service banners", EnabledByDefault: false, Run: bannergrab.Run},
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
	selected, err := NormalizeTools(cfg.SelectedTools)
	if err != nil {
		scanErrors = append(scanErrors, report.ScanErrorV1{
			Module:  "scanner",
			Message: err.Error(),
		})

		return report.New("v1", cfg.Target, started, time.Since(started), recon.Surface{}, findings, scanErrors)
	}

	enabled := selectedTools(selected)
	surface := &recon.Surface{}

	for _, m := range Tools {
		if !enabled[m.Name] {
			continue
		}

		toolStarted := startTool(logger, m.Name, m.Activity)
		toolFindings, panicErr := runTool(m, cfg, client, surface)
		findings = append(findings, toolFindings...)
		toolErrors := recorder.Take(m.Name)
		if panicErr != nil {
			logger.Printf("ERROR [%s] isolated panic: %s", m.Name, panicErr.Message)
			toolErrors = append(toolErrors, *panicErr)
		}
		scanErrors = append(scanErrors, toolErrors...)
		finishTool(logger, m.Name, toolStarted, len(toolFindings), len(toolErrors))
	}

	logger.Printf(
		"INFO  scan completed in %s with %d finding(s) and %d error(s)",
		time.Since(started).Round(time.Millisecond),
		len(findings),
		len(scanErrors),
	)

	return report.New("v1", cfg.Target, started, time.Since(started), *surface, findings, scanErrors)
}

// runTool executes one tool's Run function with panic isolation. A tool that
// panics (a bug, a nil dereference, an external integration crash) is contained
// here: it yields no findings and a recorded scan error instead of aborting the
// whole scan, so every other tool still runs and the report is still returned.
func runTool(m Tool, cfg *config.Config, client *http.Client, surface *recon.Surface) (findings []finding.Finding, scanErr *report.ScanErrorV1) {
	defer func() {
		if r := recover(); r != nil {
			findings = nil
			scanErr = &report.ScanErrorV1{
				Module:  m.Name,
				Message: fmt.Sprintf("tool panicked and was isolated: %v", r),
			}
		}
	}()

	return m.Run(cfg, client, surface), nil
}

// ToolNames returns every Framework v1 tool name in execution order.
func ToolNames() []string {
	names := make([]string, 0, len(Tools))
	for _, tool := range Tools {
		names = append(names, tool.Name)
	}

	return names
}

// DefaultToolNames returns every Framework v1 tool enabled by default.
func DefaultToolNames() []string {
	var names []string
	for _, tool := range Tools {
		if tool.EnabledByDefault {
			names = append(names, tool.Name)
		}
	}

	return names
}

// NormalizeTools validates tool names and includes required dependencies.
// Empty input means every default Framework v1 tool is enabled.
func NormalizeTools(names []string) ([]string, error) {
	if len(names) == 0 {
		return DefaultToolNames(), nil
	}

	valid := map[string]bool{}
	for _, tool := range Tools {
		valid[tool.Name] = true
	}

	seen := map[string]bool{}
	var selected []string

	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}

		if !valid[name] {
			return nil, fmt.Errorf("unknown scanner tool %q", raw)
		}

		if !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}

	if len(selected) == 0 {
		return nil, errors.New("at least one scanner tool must be selected")
	}

	return includeRequiredTools(selected), nil
}

func includeRequiredTools(selected []string) []string {
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

func selectedTools(names []string) map[string]bool {
	enabled := map[string]bool{}
	for _, name := range names {
		enabled[name] = true
	}

	return enabled
}

// newClient builds the shared HTTP client. TLS verification is disabled so the
// scan can reach targets with invalid certificates; the misconfig tool
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

func startTool(logger *log.Logger, name, activity string) time.Time {
	logger.Printf("INFO  [%s] started: %s", name, activity)

	return time.Now()
}

func finishTool(logger *log.Logger, name string, started time.Time, findings, scanErrors int) {
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
