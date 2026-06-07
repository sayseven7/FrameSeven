// Package scanner orchestrates a full scan: it maps the surface with recon and
// then runs every test and enrichment module against it, returning a report.
package scanner

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/cve"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/report"
	"github.com/sayseven7/frameseven/internal/tools/v1/access"
	"github.com/sayseven7/frameseven/internal/tools/v1/lfi"
	"github.com/sayseven7/frameseven/internal/tools/v1/misconfig"
	"github.com/sayseven7/frameseven/internal/tools/v1/ratelimit"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
	"github.com/sayseven7/frameseven/internal/tools/v1/sqli"
	"github.com/sayseven7/frameseven/internal/tools/v1/ssrf"
)

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
	enabled := selectedModules(cfg.SelectedModules)

	surface := recon.Surface{}
	var moduleFindings []finding.Finding
	var moduleErrors []report.ScanErrorV1

	if enabled["recon"] {
		moduleStarted := startModule(logger, "recon", "mapping the target attack surface")
		surface, moduleFindings = recon.Run(cfg, client)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("recon")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "recon", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["sqli"] {
		moduleStarted := startModule(logger, "sqli", "testing SQL injection vectors")
		moduleFindings = sqli.Run(cfg, client, surface)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("sqli")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "sqli", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["access"] {
		moduleStarted := startModule(logger, "access", "testing unauthenticated access and IDOR behavior")
		moduleFindings = access.Run(cfg, client, surface)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("access")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "access", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["ssrf"] {
		moduleStarted := startModule(logger, "ssrf", "testing server-side request forgery vectors")
		moduleFindings = ssrf.Run(cfg, client, surface)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("ssrf")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "ssrf", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["lfi"] {
		moduleStarted := startModule(logger, "lfi", "testing file inclusion and path traversal vectors")
		moduleFindings = lfi.Run(cfg, client, surface)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("lfi")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "lfi", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["misconfig"] {
		moduleStarted := startModule(logger, "misconfig", "checking HTTP and TLS configuration")
		moduleFindings = misconfig.Run(cfg, client)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("misconfig")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "misconfig", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["ratelimit"] {
		moduleStarted := startModule(logger, "ratelimit", "checking request rate-limit behavior")
		moduleFindings = ratelimit.Run(cfg, client)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("ratelimit")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "ratelimit", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	if enabled["cve"] {
		moduleStarted := startModule(logger, "cve", "looking up CVEs for detected products")
		moduleFindings = cve.Run(cfg, client, surface)
		findings = append(findings, moduleFindings...)
		moduleErrors = recorder.Take("cve")
		scanErrors = append(scanErrors, moduleErrors...)
		finishModule(logger, "cve", moduleStarted, len(moduleFindings), len(moduleErrors))
	}

	logger.Printf(
		"INFO  scan completed in %s with %d finding(s) and %d error(s)",
		time.Since(started).Round(time.Millisecond),
		len(findings),
		len(scanErrors),
	)

	return report.New("v1", cfg.Target, started, time.Since(started), surface, findings, scanErrors)
}

func selectedModules(names []string) map[string]bool {
	enabled := map[string]bool{}
	if len(names) == 0 {
		for _, name := range []string{"recon", "sqli", "access", "ssrf", "lfi", "misconfig", "ratelimit", "cve"} {
			enabled[name] = true
		}

		return enabled
	}

	for _, name := range names {
		enabled[strings.ToLower(strings.TrimSpace(name))] = true
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
