// Package scanner orchestrates a full scan: it maps the surface with recon and
// then runs every test and enrichment module against it, returning a report.
package scanner

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
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
	recorder := &requestErrorRecorder{}
	client := newClient(cfg, recorder)

	var findings []finding.Finding
	var scanErrors []report.ScanErrorV1

	surface, reconFindings := recon.Run(cfg, client)
	findings = append(findings, reconFindings...)
	scanErrors = append(scanErrors, recorder.Take("recon")...)

	findings = append(findings, sqli.Run(cfg, client, surface)...)
	scanErrors = append(scanErrors, recorder.Take("sqli")...)

	findings = append(findings, access.Run(cfg, client, surface)...)
	scanErrors = append(scanErrors, recorder.Take("access")...)

	findings = append(findings, ssrf.Run(cfg, client, surface)...)
	scanErrors = append(scanErrors, recorder.Take("ssrf")...)

	findings = append(findings, lfi.Run(cfg, client, surface)...)
	scanErrors = append(scanErrors, recorder.Take("lfi")...)

	findings = append(findings, misconfig.Run(cfg, client)...)
	scanErrors = append(scanErrors, recorder.Take("misconfig")...)

	findings = append(findings, ratelimit.Run(cfg, client)...)
	scanErrors = append(scanErrors, recorder.Take("ratelimit")...)

	findings = append(findings, cve.Run(cfg, client, surface)...)
	scanErrors = append(scanErrors, recorder.Take("cve")...)

	return report.New("v1", cfg.Target, started, time.Since(started), surface, findings, scanErrors)
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
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.recorder.Record(err)
	}

	return resp, err
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
