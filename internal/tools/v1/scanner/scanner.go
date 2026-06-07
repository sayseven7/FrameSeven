// Package scanner orchestrates a full scan: it maps the surface with recon and
// then runs every test and enrichment module against it, returning a report.
package scanner

import (
	"crypto/tls"
	"net/http"
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
	client := newClient(cfg)

	var findings []finding.Finding

	surface, reconFindings := recon.Run(cfg, client)
	findings = append(findings, reconFindings...)

	findings = append(findings, sqli.Run(cfg, client, surface)...)
	findings = append(findings, access.Run(cfg, client, surface)...)
	findings = append(findings, ssrf.Run(cfg, client, surface)...)
	findings = append(findings, lfi.Run(cfg, client, surface)...)
	findings = append(findings, misconfig.Run(cfg, client)...)
	findings = append(findings, ratelimit.Run(cfg, client)...)
	findings = append(findings, cve.Run(cfg, client, surface)...)

	return report.New(cfg.Target, started, time.Since(started), surface, findings)
}

// newClient builds the shared HTTP client. TLS verification is disabled so the
// scan can reach targets with invalid certificates; the misconfig module
// reports certificate problems separately.
func newClient(cfg *config.Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - a scanner must reach hosts with invalid certs
	}

	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}
}
