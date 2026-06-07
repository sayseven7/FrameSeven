// Package misconfig checks for security misconfiguration: missing security
// headers, dangerous HTTP methods, permissive CORS and weak TLS.
package misconfig

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// securityHeaders maps a header to a short note on what it protects against.
var securityHeaders = map[string]string{
	"Content-Security-Policy":   "mitigates XSS and data injection",
	"X-Frame-Options":           "prevents clickjacking",
	"X-Content-Type-Options":    "stops MIME sniffing",
	"Referrer-Policy":           "limits referrer leakage",
	"Permissions-Policy":        "restricts powerful browser features",
	"Strict-Transport-Security": "enforces HTTPS",
}

const evilOrigin = "https://evil.example"

// Run performs all configuration checks against the target.
func Run(cfg *config.Config, client *http.Client, _ *recon.Surface) []finding.Finding {
	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil
	}

	var findings []finding.Finding

	findings = append(findings, checkHeaders(cfg, client, base)...)
	findings = append(findings, checkMethods(cfg, client)...)
	findings = append(findings, checkCORS(cfg, client)...)
	findings = append(findings, checkTLS(base)...)

	return findings
}

func checkHeaders(cfg *config.Config, client *http.Client, base *url.URL) []finding.Finding {
	req, err := http.NewRequest(http.MethodGet, cfg.Target, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()

	missing := missingHeaders(resp.Header, base.Scheme == "https")
	if len(missing) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Missing security headers",
		Module:      "misconfig",
		Severity:    finding.Low,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-693",
		CVSS:        3.7,
		Description: "Recommended security response headers are absent: " + strings.Join(missing, ", ") + ".",
		Evidence: finding.Evidence{
			Request:   string(dump),
			Extracted: strings.Join(missing, "\n"),
		},
		NextSteps: []string{
			"Add the missing headers at the application or reverse-proxy layer.",
			"Start CSP in report-only mode, then enforce once tuned.",
		},
	}}
}

// missingHeaders returns the security headers absent from h. HSTS is only
// expected when the site is served over HTTPS.
func missingHeaders(h http.Header, https bool) []string {
	var missing []string

	for name := range securityHeaders {
		if name == "Strict-Transport-Security" && !https {
			continue
		}

		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}

	return missing
}

func checkMethods(cfg *config.Config, client *http.Client) []finding.Finding {
	var dangerous []string
	var dump string

	for _, method := range []string{http.MethodPut, http.MethodDelete, "TRACE"} {
		req, err := http.NewRequest(method, cfg.Target, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", cfg.UserAgent)

		if dump == "" {
			d, _ := httputil.DumpRequestOut(req, false)
			dump = string(d)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()

		if resp.StatusCode < 400 {
			dangerous = append(dangerous, fmt.Sprintf("%s (%d)", method, resp.StatusCode))
		}
	}

	if len(dangerous) == 0 {
		return nil
	}

	return []finding.Finding{{
		Title:       "Dangerous HTTP methods enabled",
		Module:      "misconfig",
		Severity:    finding.Medium,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-650",
		CVSS:        5.3,
		Description: "The server accepted potentially dangerous HTTP methods: " + strings.Join(dangerous, ", ") + ".",
		Evidence: finding.Evidence{
			Request:   dump,
			Extracted: strings.Join(dangerous, "\n"),
		},
		NextSteps: []string{
			"Disable unused methods (PUT, DELETE, TRACE) at the server.",
			"Allow only the methods each endpoint actually requires.",
		},
	}}
}

func checkCORS(cfg *config.Config, client *http.Client) []finding.Finding {
	req, err := http.NewRequest(http.MethodGet, cfg.Target, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Origin", evilOrigin)

	dump, _ := httputil.DumpRequestOut(req, true)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()

	permissive, withCreds := corsPermissive(resp.Header, evilOrigin)
	if !permissive {
		return nil
	}

	severity := finding.Medium
	cvss := 5.4

	if withCreds {
		severity = finding.High
		cvss = 7.5
	}

	return []finding.Finding{{
		Title:       "Permissive CORS policy",
		Module:      "misconfig",
		Severity:    severity,
		OWASP:       "A05:2025 - Security Misconfiguration",
		CWE:         "CWE-942",
		CVSS:        cvss,
		Description: "The server reflects an arbitrary Origin in Access-Control-Allow-Origin" + credsNote(withCreds) + ".",
		Evidence: finding.Evidence{
			Request:   string(dump),
			Response:  "Access-Control-Allow-Origin: " + resp.Header.Get("Access-Control-Allow-Origin"),
			Extracted: "reflected origin: " + evilOrigin + credsNote(withCreds),
		},
		NextSteps: []string{
			"Reflect only allowlisted origins; never echo arbitrary Origin values.",
			"Avoid combining Access-Control-Allow-Credentials with a wildcard or reflected origin.",
		},
	}}
}

// corsPermissive reports whether the response allows the probe origin (or any
// origin) and whether credentials are permitted.
func corsPermissive(h http.Header, origin string) (bool, bool) {
	allow := h.Get("Access-Control-Allow-Origin")
	creds := strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true")

	permissive := allow == "*" || allow == origin

	return permissive, creds && permissive
}

func checkTLS(base *url.URL) []finding.Finding {
	if base.Scheme != "https" {
		return nil
	}

	host := base.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, nil)
	if err != nil {
		// Verification failed: try again without verification to describe why.
		insecure, ierr := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 - intentional, to inspect an invalid chain
		if ierr != nil {
			return nil
		}
		defer insecure.Close()

		return []finding.Finding{tlsFinding(
			"Invalid or untrusted TLS certificate",
			finding.High, 7.4,
			"The TLS certificate failed verification: "+err.Error()+".",
			host,
		)}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var findings []finding.Finding

	if state.Version < tls.VersionTLS12 {
		findings = append(findings, tlsFinding(
			"Weak TLS protocol version",
			finding.Medium, 5.9,
			"The server negotiated "+tlsVersionName(state.Version)+", below TLS 1.2.",
			host,
		))
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if time.Now().After(cert.NotAfter) {
			findings = append(findings, tlsFinding(
				"Expired TLS certificate",
				finding.High, 7.4,
				"The certificate expired on "+cert.NotAfter.Format(time.RFC3339)+".",
				host,
			))
		}
	}

	return findings
}

func tlsFinding(title string, sev finding.Severity, cvss float64, desc, host string) finding.Finding {
	return finding.Finding{
		Title:       title,
		Module:      "misconfig",
		Severity:    sev,
		OWASP:       "A02:2025 - Cryptographic Failures",
		CWE:         "CWE-326",
		CVSS:        cvss,
		Description: desc,
		Evidence: finding.Evidence{
			Extracted: "host: " + host,
		},
		NextSteps: []string{
			"Serve a valid certificate from a trusted CA and renew before expiry.",
			"Disable TLS versions below 1.2 and prefer 1.3.",
		},
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func credsNote(withCreds bool) string {
	if withCreds {
		return " with credentials allowed"
	}

	return ""
}
