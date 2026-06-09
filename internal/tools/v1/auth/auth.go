// Package auth implements browser-based authentication capture. It opens a
// visible browser, lets the user log in and browse the app manually, and
// collects the session cookies, auth headers, and the API endpoints the app
// calls so later scan requests run authenticated against the real surface.
package auth

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// SessionResult holds the authentication material captured from a manual
// browser login session.
type SessionResult struct {
	// Cookies are session cookies for the target domain, formatted as
	// "name=value" pairs.
	Cookies []string

	// Headers are auth headers observed during the session, for example
	// Authorization.
	Headers map[string]string

	// Endpoints are same-host API URLs the app called during the session.
	// They seed the recon surface so scan tools test the real application
	// routes (an SPA loads these via JavaScript, so a static crawl misses them).
	Endpoints []string
}

// authHeaderNames lists the request headers treated as authentication material.
// Token-based apps (single-page apps reading a token from localStorage) send it
// under one of these names, so observing them on the wire lets the scan replay
// the same authentication.
var authHeaderNames = []string{
	"Authorization",
	"Authentication",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Api-Key",
	"X-Csrf-Token",
}

// maxCapturedEndpoints bounds how many session endpoints are recorded.
const maxCapturedEndpoints = 300

// staticAssetExts are file extensions for static resources that are not worth
// seeding into the scan surface.
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".avi": true,
}

// Capture opens a visible browser at target, waits for the user to log in and
// browse the app, then returns the session cookies for the target domain, any
// auth headers, and the same-host endpoints observed. When no cookies match the
// target domain it returns an empty cookie list, not an error.
func Capture(target string) (SessionResult, error) {
	host, err := targetHost(target)
	if err != nil {
		return SessionResult{}, err
	}

	controlURL, err := launcher.New().Headless(false).Launch()
	if err != nil {
		return SessionResult{}, err
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return SessionResult{}, err
	}
	defer browser.Close()

	page, err := browser.Page(proto.TargetCreateTarget{URL: target})
	if err != nil {
		return SessionResult{}, err
	}

	recorder := newSessionRecorder()
	go observeSession(page, host, recorder)

	fmt.Println("Browser opened. Please log in, browse the app (open your basket, orders, profile), and press Enter when ready...")
	waitForEnter(os.Stdin)

	cookies, err := browser.GetCookies()
	if err != nil {
		return SessionResult{}, err
	}

	result := buildSession(cookies, host, recorder.snapshotHeaders())
	result.Endpoints = recorder.endpointList()

	return result, nil
}

// observeSession passively records auth headers and same-host endpoints seen on
// outgoing requests. It runs until the browser is closed and never interferes
// with the page load.
func observeSession(page *rod.Page, host string, rec *sessionRecorder) {
	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return
	}

	page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if e.Request == nil {
			return
		}

		for key, value := range e.Request.Headers {
			if canonical, ok := canonicalAuthHeader(key); ok {
				rec.recordHeader(canonical, value.Str())
			}
		}

		rec.recordEndpoint(host, e.Request.URL)
	})()
}

// canonicalAuthHeader reports whether a request header name is an auth header,
// matched case-insensitively, and returns its canonical name.
func canonicalAuthHeader(name string) (string, bool) {
	for _, candidate := range authHeaderNames {
		if strings.EqualFold(name, candidate) {
			return candidate, true
		}
	}

	return "", false
}

// buildSession turns captured browser cookies and observed headers into a
// SessionResult, keeping only cookies that belong to the target domain.
func buildSession(cookies []*proto.NetworkCookie, host string, headers map[string]string) SessionResult {
	if headers == nil {
		headers = map[string]string{}
	}

	result := SessionResult{Headers: headers}

	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}

		if !domainMatches(host, cookie.Domain) {
			continue
		}

		result.Cookies = append(result.Cookies, formatCookie(cookie.Name, cookie.Value))
	}

	return result
}

// formatCookie renders a cookie as a "name=value" pair for the Cookie header.
func formatCookie(name, value string) string {
	return name + "=" + value
}

// domainMatches reports whether a cookie domain applies to the target host. It
// accepts an exact match and a parent domain (with or without a leading dot).
func domainMatches(host, cookieDomain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cookieDomain)), ".")

	if host == "" || domain == "" {
		return false
	}

	return host == domain || strings.HasSuffix(host, "."+domain)
}

// isStaticAsset reports whether a path points at a static resource by extension.
func isStaticAsset(p string) bool {
	return staticAssetExts[strings.ToLower(path.Ext(p))]
}

func targetHost(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}

	if u.Hostname() == "" {
		return "", fmt.Errorf("target %q has no host", target)
	}

	return u.Hostname(), nil
}

func waitForEnter(input io.Reader) {
	reader := bufio.NewReader(input)
	_, _ = reader.ReadString('\n')
}

type sessionRecorder struct {
	mu        sync.Mutex
	headers   map[string]string
	endpoints []string
	seen      map[string]bool
}

func newSessionRecorder() *sessionRecorder {
	return &sessionRecorder{
		headers: map[string]string{},
		seen:    map[string]bool{},
	}
}

func (r *sessionRecorder) recordHeader(name, value string) {
	if value == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.headers[name] = value
}

func (r *sessionRecorder) recordEndpoint(host, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}

	if !strings.EqualFold(u.Hostname(), host) || isStaticAsset(u.Path) {
		return
	}

	u.Fragment = ""
	endpoint := u.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.seen[endpoint] || len(r.endpoints) >= maxCapturedEndpoints {
		return
	}

	r.seen[endpoint] = true
	r.endpoints = append(r.endpoints, endpoint)
}

func (r *sessionRecorder) snapshotHeaders() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]string, len(r.headers))
	for name, value := range r.headers {
		out[name] = value
	}

	return out
}

func (r *sessionRecorder) endpointList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, len(r.endpoints))
	copy(out, r.endpoints)

	return out
}
