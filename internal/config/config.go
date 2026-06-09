// Package config defines the scan configuration and provides a factory that
// applies project-level defaults for timeout, user agent, and rate limits.
package config

import (
	"crypto/rand"
	"errors"
	"io"
	"log"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Config holds every option that drives a scan. It is built once from the CLI
// and passed (read-only) to each tool.
type Config struct {
	Target    string
	Timeout   time.Duration
	UserAgent string

	// ToolTimeout is the maximum time one scanner tool may run before the
	// scanner records a tool error and continues.
	ToolTimeout time.Duration

	// ToolConcurrency limits how many independent scanner tools run at once
	// after recon has populated the shared surface.
	ToolConcurrency int

	// RateRequests is how many requests the rate-limit tool sends.
	RateRequests int

	// NVDAPIKey is optional. When set it is sent to the NVD API to raise the
	// request rate limit.
	NVDAPIKey string

	// SelectedTools limits the scanner to the named framework tools. Empty
	// means every tool is enabled.
	SelectedTools []string

	// CustomPayloads are optional caller-supplied probe values. Tools that
	// support dynamic input decide how to apply them.
	CustomPayloads []string

	// AuthCookies holds session cookies captured from a browser login.
	// Format: ["name=value", "name=value"]. When non-empty, every tool
	// injects these into the Cookie header of each request.
	AuthCookies []string

	// AuthHeaders holds extra headers captured from a browser login session,
	// for example Authorization. When non-empty, every tool injects these
	// into each request.
	AuthHeaders map[string]string

	// SeedEndpoints holds same-host API URLs captured from a browser session.
	// recon merges them into the surface so scan tools test the real
	// application routes that a static crawl of an SPA would miss.
	SeedEndpoints []string

	// Logger receives scan progress and diagnostic messages.
	Logger *log.Logger

	// Verbose enables request-level diagnostic messages.
	Verbose bool
}

// Project-level defaults. New applies these when the caller does not supply
// an explicit value.
const (
	DefaultTimeout         = 10 * time.Second
	DefaultToolTimeout     = 120 * time.Second
	DefaultToolConcurrency = 10
	DefaultUserAgent       = "frameseven/v1"
	DefaultRateRequests    = 50
	MaxCustomPayloads      = 25
	MaxCustomPayloadLen    = 300
)

// UserAgents is a pool of realistic browser User-Agent strings. The CLI picks
// one at random when no explicit agent is supplied, so probes blend in with
// ordinary traffic. The honest DefaultUserAgent is included so the project can
// still identify itself when selected.
var UserAgents = []string{
	DefaultUserAgent,
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}

// RandomUserAgent returns a randomly selected agent from UserAgents. It uses
// crypto/rand so the choice is not a predictable PRNG sequence, and falls back
// to DefaultUserAgent if the pool is empty or the entropy source fails.
func RandomUserAgent() string {
	if len(UserAgents) == 0 {
		return DefaultUserAgent
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(UserAgents))))
	if err != nil {
		return DefaultUserAgent
	}

	return UserAgents[n.Int64()]
}

// New returns a Config with defaults applied for the given target.
// The target URL is normalized: scheme and host are lowercased, and any
// trailing slash is removed from the path.
func New(target string) Config {
	target = normalizeTarget(target)

	return Config{
		Target:          target,
		Timeout:         DefaultTimeout,
		ToolTimeout:     DefaultToolTimeout,
		ToolConcurrency: DefaultToolConcurrency,
		UserAgent:       DefaultUserAgent,
		RateRequests:    DefaultRateRequests,
		Logger:          log.New(io.Discard, "", log.Ltime),
	}
}

func normalizeTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}

	if u.Scheme != "" {
		u.Scheme = strings.ToLower(u.Scheme)
	}

	u.Host = strings.ToLower(u.Host)

	path := strings.TrimRight(u.Path, "/")
	if path != u.Path {
		u.Path = path
	}

	normalized := u.String()
	if normalized != target {
		return normalized
	}

	return target
}

// Validate checks that the target is a usable absolute HTTP(S) URL and that
// numeric options are sane.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Target) == "" {
		return errors.New("target URL is required")
	}

	u, err := url.Parse(c.Target)
	if err != nil {
		return err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("target URL must use http or https")
	}

	if u.Host == "" {
		return errors.New("target URL must include a host")
	}

	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	if c.ToolTimeout <= 0 {
		return errors.New("tool timeout must be positive")
	}

	if c.ToolConcurrency <= 0 {
		return errors.New("tool concurrency must be positive")
	}

	if c.RateRequests <= 0 {
		return errors.New("rate request count must be positive")
	}

	return nil
}

// NormalizedCustomPayloads returns a bounded, deduplicated custom payload list.
func (c Config) NormalizedCustomPayloads() []string {
	seen := map[string]bool{}
	var payloads []string

	for _, raw := range c.CustomPayloads {
		payload := strings.TrimSpace(raw)
		if payload == "" {
			continue
		}

		if len(payload) > MaxCustomPayloadLen {
			payload = payload[:MaxCustomPayloadLen]
		}

		if seen[payload] {
			continue
		}

		seen[payload] = true
		payloads = append(payloads, payload)

		if len(payloads) == MaxCustomPayloads {
			break
		}
	}

	return payloads
}
