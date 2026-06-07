// Package config defines the scan configuration and provides a factory that
// applies project-level defaults for timeout, user agent, and rate limits.
package config

import (
	"errors"
	"io"
	"log"
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

	// RateRequests is how many requests the rate-limit tool sends.
	RateRequests int

	// NVDAPIKey is optional. When set it is sent to the NVD API to raise the
	// request rate limit.
	NVDAPIKey string

	// SelectedTools limits the scanner to the named framework tools. Empty
	// means every tool is enabled.
	SelectedTools []string

	// Logger receives scan progress and diagnostic messages.
	Logger *log.Logger

	// Verbose enables request-level diagnostic messages.
	Verbose bool
}

// Project-level defaults. New applies these when the caller does not supply
// an explicit value.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultUserAgent    = "frameseven/v1"
	DefaultRateRequests = 50
)

// New returns a Config with defaults applied for the given target.
// The target URL is normalized: scheme and host are lowercased, and any
// trailing slash is removed from the path.
func New(target string) Config {
	target = normalizeTarget(target)

	return Config{
		Target:       target,
		Timeout:      DefaultTimeout,
		UserAgent:    DefaultUserAgent,
		RateRequests: DefaultRateRequests,
		Logger:       log.New(io.Discard, "", log.Ltime),
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

	if c.RateRequests <= 0 {
		return errors.New("rate request count must be positive")
	}

	return nil
}
