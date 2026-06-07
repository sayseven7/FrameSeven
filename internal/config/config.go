package config

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// Config holds every option that drives a scan. It is built once from the CLI
// and passed (read-only) to each module.
type Config struct {
	Target    string
	Timeout   time.Duration
	UserAgent string

	// RateRequests is how many requests the rate-limit module sends.
	RateRequests int

	// NVDAPIKey is optional. When set it is sent to the NVD API to raise the
	// request rate limit.
	NVDAPIKey string
}

const (
	DefaultTimeout      = 10 * time.Second
	DefaultUserAgent    = "frameseven/v1"
	DefaultRateRequests = 50
)

// New returns a Config with defaults applied for the given target.
func New(target string) Config {
	return Config{
		Target:       target,
		Timeout:      DefaultTimeout,
		UserAgent:    DefaultUserAgent,
		RateRequests: DefaultRateRequests,
	}
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
