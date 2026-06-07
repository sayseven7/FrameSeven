package config

import (
	"testing"
	"time"
)

func TestNewDefaults(t *testing.T) {
	cfg := New("https://example.com")

	if cfg.Target != "https://example.com" {
		t.Errorf("target = %q", cfg.Target)
	}

	if cfg.Timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}

	if cfg.UserAgent != DefaultUserAgent {
		t.Errorf("user agent = %q, want %q", cfg.UserAgent, DefaultUserAgent)
	}

	if cfg.RateRequests != DefaultRateRequests {
		t.Errorf("rate requests = %d, want %d", cfg.RateRequests, DefaultRateRequests)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"http://example.com/admin/", "http://example.com/admin"},
		{"http://Example.COM/Path/", "http://example.com/Path"},
		{"HTTP://EXAMPLE.COM", "http://example.com"},
		{"https://example.com/path/to/page", "https://example.com/path/to/page"},
		{"http://example.com/path?a=1&b=2", "http://example.com/path?a=1&b=2"},
		{"", ""},
		{"not-a-url", "not-a-url"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := normalizeTarget(c.input)
			if got != c.want {
				t.Errorf("normalizeTarget(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid https", New("https://example.com"), false},
		{"valid http", New("http://example.com/path?a=1"), false},
		{"empty target", New(""), true},
		{"blank target", New("   "), true},
		{"missing scheme", New("example.com"), true},
		{"unsupported scheme", New("ftp://example.com"), true},
		{"no host", New("http://"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()

			if c.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}

			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateNumericFields(t *testing.T) {
	cfg := New("https://example.com")
	cfg.Timeout = 0

	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for non-positive timeout")
	}

	cfg = New("https://example.com")
	cfg.RateRequests = 0

	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for non-positive rate requests")
	}

	cfg = New("https://example.com")
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 10

	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
