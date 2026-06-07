package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestNewClient(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.Timeout = 7 * time.Second

	client := newClient(&cfg)

	if client.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is not *http.Transport")
	}

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be enabled for scanning")
	}
}

func TestScanProducesReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html><body>home</body></html>"))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 3

	rep := Scan(&cfg)

	if rep.Target != srv.URL {
		t.Errorf("target = %q, want %q", rep.Target, srv.URL)
	}

	if rep.Surface.Host == "" {
		t.Errorf("expected surface host to be set")
	}

	if rep.StartedAt.IsZero() {
		t.Errorf("expected started time to be set")
	}

	// A server with no throttling should at least yield the rate-limit finding.
	var hasRateLimit bool
	for _, f := range rep.Findings {
		if f.Module == "ratelimit" {
			hasRateLimit = true
		}
	}

	if !hasRateLimit {
		t.Errorf("expected a rate-limit finding, got %+v", rep.Findings)
	}
}
