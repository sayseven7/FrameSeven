package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestStats(t *testing.T) {
	latencies := []time.Duration{
		30 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
	}

	min, avg, max := stats(latencies)

	if min != 10*time.Millisecond {
		t.Errorf("min = %v, want 10ms", min)
	}

	if max != 30*time.Millisecond {
		t.Errorf("max = %v, want 30ms", max)
	}

	if avg != 20*time.Millisecond {
		t.Errorf("avg = %v, want 20ms", avg)
	}
}

func TestFormatStatuses(t *testing.T) {
	got := formatStatuses(map[int]int{200: 3, 404: 1})

	if got != "200=3 404=1" {
		t.Errorf("formatStatuses = %q, want \"200=3 404=1\"", got)
	}
}

func TestRunReportsMissingRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 5

	findings := Run(&cfg, srv.Client())

	if len(findings) != 1 || findings[0].CWE != "CWE-770" {
		t.Fatalf("expected one missing-rate-limit finding, got %+v", findings)
	}
}

func TestRunSilentWhenThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 5

	if findings := Run(&cfg, srv.Client()); len(findings) != 0 {
		t.Errorf("expected no finding when throttled, got %+v", findings)
	}
}
