// Package ratelimit measures whether the target throttles repeated requests by
// firing a burst and observing status-code and latency variation.
package ratelimit

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
)

// Run sends cfg.RateRequests requests to the target and reports if no
// throttling is observed.
func Run(cfg *config.Config, client *http.Client) []finding.Finding {
	statuses := map[int]int{}
	var latencies []time.Duration
	throttled := false
	var firstDump string

	for i := 0; i < cfg.RateRequests; i++ {
		req, err := http.NewRequest(http.MethodGet, cfg.Target, nil)
		if err != nil {
			return nil
		}

		req.Header.Set("User-Agent", cfg.UserAgent)

		if firstDump == "" {
			dump, _ := httputil.DumpRequestOut(req, false)
			firstDump = string(dump)
		}

		start := time.Now()

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		latencies = append(latencies, time.Since(start))
		statuses[resp.StatusCode]++

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			throttled = true
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}

	if len(latencies) == 0 {
		return nil
	}

	if throttled {
		return nil
	}

	min, avg, max := stats(latencies)

	extracted := fmt.Sprintf(
		"requests: %d\nstatus distribution: %s\nlatency min/avg/max: %s / %s / %s\nno 429/503 observed",
		cfg.RateRequests, formatStatuses(statuses), min, avg, max,
	)

	return []finding.Finding{{
		Title:       "Missing rate limiting",
		Module:      "ratelimit",
		Severity:    finding.Medium,
		OWASP:       "A04:2025 - Insecure Design",
		CWE:         "CWE-770",
		CVSS:        5.3,
		Description: fmt.Sprintf("Sent %d requests with no throttling response, leaving the endpoint open to brute force and abuse.", cfg.RateRequests),
		Evidence: finding.Evidence{
			Request:   firstDump,
			Extracted: extracted,
		},
		NextSteps: []string{
			"Apply per-IP / per-account rate limiting and return 429 when exceeded.",
			"Add throttling and lockout on authentication and other costly endpoints.",
		},
	}}
}

func stats(latencies []time.Duration) (time.Duration, time.Duration, time.Duration) {
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	var total time.Duration
	for _, l := range latencies {
		total += l
	}

	avg := total / time.Duration(len(latencies))

	return latencies[0], avg, latencies[len(latencies)-1]
}

func formatStatuses(statuses map[int]int) string {
	codes := make([]int, 0, len(statuses))
	for code := range statuses {
		codes = append(codes, code)
	}

	sort.Ints(codes)

	var parts []string
	for _, code := range codes {
		parts = append(parts, fmt.Sprintf("%d=%d", code, statuses[code]))
	}

	return strings.Join(parts, " ")
}
