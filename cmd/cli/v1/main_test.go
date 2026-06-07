package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/report"
)

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	if !strings.Contains(stdout.String(), "CLI v1") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	if !strings.Contains(stderr.String(), "Usage: frameseven") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunListsModules(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--list-modules"}, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	for _, name := range []string{"recon", "sqli", "access", "ssrf", "lfi", "misconfig", "ratelimit", "cve"} {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("module %q missing from output", name)
		}
	}
}

func TestRunRejectsInteractiveModeWithoutTerminal(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--interactive"}, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}

	if !strings.Contains(stderr.String(), "requires a terminal") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunWizardUsesDefaults(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var received config.Config

	input := strings.Join([]string{
		"https://example.com",
		"",
		"",
		"",
		"",
		"yes",
		"",
	}, "\n")

	code := run([]string{"--interactive"}, strings.NewReader(input), &stdout, &stderr, true, func(cfg *config.Config) report.Report {
		received = *cfg

		return report.Report{}
	})

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	if received.Target != "https://example.com" {
		t.Errorf("target = %q", received.Target)
	}

	if received.Timeout != config.DefaultTimeout {
		t.Errorf("timeout = %v", received.Timeout)
	}

	if received.RateRequests != config.DefaultRateRequests {
		t.Errorf("rate = %d", received.RateRequests)
	}

	if received.UserAgent != config.DefaultUserAgent {
		t.Errorf("user agent = %q", received.UserAgent)
	}
}

func TestRunWizardAcceptsCustomValuesWithYesFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var received config.Config

	input := strings.Join([]string{
		"https://example.com",
		"25s",
		"12",
		"security-team/v1",
		"",
	}, "\n")

	code := run([]string{"--interactive", "--yes", "--quiet"}, strings.NewReader(input), &stdout, &stderr, true, func(cfg *config.Config) report.Report {
		received = *cfg

		return report.Report{}
	})

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	if received.Timeout != 25*time.Second {
		t.Errorf("timeout = %v", received.Timeout)
	}

	if received.RateRequests != 12 {
		t.Errorf("rate = %d", received.RateRequests)
	}

	if received.UserAgent != "security-team/v1" {
		t.Errorf("user agent = %q", received.UserAgent)
	}

	if strings.Contains(stderr.String(), "scanning") {
		t.Errorf("quiet mode wrote progress: %q", stderr.String())
	}
}

func TestRunWizardCancellationDoesNotScan(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false

	input := strings.Join([]string{
		"https://example.com",
		"",
		"",
		"",
		"",
		"no",
		"",
	}, "\n")

	code := run([]string{"--interactive"}, strings.NewReader(input), &stdout, &stderr, true, func(cfg *config.Config) report.Report {
		called = true

		return report.Report{}
	})

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	if called {
		t.Fatal("scan was called after cancellation")
	}
}

func TestRunRequiresURLWithoutTerminal(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(nil, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}

	if !strings.Contains(stderr.String(), "target URL is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
