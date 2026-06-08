package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
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

func TestRunListsTools(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"--list-tools"}, strings.NewReader(""), &stdout, &stderr, false, nil)

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	for _, name := range []string{
		"recon",
		"sqli",
		"access",
		"ssrf",
		"lfi",
		"misconfig",
		"ratelimit",
		"cve",
		"crawler",
		"content",
		"subdomain",
		"ports",
		"nmap",
		"sqlmap",
		"bannergrab",
	} {
		if !strings.Contains(stdout.String(), name) {
			t.Errorf("tool %q missing from output", name)
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
	outputDir := t.TempDir()

	input := strings.Join([]string{
		"https://example.com",
		"",
		"",
		"",
		outputDir,
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

	if !slices.Contains(config.UserAgents, received.UserAgent) {
		t.Errorf("user agent = %q, want a random agent from the pool", received.UserAgent)
	}

	if strings.Join(received.SelectedTools, ",") != "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve" {
		t.Errorf("selected tools = %v", received.SelectedTools)
	}

	assertReportFiles(t, outputDir)
}

func TestRunWizardAcceptsCustomValuesWithYesFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var received config.Config
	outputDir := t.TempDir()

	input := strings.Join([]string{
		"https://example.com",
		"25s",
		"12",
		"security-team/v1",
		outputDir,
		"2,5",
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

	if strings.Join(received.SelectedTools, ",") != "recon,sqli,lfi" {
		t.Errorf("selected modules = %v", received.SelectedTools)
	}

	if strings.Contains(stderr.String(), "scanning") {
		t.Errorf("quiet mode wrote progress: %q", stderr.String())
	}

	assertReportFiles(t, outputDir)
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

func TestRunAcceptsToolFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var received config.Config
	outputDir := t.TempDir()

	code := run(
		[]string{"-url", "https://example.com", "--out", outputDir, "--tools", "sqli,misconfig", "--quiet"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		false,
		func(cfg *config.Config) report.Report {
			received = *cfg

			return report.Report{}
		},
	)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	if strings.Join(received.SelectedTools, ",") != "recon,sqli,misconfig" {
		t.Errorf("selected tools = %v", received.SelectedTools)
	}
}

func TestRunAcceptsAllTools(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var received config.Config
	outputDir := t.TempDir()

	code := run(
		[]string{"-url", "https://example.com", "--out", outputDir, "--tools", "all", "--quiet"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		false,
		func(cfg *config.Config) report.Report {
			received = *cfg

			return report.Report{}
		},
	)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	want := "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve,crawler,content,subdomain,ports,nmap,sqlmap,bannergrab"
	if strings.Join(received.SelectedTools, ",") != want {
		t.Errorf("selected tools = %v", received.SelectedTools)
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

func TestRunWritesReportsAndVerboseLogs(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	outputDir := t.TempDir()

	code := run(
		[]string{"-url", "https://example.com", "--out", outputDir, "--verbose"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		false,
		func(cfg *config.Config) report.Report {
			cfg.Logger.Printf("DEBUG test debug message")

			return report.Report{
				SchemaVersion: "v1",
				Target:        cfg.Target,
				StartedAt:     time.Unix(0, 0).UTC(),
				Duration:      "1s",
			}
		},
	)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	assertReportFiles(t, outputDir)

	logData, err := os.ReadFile(filepath.Join(outputDir, "scan.log"))
	if err != nil {
		t.Fatalf("read scan log: %v", err)
	}

	if !strings.Contains(string(logData), "DEBUG test debug message") {
		t.Fatalf("scan log missing debug message:\n%s", logData)
	}
}

func assertReportFiles(t *testing.T, outputDir string) {
	t.Helper()

	for _, name := range []string{"report.html", "report.md", "report.json", "scan.log"} {
		info, err := os.Stat(filepath.Join(outputDir, name))
		if err != nil {
			t.Errorf("%s was not created: %v", name, err)
			continue
		}

		if name != "scan.log" && info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
