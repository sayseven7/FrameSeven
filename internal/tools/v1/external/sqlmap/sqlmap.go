// Package sqlmap runs sqlmap for Framework v1 and maps its result into a
// finding. Execution is fail-safe: a missing binary, a failed run, or output
// that cannot be interpreted is reported as an informational finding instead of
// blocking the scan.
package sqlmap

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/external"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const binary = "sqlmap"

// Run executes sqlmap against the configured target URL and returns a finding
// describing any confirmed SQL injection. Any failure degrades to an
// informational finding so the remainder of the scan is never blocked.
func Run(cfg *config.Config, _ *http.Client, _ *recon.Surface) []finding.Finding {
	if cfg == nil || strings.TrimSpace(cfg.Target) == "" {
		return []finding.Finding{external.Unavailable(binary, "no target URL was configured")}
	}

	if _, err := exec.LookPath(binary); err != nil {
		return []finding.Finding{external.NotFound(binary)}
	}

	timeout := external.Budget(cfg.Timeout)
	res, err := external.Execute(
		timeout, binary,
		"-u", cfg.Target,
		"--batch",
		"--disable-coloring",
		"--flush-session",
		"--level=1",
		"--risk=1",
	)

	// sqlmap returns a non-zero exit in some benign cases; trust the parsed
	// output first and only fall back to a failure finding when there is
	// nothing usable to read.
	injection := parseInjection(res.Stdout)
	if injection != "" {
		return []finding.Finding{vulnerable(cfg.Target, injection)}
	}

	if err != nil && strings.TrimSpace(res.Stdout) == "" {
		reason := "the sqlmap process exited with an error"
		if res.TimedOut {
			reason = fmt.Sprintf("the sqlmap process exceeded the %s budget", timeout)
		}

		return []finding.Finding{external.Failed(binary, reason, firstNonEmpty(res.Stderr, res.Stdout))}
	}

	return []finding.Finding{notInjectable(cfg.Target)}
}

// parseInjection extracts the injection-point block from sqlmap's stdout. It
// returns an empty string when sqlmap did not confirm an injection.
func parseInjection(out string) string {
	if !strings.Contains(out, "identified the following injection point") {
		return ""
	}

	var block []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Parameter:"),
			strings.HasPrefix(trimmed, "Type:"),
			strings.HasPrefix(trimmed, "Title:"),
			strings.HasPrefix(trimmed, "Payload:"):
			block = append(block, trimmed)
		}
	}

	return strings.Join(block, "\n")
}

func vulnerable(target, injection string) finding.Finding {
	return finding.Finding{
		Title:       "SQL injection confirmed by sqlmap",
		Module:      binary,
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "sqlmap confirmed at least one injectable parameter on " + target + ", proving the application builds SQL queries from unsanitized input.",
		Evidence: finding.Evidence{
			Request:   target,
			Extracted: injection,
		},
		NextSteps: []string{
			"Use parameterized queries / prepared statements for the affected parameters.",
			"Validate and allowlist input types before they reach the database.",
		},
	}
}

func notInjectable(target string) finding.Finding {
	return finding.Finding{
		Title:       "sqlmap found no injectable parameters",
		Module:      binary,
		Severity:    finding.Info,
		OWASP:       "A03:2025 - Injection",
		Description: "sqlmap ran against " + target + " and did not confirm a SQL injection at the configured level/risk.",
		Evidence: finding.Evidence{
			Extracted: "no injection confirmed",
		},
		NextSteps: []string{
			"Increase --level/--risk or supply authenticated session data for deeper testing.",
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}

	return ""
}
