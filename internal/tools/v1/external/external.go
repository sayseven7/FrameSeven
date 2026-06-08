// Package external runs external security binaries (such as Nmap and sqlmap)
// for Framework v1 in a fail-safe way: a missing binary, a non-zero exit, a
// timeout, or unparseable output is always turned into a finding instead of an
// error that could block the rest of the scan. Callers therefore always receive
// at least one finding back.
package external

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
)

// Process timeout bounds. The per-request HTTP timeout is far too small for
// external scanners, so Budget scales it up but keeps it bounded so a hung
// binary can never stall a scan indefinitely.
const (
	minTimeout = 30 * time.Second
	maxTimeout = 3 * time.Minute
)

// Budget derives a bounded process timeout from the configured per-request
// timeout. A non-positive input falls back to the minimum.
func Budget(perRequest time.Duration) time.Duration {
	scaled := perRequest * 6
	switch {
	case scaled < minTimeout:
		return minTimeout
	case scaled > maxTimeout:
		return maxTimeout
	default:
		return scaled
	}
}

// Result is the captured outcome of an external command.
type Result struct {
	Stdout   string
	Stderr   string
	TimedOut bool
}

// Execute runs one of the allowlisted external binaries with args under a
// timeout. The binary name must be a member of the allowlist; any other value
// is rejected before a process is started, so this runner can never launch an
// arbitrary executable. It never panics: every failure mode (binary missing,
// non-zero exit, timeout) is returned as an error while still handing back
// whatever output was captured so callers can degrade gracefully.
func Execute(timeout time.Duration, bin string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd, err := command(ctx, bin, args)
	if err != nil {
		return Result{}, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	res := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		TimedOut: ctx.Err() == context.DeadlineExceeded,
	}

	if res.TimedOut {
		return res, errors.New("external tool timed out")
	}

	return res, runErr
}

// command builds an *exec.Cmd for one of the explicitly allowlisted external
// binaries. Each branch passes a constant binary name, so it is impossible to
// launch an executable that is not named here regardless of what a caller
// supplies. Unknown names are rejected with an error.
func command(ctx context.Context, bin string, args []string) (*exec.Cmd, error) {
	switch bin {
	case "nmap":
		// #nosec G204 - constant binary; the only caller-derived argument (the target) is validated by SafeArg against flag/control-char injection.
		return exec.CommandContext(ctx, "nmap", args...), nil
	case "sqlmap":
		// #nosec G204 - constant binary; the only caller-derived argument (the target) is validated by SafeArg against flag/control-char injection.
		return exec.CommandContext(ctx, "sqlmap", args...), nil
	default:
		return nil, fmt.Errorf("external: %q is not an allowlisted binary", bin)
	}
}

// SafeArg validates a caller-derived value (a target host or URL) before it is
// passed to an external binary. It blocks argument injection: a value that is
// empty, looks like an option flag, or contains whitespace or control
// characters could be reinterpreted by the tool as a flag or a second argument.
func SafeArg(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value is empty")
	}

	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("value %q must not start with '-'", value)
	}

	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return fmt.Errorf("value %q contains an illegal character", value)
		}
	}

	return nil
}

// NotFound is the standard info finding for a binary that is not installed or
// not on PATH. The scan continues; the operator simply learns the tool is
// unavailable.
func NotFound(name string) finding.Finding {
	return finding.Finding{
		Title:       name + " binary not found",
		Module:      name,
		Severity:    finding.Info,
		Description: name + " is not installed or is not available in PATH, so this module was skipped without affecting the rest of the scan.",
		Evidence: finding.Evidence{
			Extracted: "binary not found in PATH",
		},
		NextSteps: []string{
			"Install the external tool to enable execution support.",
			"Keep this tool selected only when external tooling is needed.",
		},
	}
}

// Unavailable is the info finding returned when the module cannot run even
// though the binary may exist (for example, no target was configured).
func Unavailable(name, reason string) finding.Finding {
	return finding.Finding{
		Title:       name + " execution skipped",
		Module:      name,
		Severity:    finding.Info,
		Description: name + " could not be executed: " + reason + ". The scan continued without it.",
		Evidence: finding.Evidence{
			Extracted: reason,
		},
		NextSteps: []string{
			"Provide a valid target before enabling this module.",
		},
	}
}

// Failed is the info finding returned when the binary ran but failed (non-zero
// exit, timeout, or output that could not be parsed). It always carries a short
// detail snippet so the operator can see what happened, and never blocks the
// remaining tools.
func Failed(name, reason, detail string) finding.Finding {
	detail = snippet(detail, 500)

	desc := name + " ran but did not complete successfully: " + reason + ". The scan continued and other tools were unaffected."

	return finding.Finding{
		Title:       name + " execution failed",
		Module:      name,
		Severity:    finding.Info,
		Description: desc,
		Evidence: finding.Evidence{
			Extracted: detail,
		},
		NextSteps: []string{
			"Re-run the external tool manually to inspect the full output.",
			"Confirm the target is reachable and the tool arguments are valid.",
		},
	}
}

// snippet trims s to at most max characters, collapsing trailing whitespace and
// appending an ellipsis when truncated. Empty input yields a stable placeholder.
func snippet(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output captured"
	}

	if len(s) <= max {
		return s
	}

	return strings.TrimSpace(s[:max]) + " […]"
}
