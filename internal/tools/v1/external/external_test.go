package external

import (
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/finding"
)

func TestBudgetClampsToBounds(t *testing.T) {
	if got := Budget(0); got != minTimeout {
		t.Errorf("Budget(0) = %s, want %s", got, minTimeout)
	}

	if got := Budget(time.Hour); got != maxTimeout {
		t.Errorf("Budget(1h) = %s, want %s", got, maxTimeout)
	}

	if got := Budget(10 * time.Second); got != 60*time.Second {
		t.Errorf("Budget(10s) = %s, want 60s", got)
	}
}

func TestExecuteTimesOut(t *testing.T) {
	// `sleep` is not guaranteed everywhere, but a missing binary still exercises
	// the never-panic contract: Execute must return an error, not crash.
	res, err := Execute(50*time.Millisecond, "definitely-not-a-real-binary-xyz")
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}

	if res.Stdout != "" {
		t.Errorf("expected empty stdout, got %q", res.Stdout)
	}
}

func TestFailedAlwaysReturnsInfoWithDetail(t *testing.T) {
	f := Failed("nmap", "the process exited with an error", "")
	if f.Severity != finding.Info {
		t.Errorf("severity = %q, want INFO", f.Severity)
	}

	if f.Evidence.Extracted == "" {
		t.Error("expected a placeholder detail, got empty evidence")
	}
}

func TestExecuteRejectsNonAllowlistedBinary(t *testing.T) {
	if _, err := Execute(time.Second, "rm", "-rf", "/"); err == nil {
		t.Fatal("expected non-allowlisted binary to be rejected")
	}
}

func TestSafeArg(t *testing.T) {
	valid := []string{
		"testaspnet.vulnweb.com",
		"http://testaspnet.vulnweb.com/page?id=1",
		"192.168.1.10",
	}
	for _, v := range valid {
		if err := SafeArg(v); err != nil {
			t.Errorf("SafeArg(%q) = %v, want nil", v, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"-oG",                // option flag injection
		"--script=evil",      // long option injection
		"host with space",    // splits into extra arguments
		"host\nwith-newline", // control character
		"host\x00null",       // null byte
	}
	for _, v := range invalid {
		if err := SafeArg(v); err == nil {
			t.Errorf("SafeArg(%q) = nil, want error", v)
		}
	}
}

func TestSnippetTruncates(t *testing.T) {
	got := snippet(strings.Repeat("x", 600), 500)
	if !strings.HasSuffix(got, "[…]") {
		t.Errorf("expected truncation marker, got suffix %q", got[len(got)-10:])
	}
}
