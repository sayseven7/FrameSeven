package misconfig

import (
	"net/http"
	"testing"
)

func TestMissingHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")

	missing := missingHeaders(h, true)

	got := map[string]bool{}
	for _, m := range missing {
		got[m] = true
	}

	if !got["Content-Security-Policy"] {
		t.Errorf("expected CSP reported missing")
	}

	if !got["Strict-Transport-Security"] {
		t.Errorf("expected HSTS reported missing on https")
	}

	if got["X-Frame-Options"] {
		t.Errorf("X-Frame-Options is present, should not be reported")
	}
}

func TestMissingHeadersHTTPSkipsHSTS(t *testing.T) {
	missing := missingHeaders(http.Header{}, false)

	for _, m := range missing {
		if m == "Strict-Transport-Security" {
			t.Fatalf("HSTS should not be expected over plain HTTP")
		}
	}
}

func TestCORSPermissive(t *testing.T) {
	reflected := http.Header{}
	reflected.Set("Access-Control-Allow-Origin", evilOrigin)
	reflected.Set("Access-Control-Allow-Credentials", "true")

	permissive, creds := corsPermissive(reflected, evilOrigin)
	if !permissive || !creds {
		t.Errorf("expected permissive with credentials, got %v/%v", permissive, creds)
	}

	strict := http.Header{}
	strict.Set("Access-Control-Allow-Origin", "https://trusted.example")

	if p, _ := corsPermissive(strict, evilOrigin); p {
		t.Errorf("expected strict origin not flagged")
	}

	wildcard := http.Header{}
	wildcard.Set("Access-Control-Allow-Origin", "*")

	if p, c := corsPermissive(wildcard, evilOrigin); !p || c {
		t.Errorf("expected wildcard permissive without creds, got %v/%v", p, c)
	}
}
