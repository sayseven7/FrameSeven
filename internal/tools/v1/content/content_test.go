package content

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestRunReportsExistingContentPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			fmt.Fprint(w, "login page with application content")
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	findings := Run(&cfg, srv.Client())
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one finding", findings)
	}

	if findings[0].Module != "content" {
		t.Fatalf("module = %q, want content", findings[0].Module)
	}
}

func TestRunSkipsSoft404Responses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not found but always successful")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	findings := Run(&cfg, srv.Client())
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}
