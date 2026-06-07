package access

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestComparableSize(t *testing.T) {
	if !comparableSize("aaaa", "aaab") {
		t.Errorf("equal-length bodies should be comparable")
	}

	if comparableSize("a", "") {
		t.Errorf("empty body should not be comparable")
	}

	if comparableSize("aaaa", "aaaaaaaaaaaa") {
		t.Errorf("3x size difference should not be comparable")
	}
}

func TestRunUnauthAndIDOR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			fmt.Fprint(w, "admin panel - control center")
		case "/item":
			id := r.URL.Query().Get("id")
			fmt.Fprintf(w, "profile of user number %s with private data here", id)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "id", Endpoint: srv.URL + "/item?id=2", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), surface)

	var unauth, idor bool
	for _, f := range findings {
		if f.Title == "Sensitive endpoint reachable without authentication: /admin" {
			unauth = true
		}

		if f.CWE == "CWE-639" {
			idor = true
		}
	}

	if !unauth {
		t.Errorf("expected unauthenticated /admin finding, got %+v", findings)
	}

	if !idor {
		t.Errorf("expected IDOR finding, got %+v", findings)
	}
}

func TestRunReportsProtectedAdminCandidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	findings := Run(&cfg, srv.Client(), recon.Surface{})

	for _, f := range findings {
		if f.Title == "Administrative interface candidate discovered: /admin" {
			return
		}
	}

	t.Errorf("expected protected admin candidate finding, got %+v", findings)
}

func TestRunNoIDORForNonNumeric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "name", Endpoint: srv.URL + "/item?name=alice", Method: http.MethodGet},
		},
	}

	for _, f := range Run(&cfg, srv.Client(), surface) {
		if f.CWE == "CWE-639" {
			t.Errorf("did not expect IDOR finding for non-numeric parameter")
		}
	}
}
