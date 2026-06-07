package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

func TestRunDiscoversNewEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			fmt.Fprint(w, `<a href="/new-endpoint">link</a>`)
			return
		}

		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Endpoints: []string{srv.URL + "/page"},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	if len(findings) == 0 {
		t.Fatal("expected crawler to discover at least one endpoint")
	}

	if findings[0].Module != "crawler" {
		t.Errorf("tool = %q, want crawler", findings[0].Module)
	}
}

func TestRunNoDiscoveryReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>no links here</body></html>")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	findings := Run(&cfg, srv.Client(), &recon.Surface{})

	if findings != nil {
		t.Errorf("expected nil, got %+v", findings)
	}
}
