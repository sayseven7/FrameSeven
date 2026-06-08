package sqli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

// boolServer simulates a boolean-based SQL injection: a false condition wipes
// the result set, a true condition keeps the baseline page.
func boolServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		if strings.Contains(id, "1=2") || strings.Contains(id, "'1'='2") {
			fmt.Fprint(w, "no results found")
			return
		}

		fmt.Fprint(w, "results: itemA itemB itemC widget gadget sprocket")
	}))
}

func TestRunDetectsBooleanInjection(t *testing.T) {
	srv := boolServer()
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "id", Endpoint: srv.URL + "/item?id=2", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	var found bool
	for _, f := range findings {
		if f.CWE == "CWE-89" && strings.Contains(f.Title, "boolean-based") {
			found = true
		}
	}

	if !found {
		t.Errorf("expected boolean-based SQLi finding, got %+v", findings)
	}
}

func TestRunNoInjectionOnStableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "static page that ignores the id parameter entirely")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "id", Endpoint: srv.URL + "/item?id=2", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings on stable endpoint, got %+v", findings)
	}
}

func TestRunChecksCustomPayloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		if strings.Contains(id, "custom-sqli") {
			http.Error(w, "SQL syntax error near custom-sqli", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, "regular item page")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.CustomPayloads = []string{"' custom-sqli"}

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "id", Endpoint: srv.URL + "/item?id=2", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if strings.Contains(f.Title, "Custom SQL injection payload") {
			return
		}
	}

	t.Errorf("expected custom SQLi payload finding, got %+v", findings)
}
