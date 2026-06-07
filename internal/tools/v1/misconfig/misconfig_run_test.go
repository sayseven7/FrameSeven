package misconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestRunFlagsMisconfigurations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect any Origin with credentials and set no security headers.
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Accept every method (including PUT/DELETE/TRACE) with 200.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	findings := Run(&cfg, srv.Client(), nil)

	cwes := map[string]bool{}
	for _, f := range findings {
		cwes[f.CWE] = true
	}

	if !cwes["CWE-693"] {
		t.Errorf("expected missing security headers finding (CWE-693)")
	}

	if !cwes["CWE-650"] {
		t.Errorf("expected dangerous HTTP methods finding (CWE-650)")
	}

	if !cwes["CWE-942"] {
		t.Errorf("expected permissive CORS finding (CWE-942)")
	}
}
