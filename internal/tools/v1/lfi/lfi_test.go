package lfi

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

func TestParamHint(t *testing.T) {
	for _, name := range []string{"file", "path", "template", "include", "download"} {
		if !paramHint.MatchString(name) {
			t.Errorf("expected %q to be treated as file-like", name)
		}
	}

	if paramHint.MatchString("quantity") {
		t.Errorf("did not expect %q to be file-like", "quantity")
	}
}

func TestRunDetectsPasswd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")

		if strings.Contains(file, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}

		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "file", Endpoint: srv.URL + "/read?file=home.html", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	var found bool
	for _, f := range findings {
		if f.CWE == "CWE-22" {
			found = true
		}
	}

	if !found {
		t.Errorf("expected LFI finding, got %+v", findings)
	}
}

func TestRunNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "regular page content with no file contents")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "file", Endpoint: srv.URL + "/read?file=home.html", Method: http.MethodGet},
		},
	}

	if findings := Run(&cfg, srv.Client(), &surface); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestRunChecksCustomPayloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")

		if file == "custom-passwd" {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}

		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.CustomPayloads = []string{"custom-passwd"}

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "file", Endpoint: srv.URL + "/read?file=home.html", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if strings.Contains(f.Evidence.Extracted, "custom-passwd") {
			return
		}
	}

	t.Errorf("expected custom LFI payload finding, got %+v", findings)
}
