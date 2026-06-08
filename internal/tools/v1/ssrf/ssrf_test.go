package ssrf

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
	for _, name := range []string{"url", "redirectUri", "next", "callback", "image"} {
		if !paramHint.MatchString(name) {
			t.Errorf("expected %q to be treated as URL-like", name)
		}
	}

	if paramHint.MatchString("quantity") {
		t.Errorf("did not expect %q to be URL-like", "quantity")
	}
}

func TestRunDetectsAWSMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")

		if strings.Contains(target, "169.254.169.254") {
			fmt.Fprint(w, "instance-id: i-0abc\nami-id: ami-123\n")
			return
		}

		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "url", Endpoint: srv.URL + "/fetch?url=http://test", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	var found bool
	for _, f := range findings {
		if f.CWE == "CWE-918" && strings.Contains(f.Title, "AWS metadata") {
			found = true
		}
	}

	if !found {
		t.Errorf("expected AWS metadata SSRF finding, got %+v", findings)
	}
}

func TestRunSkipsNonURLParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "instance-id ami-id")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "quantity", Endpoint: srv.URL + "/cart?quantity=1", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	var hasInfo bool
	for _, f := range findings {
		if f.Title == "No URL-like parameters discovered for SSRF testing" {
			hasInfo = true
		}
	}

	if !hasInfo {
		t.Errorf("expected info finding, got %+v", findings)
	}

	for _, f := range findings {
		if f.CWE == "CWE-918" {
			t.Errorf("did not expect SSRF finding for non-URL parameter, got %+v", f)
		}
	}
}

func TestRunChecksCustomPayloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")

		if target == "http://custom-metadata.local/latest" {
			fmt.Fprint(w, "instance-id: i-custom\n")
			return
		}

		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.CustomPayloads = []string{"http://custom-metadata.local/latest"}

	surface := recon.Surface{
		Params: []recon.Param{
			{Name: "url", Endpoint: srv.URL + "/fetch?url=http://test", Method: http.MethodGet},
		},
	}

	findings := Run(&cfg, srv.Client(), &surface)

	for _, f := range findings {
		if strings.Contains(f.Evidence.Extracted, "http://custom-metadata.local/latest") {
			return
		}
	}

	t.Errorf("expected custom SSRF payload finding, got %+v", findings)
}
