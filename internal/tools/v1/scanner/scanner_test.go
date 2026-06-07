package scanner

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestNewClient(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.Timeout = 7 * time.Second
	recorder := &requestErrorRecorder{}

	client := newClient(&cfg, recorder)

	if client.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", client.Timeout)
	}

	recording, ok := client.Transport.(*recordingTransport)
	if !ok {
		t.Fatalf("transport is not *recordingTransport")
	}

	transport, ok := recording.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport is not *http.Transport")
	}

	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected InsecureSkipVerify to be enabled for scanning")
	}
}

func TestClientBlocksCrossOriginRedirect(t *testing.T) {
	cfg := config.New("https://example.com")
	recorder := &requestErrorRecorder{}
	client := newClient(&cfg, recorder)

	source, err := http.NewRequest(http.MethodGet, "https://example.com/start", nil)
	if err != nil {
		t.Fatalf("build source request: %v", err)
	}

	destination, err := http.NewRequest(http.MethodGet, "https://other.example/end", nil)
	if err != nil {
		t.Fatalf("build destination request: %v", err)
	}

	if err := client.CheckRedirect(destination, []*http.Request{source}); err == nil {
		t.Fatal("expected cross-origin redirect to fail")
	}

	errors := recorder.Take("test")
	if len(errors) == 0 {
		t.Fatal("expected redirect error to be recorded")
	}
}

func TestScanProducesReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("<html><body>home</body></html>"))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.RateRequests = 3
	var logs bytes.Buffer
	cfg.Logger = log.New(&logs, "", 0)
	cfg.Verbose = true

	rep := Scan(&cfg)

	if rep.Target != srv.URL {
		t.Errorf("target = %q, want %q", rep.Target, srv.URL)
	}

	if rep.Surface.Host == "" {
		t.Errorf("expected surface host to be set")
	}

	if rep.StartedAt.IsZero() {
		t.Errorf("expected started time to be set")
	}

	// A server with no throttling should at least yield the rate-limit finding.
	var hasRateLimit bool
	for _, f := range rep.Findings {
		if f.Module == "ratelimit" {
			hasRateLimit = true
		}
	}

	if !hasRateLimit {
		t.Errorf("expected a rate-limit finding, got %+v", rep.Findings)
	}

	for _, want := range []string{"[recon] started", "[cve] completed", "HTTP request", "scan completed"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("scan log missing %q:\n%s", want, logs.String())
		}
	}
}

func TestScanRunsOnlySelectedModules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.SelectedModules = []string{"recon", "misconfig"}

	var logs bytes.Buffer
	cfg.Logger = log.New(&logs, "", 0)

	rep := Scan(&cfg)

	if rep.Surface.Host == "" {
		t.Errorf("expected recon to populate the surface")
	}

	if strings.Contains(logs.String(), "[sqli] started") {
		t.Errorf("sqli ran even though it was not selected:\n%s", logs.String())
	}

	if strings.Contains(logs.String(), "[ratelimit] started") {
		t.Errorf("ratelimit ran even though it was not selected:\n%s", logs.String())
	}

	if !strings.Contains(logs.String(), "[misconfig] started") {
		t.Errorf("misconfig did not run:\n%s", logs.String())
	}
}

func TestScanReportsInvalidSelectedModule(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.SelectedModules = []string{"banana"}

	rep := Scan(&cfg)

	if len(rep.Errors) != 1 {
		t.Fatalf("errors = %+v, want one scanner error", rep.Errors)
	}

	if rep.Errors[0].Module != "scanner" || !strings.Contains(rep.Errors[0].Message, "banana") {
		t.Fatalf("unexpected error: %+v", rep.Errors[0])
	}
}

func TestNormalizeModulesAddsReconDependency(t *testing.T) {
	got, err := NormalizeModules([]string{"sqli", "misconfig"})
	if err != nil {
		t.Fatalf("NormalizeModules: %v", err)
	}

	if strings.Join(got, ",") != "recon,sqli,misconfig" {
		t.Fatalf("modules = %v", got)
	}
}

func TestNormalizeModulesDefaultsToCoreModules(t *testing.T) {
	got, err := NormalizeModules(nil)
	if err != nil {
		t.Fatalf("NormalizeModules: %v", err)
	}

	want := "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve"
	if strings.Join(got, ",") != want {
		t.Fatalf("modules = %v", got)
	}
}

func TestNormalizeModulesAllowsAllOfficialModules(t *testing.T) {
	got, err := NormalizeModules(ModuleNames())
	if err != nil {
		t.Fatalf("NormalizeModules: %v", err)
	}

	want := "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve,crawler,content,subdomain,ports,nmap,sqlmap,bannergrab"
	if strings.Join(got, ",") != want {
		t.Fatalf("modules = %v", got)
	}
}
