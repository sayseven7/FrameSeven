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
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
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

func TestScanRunsOnlySelectedTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second
	cfg.SelectedTools = []string{"recon", "misconfig"}

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

func TestScanReportsInvalidSelectedTool(t *testing.T) {
	cfg := config.New("https://example.com")
	cfg.SelectedTools = []string{"banana"}

	rep := Scan(&cfg)

	if len(rep.Errors) != 1 {
		t.Fatalf("errors = %+v, want one scanner error", rep.Errors)
	}

	if rep.Errors[0].Module != "scanner" || !strings.Contains(rep.Errors[0].Message, "banana") {
		t.Fatalf("unexpected error: %+v", rep.Errors[0])
	}
}

func TestScanRunsToolsConcurrentlyAfterRecon(t *testing.T) {
	original := Tools
	defer func() {
		Tools = original
	}()

	started := make(chan string, 2)
	release := make(chan struct{})

	Tools = []Tool{
		{
			Name:             "recon",
			Description:      "test recon",
			Activity:         "mapping test surface",
			EnabledByDefault: true,
			Run: func(_ *config.Config, _ *http.Client, surface *recon.Surface) []finding.Finding {
				surface.Host = "example.com"

				return nil
			},
		},
		{
			Name:             "alpha",
			Description:      "test alpha",
			Activity:         "running alpha",
			EnabledByDefault: true,
			Run: func(*config.Config, *http.Client, *recon.Surface) []finding.Finding {
				started <- "alpha"
				<-release

				return nil
			},
		},
		{
			Name:             "beta",
			Description:      "test beta",
			Activity:         "running beta",
			EnabledByDefault: true,
			Run: func(*config.Config, *http.Client, *recon.Surface) []finding.Finding {
				started <- "beta"
				<-release

				return nil
			},
		},
	}

	cfg := config.New("https://example.com")
	cfg.ToolConcurrency = 2
	cfg.ToolTimeout = time.Second

	done := make(chan reportDone, 1)
	go func() {
		rep := Scan(&cfg)
		done <- reportDone{host: rep.Surface.Host, errors: len(rep.Errors)}
	}()

	waitStartedTool(t, started)
	waitStartedTool(t, started)
	close(release)

	select {
	case result := <-done:
		if result.host != "example.com" {
			t.Errorf("surface host = %q, want example.com", result.host)
		}

		if result.errors != 0 {
			t.Errorf("scan errors = %d, want 0", result.errors)
		}
	case <-time.After(time.Second):
		t.Fatal("scan did not finish")
	}
}

type reportDone struct {
	host   string
	errors int
}

func waitStartedTool(t *testing.T, started <-chan string) {
	t.Helper()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for concurrent tool start")
	}
}

func TestNormalizeToolsAddsReconDependency(t *testing.T) {
	got, err := NormalizeTools([]string{"sqli", "misconfig"})
	if err != nil {
		t.Fatalf("NormalizeTools: %v", err)
	}

	if strings.Join(got, ",") != "recon,sqli,misconfig" {
		t.Fatalf("tools = %v", got)
	}
}

func TestNormalizeToolsDefaultsToCoreTools(t *testing.T) {
	got, err := NormalizeTools(nil)
	if err != nil {
		t.Fatalf("NormalizeTools: %v", err)
	}

	want := "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve"
	if strings.Join(got, ",") != want {
		t.Fatalf("tools = %v", got)
	}
}

func TestNormalizeToolsAllowsAllOfficialTools(t *testing.T) {
	got, err := NormalizeTools(ToolNames())
	if err != nil {
		t.Fatalf("NormalizeTools: %v", err)
	}

	want := "recon,sqli,access,ssrf,lfi,misconfig,ratelimit,cve,crawler,content,subdomain,ports,nmap,sqlmap,bannergrab"
	if strings.Join(got, ",") != want {
		t.Fatalf("tools = %v", got)
	}
}
