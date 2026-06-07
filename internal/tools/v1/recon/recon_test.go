package recon

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sayseven7/frameseven/internal/config"
)

func TestSplitProductVersion(t *testing.T) {
	cases := []struct {
		in          string
		wantName    string
		wantVersion string
	}{
		{"Apache/2.4.49 (Ubuntu)", "Apache", "2.4.49"},
		{"PHP/7.4.3", "PHP", "7.4.3"},
		{"WordPress 5.8", "WordPress", "5.8"},
		{"nginx", "nginx", ""},
		{"ASP.NET", "ASP.NET", ""},
	}

	for _, c := range cases {
		name, version := splitProductVersion(c.in)
		if name != c.wantName || version != c.wantVersion {
			t.Errorf("splitProductVersion(%q) = (%q,%q), want (%q,%q)", c.in, name, version, c.wantName, c.wantVersion)
		}
	}
}

func TestFingerprint(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "Apache/2.4.49")
	h.Set("X-Powered-By", "PHP/7.4")
	h.Add("Set-Cookie", "PHPSESSID=abc; path=/")

	body := `<html><meta name="generator" content="WordPress 5.8"><div class="wp-content"></div></html>`

	techs := fingerprint(h, body)

	want := map[string]string{"Apache": "2.4.49", "PHP": "7.4", "WordPress": "5.8"}

	got := map[string]string{}
	for _, tech := range techs {
		got[tech.Name] = tech.Version
	}

	for name, version := range want {
		if got[name] != version {
			t.Errorf("expected %s %q, got %q (all: %+v)", name, version, got[name], techs)
		}
	}
}

func TestProbeSensitiveFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			w.Write([]byte("ref: refs/heads/main\n"))
		case "/robots.txt":
			w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := config.New(srv.URL)
	cfg.Timeout = 5 * time.Second

	_, findings := Run(&cfg, srv.Client())

	found := map[string]bool{}
	for _, f := range findings {
		found[f.Evidence.Extracted] = true
	}

	if !found["/.git/HEAD"] {
		t.Errorf("expected /.git/HEAD to be reported, findings: %+v", findings)
	}

	if !found["/robots.txt"] {
		t.Errorf("expected /robots.txt to be reported")
	}
}
