package auth

import (
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestBuildSessionPopulatesFields(t *testing.T) {
	cookies := []*proto.NetworkCookie{
		{Name: "session", Value: "abc123", Domain: "example.com"},
		{Name: "csrf", Value: "tok", Domain: ".example.com"},
	}
	headers := map[string]string{"Authorization": "Bearer xyz"}

	result := buildSession(cookies, "example.com", headers)

	if len(result.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d: %v", len(result.Cookies), result.Cookies)
	}

	if result.Cookies[0] != "session=abc123" {
		t.Errorf("unexpected first cookie: %q", result.Cookies[0])
	}

	if result.Cookies[1] != "csrf=tok" {
		t.Errorf("unexpected second cookie: %q", result.Cookies[1])
	}

	if result.Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("expected Authorization header, got %q", result.Headers["Authorization"])
	}
}

func TestBuildSessionDropsOtherDomains(t *testing.T) {
	cookies := []*proto.NetworkCookie{
		{Name: "session", Value: "abc123", Domain: "example.com"},
		{Name: "tracker", Value: "nope", Domain: "ads.other.com"},
	}

	result := buildSession(cookies, "example.com", nil)

	if len(result.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d: %v", len(result.Cookies), result.Cookies)
	}

	if result.Cookies[0] != "session=abc123" {
		t.Errorf("unexpected cookie: %q", result.Cookies[0])
	}
}

func TestBuildSessionEmptyWhenNoCookies(t *testing.T) {
	result := buildSession(nil, "example.com", nil)

	if len(result.Cookies) != 0 {
		t.Errorf("expected no cookies, got %v", result.Cookies)
	}

	if result.Headers == nil {
		t.Error("expected a non-nil Headers map on an empty session")
	}

	if len(result.Headers) != 0 {
		t.Errorf("expected no headers, got %v", result.Headers)
	}
}

func TestBuildSessionSkipsNamelessCookies(t *testing.T) {
	cookies := []*proto.NetworkCookie{
		nil,
		{Name: "", Value: "ignored", Domain: "example.com"},
		{Name: "session", Value: "abc123", Domain: "example.com"},
	}

	result := buildSession(cookies, "example.com", nil)

	if len(result.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d: %v", len(result.Cookies), result.Cookies)
	}
}

func TestFormatCookie(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"session", "abc123", "session=abc123"},
		{"csrf", "", "csrf="},
		{"a", "b=c", "a=b=c"},
	}

	for _, tc := range cases {
		got := formatCookie(tc.name, tc.value)
		if got != tc.want {
			t.Errorf("formatCookie(%q, %q) = %q, want %q", tc.name, tc.value, got, tc.want)
		}
	}
}

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		host   string
		domain string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"example.com", ".example.com", true},
		{"app.example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"example.com", "", false},
		{"", "example.com", false},
	}

	for _, tc := range cases {
		got := domainMatches(tc.host, tc.domain)
		if got != tc.want {
			t.Errorf("domainMatches(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

func TestCanonicalAuthHeader(t *testing.T) {
	cases := []struct {
		name      string
		want      string
		wantMatch bool
	}{
		{"Authorization", "Authorization", true},
		{"authorization", "Authorization", true},
		{"X-AUTH-TOKEN", "X-Auth-Token", true},
		{"x-api-key", "X-Api-Key", true},
		{"Content-Type", "", false},
		{"Cookie", "", false},
	}

	for _, tc := range cases {
		got, ok := canonicalAuthHeader(tc.name)
		if ok != tc.wantMatch {
			t.Errorf("canonicalAuthHeader(%q) match = %v, want %v", tc.name, ok, tc.wantMatch)
		}

		if got != tc.want {
			t.Errorf("canonicalAuthHeader(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTargetHost(t *testing.T) {
	host, err := targetHost("https://example.com/login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if host != "example.com" {
		t.Errorf("expected example.com, got %q", host)
	}

	if _, err := targetHost("not a url"); err == nil {
		t.Error("expected an error for a target without a host")
	}
}

func TestIsStaticAsset(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/main.js", true},
		{"/styles.css", true},
		{"/assets/logo.png", true},
		{"/fonts/x.woff2", true},
		{"/rest/basket/6", false},
		{"/api/Users/1", false},
		{"/rest/user/whoami", false},
	}

	for _, tc := range cases {
		if got := isStaticAsset(tc.path); got != tc.want {
			t.Errorf("isStaticAsset(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRecordEndpointFiltersAndDedupes(t *testing.T) {
	rec := newSessionRecorder()

	rec.recordEndpoint("target.example", "https://target.example/rest/basket/6")
	rec.recordEndpoint("target.example", "https://target.example/rest/basket/6") // duplicate
	rec.recordEndpoint("target.example", "https://target.example/main.js")       // static asset
	rec.recordEndpoint("target.example", "https://cdn.other.com/api/x")          // different host
	rec.recordEndpoint("target.example", "https://target.example/api/Users/1#z") // fragment stripped

	got := rec.endpointList()

	want := map[string]bool{
		"https://target.example/rest/basket/6": true,
		"https://target.example/api/Users/1":   true,
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d endpoints, got %d: %v", len(want), len(got), got)
	}

	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected endpoint captured: %q", e)
		}
	}
}
