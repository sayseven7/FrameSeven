package main

import "testing"

func TestParseOptionsDefaultsToStdio(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}

	if opts.transport != "stdio" {
		t.Fatalf("transport = %q, want stdio", opts.transport)
	}
}

func TestParseOptionsAcceptsHTTPTransport(t *testing.T) {
	opts, err := parseOptions([]string{"-transport", "http", "-addr", "0.0.0.0:9090"})
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}

	if opts.transport != "http" {
		t.Fatalf("transport = %q, want http", opts.transport)
	}

	if opts.addr != "0.0.0.0:9090" {
		t.Fatalf("addr = %q, want 0.0.0.0:9090", opts.addr)
	}
}
