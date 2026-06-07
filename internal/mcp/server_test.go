package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewStreamableHTTPHandlerServesHealth(t *testing.T) {
	handler := NewStreamableHTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
