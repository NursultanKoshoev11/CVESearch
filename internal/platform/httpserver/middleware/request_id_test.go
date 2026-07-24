package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDPreservesValidValue(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestIDFromContext(r.Context()); got != "client-123" {
			t.Fatalf("context request ID = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "client-123")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if got := res.Header().Get("X-Request-ID"); got != "client-123" {
		t.Fatalf("response request ID = %q", got)
	}
}

func TestRequestIDReplacesUnsafeValue(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", strings.Repeat("x", 129))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	got := res.Header().Get("X-Request-ID")
	if !strings.HasPrefix(got, "req_") {
		t.Fatalf("generated request ID = %q", got)
	}
}
