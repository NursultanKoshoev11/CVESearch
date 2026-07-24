package auth

import "testing"

func TestSafeReturnToRejectsExternalRedirect(t *testing.T) {
	h := &Handler{webPublicURL: "https://atlas.example"}
	if got := h.safeReturnTo("https://evil.example/phish"); got != "https://atlas.example/" {
		t.Fatalf("got %q", got)
	}
}

func TestSafeReturnToAllowsSameOriginAndRelative(t *testing.T) {
	h := &Handler{webPublicURL: "https://atlas.example"}
	if got := h.safeReturnTo("/findings?status=new"); got != "https://atlas.example/findings?status=new" {
		t.Fatalf("relative return URL = %q", got)
	}
	if got := h.safeReturnTo("https://atlas.example/dashboard"); got != "https://atlas.example/dashboard" {
		t.Fatalf("absolute return URL = %q", got)
	}
}
