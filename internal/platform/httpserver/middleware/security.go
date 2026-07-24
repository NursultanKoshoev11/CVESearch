package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/NursultanKoshoev11/CVESearch/packages/platform"
)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func CORS(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				w.Header().Add("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				if origin != allowedOrigin {
					platform.WriteError(w, http.StatusForbidden, "ORIGIN_NOT_ALLOWED", "Origin is not allowed.", RequestIDFromContext(r.Context()), nil)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func SameOrigin(allowedOrigin string) func(http.Handler) http.Handler {
	allowed, _ := url.Parse(allowedOrigin)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				platform.WriteError(w, http.StatusForbidden, "ORIGIN_REQUIRED", "Origin header is required for state-changing requests.", RequestIDFromContext(r.Context()), nil)
				return
			}
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != allowed.Scheme || parsed.Host != allowed.Host {
				platform.WriteError(w, http.StatusForbidden, "ORIGIN_NOT_ALLOWED", "Origin is not allowed.", RequestIDFromContext(r.Context()), nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
