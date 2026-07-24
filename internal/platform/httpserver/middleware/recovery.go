package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/NursultanKoshoev11/CVESearch/packages/platform"
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.ErrorContext(r.Context(), "http.panic",
						"request_id", RequestIDFromContext(r.Context()),
						"panic", recovered,
						"stack", string(debug.Stack()),
					)
					platform.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.", RequestIDFromContext(r.Context()), nil)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
