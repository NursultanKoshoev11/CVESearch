package httpserver

import (
	"net/http"
	"time"

	"github.com/NursultanKoshoev11/CVESearch/internal/audit"
	"github.com/NursultanKoshoev11/CVESearch/internal/auth"
	httpmiddleware "github.com/NursultanKoshoev11/CVESearch/internal/platform/httpserver/middleware"
	"github.com/NursultanKoshoev11/CVESearch/packages/platform"
	"github.com/go-chi/chi/v5"
)

type Dependencies struct {
	Auth          *auth.Handler
	Audit         *audit.Repository
	HealthChecker *platform.HealthChecker
}

func NewRouter(deps Dependencies) http.Handler {
	router := chi.NewRouter()

	router.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		platform.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "alive",
			"time":   time.Now().UTC(),
		})
	})
	router.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		result, err := deps.HealthChecker.Check(r.Context())
		if err != nil {
			platform.WriteJSON(w, http.StatusServiceUnavailable, result)
			return
		}
		platform.WriteJSON(w, http.StatusOK, result)
	})

	router.Route("/api/v1", func(api chi.Router) {
		api.Get("/auth/login", deps.Auth.Login)
		api.Get("/auth/callback", deps.Auth.Callback)

		api.Group(func(protected chi.Router) {
			protected.Use(deps.Auth.AuthenticationMiddleware)
			protected.Get("/auth/me", deps.Auth.Me)
			protected.With(deps.Auth.RequirePermission("audit.read")).Get("/audit-events", func(w http.ResponseWriter, r *http.Request) {
				principal, _ := auth.PrincipalFromContext(r.Context())
				limit, offset := auth.ParsePagination(r)
				events, err := deps.Audit.List(r.Context(), principal.TenantID, limit, offset)
				if err != nil {
					platform.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
					return
				}
				platform.WriteJSON(w, http.StatusOK, map[string]any{
					"data":       events,
					"pagination": map[string]int{"limit": limit, "offset": offset, "next_offset": offset + len(events)},
				})
			})
			protected.Post("/auth/logout", deps.Auth.Logout)
		})
	})

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		platform.WriteError(w, http.StatusNotFound, "NOT_FOUND", "Resource was not found.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowedMethods(r.URL.Path))
		platform.WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "HTTP method is not allowed.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
	})
	return router
}

func allowedMethods(path string) string {
	switch path {
	case "/health/live", "/health/ready", "/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/auth/me", "/api/v1/audit-events":
		return http.MethodGet
	case "/api/v1/auth/logout":
		return http.MethodPost
	default:
		return ""
	}
}
