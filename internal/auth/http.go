package auth

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NursultanKoshoev11/CVESearch/internal/audit"
	httpmiddleware "github.com/NursultanKoshoev11/CVESearch/internal/platform/httpserver/middleware"
	"github.com/NursultanKoshoev11/CVESearch/packages/platform"
	"github.com/google/uuid"
)

type Handler struct {
	provider              Provider
	store                 *RedisStore
	repository            *Repository
	audit                 *audit.Repository
	logger                *slog.Logger
	tenantID              uuid.UUID
	defaultRole           string
	roleGroupMappings     map[string]string
	cookieName            string
	cookieSecure          bool
	sessionTTL            time.Duration
	webPublicURL          string
	postLogoutRedirectURL string
	oidcClientID          string
}

type HandlerConfig struct {
	TenantID              uuid.UUID
	DefaultRole           string
	RoleGroupMappings     map[string]string
	CookieName            string
	CookieSecure          bool
	SessionTTL            time.Duration
	WebPublicURL          string
	PostLogoutRedirectURL string
	OIDCClientID          string
}

func NewHandler(provider Provider, store *RedisStore, repository *Repository, auditRepository *audit.Repository, logger *slog.Logger, cfg HandlerConfig) *Handler {
	return &Handler{
		provider: provider, store: store, repository: repository, audit: auditRepository, logger: logger,
		tenantID: cfg.TenantID, defaultRole: cfg.DefaultRole, roleGroupMappings: cfg.RoleGroupMappings,
		cookieName: cfg.CookieName, cookieSecure: cfg.CookieSecure, sessionTTL: cfg.SessionTTL,
		webPublicURL: cfg.WebPublicURL, postLogoutRedirectURL: cfg.PostLogoutRedirectURL, oidcClientID: cfg.OIDCClientID,
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	nonce, err := randomToken(32)
	if err != nil {
		h.internalError(w, r, "generate OIDC nonce", err)
		return
	}
	verifier, err := randomToken(48)
	if err != nil {
		h.internalError(w, r, "generate PKCE verifier", err)
		return
	}
	returnTo := h.safeReturnTo(r.URL.Query().Get("return_to"))
	state, err := h.store.CreateLoginFlow(r.Context(), LoginFlow{Nonce: nonce, CodeVerifier: verifier, ReturnTo: returnTo})
	if err != nil {
		h.internalError(w, r, "store OIDC login flow", err)
		return
	}
	http.Redirect(w, r, h.provider.AuthorizationURL(state, nonce, codeChallenge(verifier)), http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	requestID := httpmiddleware.RequestIDFromContext(r.Context())
	if providerError := strings.TrimSpace(r.URL.Query().Get("error")); providerError != "" {
		h.recordLoginFailure(r, requestID, "provider_error", map[string]any{"provider_error": providerError})
		platform.WriteError(w, http.StatusUnauthorized, "OIDC_AUTHENTICATION_FAILED", "Identity provider authentication failed.", requestID, nil)
		return
	}
	flow, err := h.store.ConsumeLoginFlow(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		h.recordLoginFailure(r, requestID, "invalid_state", nil)
		platform.WriteError(w, http.StatusUnauthorized, "OIDC_STATE_INVALID", "Login transaction is invalid or expired.", requestID, nil)
		return
	}
	identity, err := h.provider.ExchangeAndVerify(r.Context(), r.URL.Query().Get("code"), flow.CodeVerifier, flow.Nonce)
	if err != nil {
		h.recordLoginFailure(r, requestID, "token_validation_failed", nil)
		h.logger.WarnContext(r.Context(), "oidc.callback.failed", "request_id", requestID, "error", err)
		platform.WriteError(w, http.StatusUnauthorized, "OIDC_TOKEN_INVALID", "Identity token validation failed.", requestID, nil)
		return
	}
	roles := ResolveRoles(h.defaultRole, h.roleGroupMappings, identity.Groups)
	userID, err := h.repository.UpsertUserAndRoles(r.Context(), h.tenantID, identity, roles)
	if err != nil {
		h.internalError(w, r, "provision OIDC user", err)
		return
	}
	sessionToken, session, err := h.store.CreateSession(r.Context(), userID.String(), h.tenantID.String())
	if err != nil {
		h.internalError(w, r, "create application session", err)
		return
	}
	if err := h.audit.Append(r.Context(), audit.Event{
		ActorID: &userID, TenantID: h.tenantID, Action: "login.success", Result: "success", RequestID: requestID,
		ResourceType: "user", ResourceID: &userID,
		Metadata: map[string]any{"oidc_issuer": identity.Issuer, "roles": roles},
	}, r.RemoteAddr); err != nil {
		_ = h.store.DeleteSession(r.Context(), sessionToken)
		h.internalError(w, r, "append login audit event", err)
		return
	}
	h.setSessionCookie(w, sessionToken, session.ExpiresAt)
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		platform.WriteError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"data": principal})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		platform.WriteError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
		return
	}
	cookie, err := r.Cookie(h.cookieName)
	if err == nil {
		if err := h.store.DeleteSession(r.Context(), cookie.Value); err != nil {
			h.internalError(w, r, "delete application session", err)
			return
		}
	}
	h.clearSessionCookie(w)
	requestID := httpmiddleware.RequestIDFromContext(r.Context())
	if err := h.audit.Append(r.Context(), audit.Event{
		ActorID: &principal.UserID, TenantID: principal.TenantID, Action: "logout", Result: "success", RequestID: requestID,
		ResourceType: "user", ResourceID: &principal.UserID,
		Metadata: map[string]any{},
	}, r.RemoteAddr); err != nil {
		h.internalError(w, r, "append logout audit event", err)
		return
	}
	logoutURL := h.provider.LogoutURL()
	if logoutURL != "" && h.postLogoutRedirectURL != "" {
		separator := "?"
		if strings.Contains(logoutURL, "?") {
			separator = "&"
		}
		logoutURL += separator + "post_logout_redirect_uri=" + url.QueryEscape(h.postLogoutRedirectURL) + "&client_id=" + url.QueryEscape(h.oidcClientID)
	}
	platform.WriteJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"logout_url": logoutURL}})
}

func (h *Handler) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := httpmiddleware.RequestIDFromContext(r.Context())
		cookie, err := r.Cookie(h.cookieName)
		if err != nil || cookie.Value == "" {
			platform.WriteError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required.", requestID, nil)
			return
		}
		session, err := h.store.GetSession(r.Context(), cookie.Value)
		if err != nil {
			h.clearSessionCookie(w)
			platform.WriteError(w, http.StatusUnauthorized, "SESSION_INVALID", "Session is invalid or expired.", requestID, nil)
			return
		}
		userID, err := uuid.Parse(session.UserID)
		if err != nil {
			h.clearSessionCookie(w)
			platform.WriteError(w, http.StatusUnauthorized, "SESSION_INVALID", "Session is invalid or expired.", requestID, nil)
			return
		}
		tenantID, err := uuid.Parse(session.TenantID)
		if err != nil || tenantID != h.tenantID {
			h.clearSessionCookie(w)
			platform.WriteError(w, http.StatusUnauthorized, "SESSION_INVALID", "Session is invalid or expired.", requestID, nil)
			return
		}
		principal, err := h.repository.LoadPrincipal(r.Context(), tenantID, userID)
		if err != nil {
			h.logger.WarnContext(r.Context(), "session.principal.failed", "request_id", requestID, "error", err)
			h.clearSessionCookie(w)
			platform.WriteError(w, http.StatusUnauthorized, "SESSION_INVALID", "Session is invalid or expired.", requestID, nil)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func (h *Handler) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok {
				platform.WriteError(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required.", httpmiddleware.RequestIDFromContext(r.Context()), nil)
				return
			}
			if !principal.HasPermission(permission) {
				requestID := httpmiddleware.RequestIDFromContext(r.Context())
				if err := h.audit.Append(r.Context(), audit.Event{
					ActorID: &principal.UserID, TenantID: principal.TenantID, Action: "authorization.denied", Result: "denied", RequestID: requestID,
					Metadata: map[string]any{"permission": permission, "method": r.Method, "path": r.URL.Path},
				}, r.RemoteAddr); err != nil {
					h.logger.ErrorContext(r.Context(), "audit.authorization_denied.failed", "request_id", requestID, "error", err)
				}
				platform.WriteError(w, http.StatusForbidden, "PERMISSION_DENIED", "You do not have permission to perform this operation.", requestID, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cookieName, Value: token, Path: "/", HttpOnly: true, Secure: h.cookieSecure,
		SameSite: http.SameSiteLaxMode, Expires: expiresAt, MaxAge: int(time.Until(expiresAt).Seconds()),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: h.cookieName, Value: "", Path: "/", HttpOnly: true, Secure: h.cookieSecure,
		SameSite: http.SameSiteLaxMode, Expires: time.Unix(0, 0), MaxAge: -1,
	})
}

func (h *Handler) safeReturnTo(raw string) string {
	fallback := strings.TrimRight(h.webPublicURL, "/") + "/"
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	base, err := url.Parse(h.webPublicURL)
	if err != nil {
		return fallback
	}
	candidate, err := url.Parse(raw)
	if err != nil {
		return fallback
	}
	if !candidate.IsAbs() {
		if !strings.HasPrefix(candidate.Path, "/") || strings.HasPrefix(candidate.Path, "//") {
			return fallback
		}
		return base.ResolveReference(candidate).String()
	}
	if candidate.Scheme != base.Scheme || candidate.Host != base.Host {
		return fallback
	}
	candidate.User = nil
	return candidate.String()
}

func (h *Handler) recordLoginFailure(r *http.Request, requestID, reason string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["reason"] = reason
	if err := h.audit.Append(r.Context(), audit.Event{
		TenantID: h.tenantID, Action: "login.failure", Result: "failure", RequestID: requestID, Metadata: metadata,
	}, r.RemoteAddr); err != nil {
		h.logger.ErrorContext(r.Context(), "audit.login_failure.failed", "request_id", requestID, "error", err)
	}
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	requestID := httpmiddleware.RequestIDFromContext(r.Context())
	h.logger.ErrorContext(r.Context(), operation, "request_id", requestID, "error", err)
	platform.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred.", requestID, nil)
}

func ParsePagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
