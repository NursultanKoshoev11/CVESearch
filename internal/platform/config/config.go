package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment     string
	APIListenAddr   string
	WebOrigin       string
	APIPublicURL    string
	WebPublicURL    string
	LogLevel        string
	ShutdownTimeout time.Duration
	AuditIPHashKey  string

	DatabaseURL string
	RedisURL    string

	BootstrapTenantID   string
	BootstrapTenantSlug string
	BootstrapTenantName string

	SessionTTL          time.Duration
	LoginFlowTTL        time.Duration
	SessionCookieName   string
	SessionCookieSecure bool

	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string

	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3Bucket    string
	S3UseSSL    bool

	OIDCIssuerURL          string
	OIDCBrowserAuthURL     string
	OIDCBrowserLogoutURL   string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCRedirectURL        string
	OIDCPostLogoutRedirect string
	OIDCDefaultRole        string
	OIDCRoleGroupMappings  map[string]string

	OTELServiceName      string
	OTELExporterEndpoint string
	OTELExporterInsecure bool
	OTELSampleRatio      float64
}

func Load() (Config, error) {
	cfg := Config{
		Environment:            getenv("APP_ENV", "development"),
		APIListenAddr:          getenv("API_LISTEN_ADDR", ":8080"),
		WebOrigin:              getenv("WEB_ORIGIN", "http://localhost:3000"),
		APIPublicURL:           getenv("API_PUBLIC_URL", "http://localhost:8080"),
		WebPublicURL:           getenv("WEB_PUBLIC_URL", "http://localhost:3000"),
		LogLevel:               getenv("LOG_LEVEL", "info"),
		AuditIPHashKey:         strings.TrimSpace(os.Getenv("AUDIT_IP_HASH_KEY")),
		DatabaseURL:            strings.TrimSpace(os.Getenv("DATABASE_URL")),
		RedisURL:               strings.TrimSpace(os.Getenv("REDIS_URL")),
		BootstrapTenantID:      strings.TrimSpace(os.Getenv("BOOTSTRAP_TENANT_ID")),
		BootstrapTenantSlug:    getenv("BOOTSTRAP_TENANT_SLUG", "local"),
		BootstrapTenantName:    getenv("BOOTSTRAP_TENANT_NAME", "CVE Atlas Local"),
		SessionCookieName:      getenv("SESSION_COOKIE_NAME", "cve_atlas_session"),
		Neo4jURI:               strings.TrimSpace(os.Getenv("NEO4J_URI")),
		Neo4jUser:              strings.TrimSpace(os.Getenv("NEO4J_USER")),
		Neo4jPassword:          strings.TrimSpace(os.Getenv("NEO4J_PASSWORD")),
		S3Endpoint:             strings.TrimSpace(os.Getenv("S3_ENDPOINT")),
		S3AccessKey:            strings.TrimSpace(os.Getenv("S3_ACCESS_KEY")),
		S3SecretKey:            strings.TrimSpace(os.Getenv("S3_SECRET_KEY")),
		S3Bucket:               getenv("S3_BUCKET", "cve-atlas"),
		OIDCIssuerURL:          strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		OIDCBrowserAuthURL:     strings.TrimSpace(os.Getenv("OIDC_BROWSER_AUTH_URL")),
		OIDCBrowserLogoutURL:   strings.TrimSpace(os.Getenv("OIDC_BROWSER_LOGOUT_URL")),
		OIDCClientID:           strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret:       strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCRedirectURL:        strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
		OIDCPostLogoutRedirect: strings.TrimSpace(os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URL")),
		OIDCDefaultRole:        getenv("OIDC_DEFAULT_ROLE", "public_user"),
		OTELServiceName:        getenv("OTEL_SERVICE_NAME", "cve-atlas-api"),
		OTELExporterEndpoint:   strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
	}

	var err error
	if cfg.ShutdownTimeout, err = durationEnv("SHUTDOWN_TIMEOUT", 15*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.SessionTTL, err = durationEnv("SESSION_TTL", 8*time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.LoginFlowTTL, err = durationEnv("LOGIN_FLOW_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.SessionCookieSecure, err = boolEnv("SESSION_COOKIE_SECURE", cfg.Environment != "development"); err != nil {
		return Config{}, err
	}
	if cfg.S3UseSSL, err = boolEnv("S3_USE_SSL", cfg.Environment != "development"); err != nil {
		return Config{}, err
	}
	if cfg.OTELExporterInsecure, err = boolEnv("OTEL_EXPORTER_OTLP_INSECURE", cfg.Environment == "development"); err != nil {
		return Config{}, err
	}
	if cfg.OTELSampleRatio, err = floatEnv("OTEL_SAMPLE_RATIO", 1.0); err != nil {
		return Config{}, err
	}
	if cfg.OTELSampleRatio < 0 || cfg.OTELSampleRatio > 1 {
		return Config{}, errors.New("OTEL_SAMPLE_RATIO must be between 0 and 1")
	}

	mappings := getenv("OIDC_ROLE_GROUP_MAPPINGS", `{}`)
	if err := json.Unmarshal([]byte(mappings), &cfg.OIDCRoleGroupMappings); err != nil {
		return Config{}, fmt.Errorf("parse OIDC_ROLE_GROUP_MAPPINGS: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	required := map[string]string{
		"DATABASE_URL":        c.DatabaseURL,
		"AUDIT_IP_HASH_KEY":   c.AuditIPHashKey,
		"REDIS_URL":           c.RedisURL,
		"BOOTSTRAP_TENANT_ID": c.BootstrapTenantID,
		"NEO4J_URI":           c.Neo4jURI,
		"NEO4J_USER":          c.Neo4jUser,
		"NEO4J_PASSWORD":      c.Neo4jPassword,
		"S3_ENDPOINT":         c.S3Endpoint,
		"S3_ACCESS_KEY":       c.S3AccessKey,
		"S3_SECRET_KEY":       c.S3SecretKey,
		"OIDC_ISSUER_URL":     c.OIDCIssuerURL,
		"OIDC_CLIENT_ID":      c.OIDCClientID,
		"OIDC_CLIENT_SECRET":  c.OIDCClientSecret,
		"OIDC_REDIRECT_URL":   c.OIDCRedirectURL,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
		if strings.Contains(value, "CHANGE_ME") {
			return fmt.Errorf("%s still contains CHANGE_ME", name)
		}
	}
	for name, raw := range map[string]string{
		"WEB_ORIGIN":        c.WebOrigin,
		"API_PUBLIC_URL":    c.APIPublicURL,
		"WEB_PUBLIC_URL":    c.WebPublicURL,
		"OIDC_ISSUER_URL":   c.OIDCIssuerURL,
		"OIDC_REDIRECT_URL": c.OIDCRedirectURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%s must be an absolute URL", name)
		}
	}
	if len(c.AuditIPHashKey) < 32 {
		return errors.New("AUDIT_IP_HASH_KEY must be at least 32 characters")
	}
	if c.Environment != "development" && !c.SessionCookieSecure {
		return errors.New("SESSION_COOKIE_SECURE must be true outside development")
	}
	if c.SessionTTL <= 0 || c.LoginFlowTTL <= 0 {
		return errors.New("session and login flow TTLs must be positive")
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return value, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return value, nil
}

func floatEnv(key string, fallback float64) (float64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return value, nil
}
