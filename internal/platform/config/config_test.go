package config

import (
	"strings"
	"testing"
)

func TestValidateRejectsPlaceholderSecrets(t *testing.T) {
	cfg := validConfig()
	cfg.OIDCClientSecret = "CHANGE_ME"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "CHANGE_ME") {
		t.Fatalf("expected placeholder validation error, got %v", err)
	}
}

func TestValidateRequiresSecureCookieOutsideDevelopment(t *testing.T) {
	cfg := validConfig()
	cfg.Environment = "production"
	cfg.SessionCookieSecure = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SESSION_COOKIE_SECURE") {
		t.Fatalf("expected secure cookie validation error, got %v", err)
	}
}

func TestValidateAcceptsCompleteDevelopmentConfiguration(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func validConfig() Config {
	return Config{
		Environment: "development", WebOrigin: "http://localhost:3000",
		APIPublicURL: "http://localhost:8080", WebPublicURL: "http://localhost:3000",
		AuditIPHashKey: strings.Repeat("a", 32), DatabaseURL: "postgres://user:pass@db/db",
		RedisURL: "redis://redis:6379/0", BootstrapTenantID: "00000000-0000-4000-8000-000000000001",
		Neo4jURI: "neo4j://neo4j:7687", Neo4jUser: "neo4j", Neo4jPassword: "strong-password",
		S3Endpoint: "minio:9000", S3AccessKey: "access", S3SecretKey: "secret",
		OIDCIssuerURL: "http://keycloak.localhost:8081/realms/cve-atlas", OIDCClientID: "client",
		OIDCClientSecret: "secret", OIDCRedirectURL: "http://localhost:8080/api/v1/auth/callback",
		SessionCookieSecure: false, SessionTTL: 1, LoginFlowTTL: 1,
	}
}
