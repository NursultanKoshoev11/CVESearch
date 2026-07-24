package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NursultanKoshoev11/CVESearch/internal/audit"
	"github.com/NursultanKoshoev11/CVESearch/internal/auth"
	"github.com/NursultanKoshoev11/CVESearch/internal/platform/config"
	"github.com/NursultanKoshoev11/CVESearch/internal/platform/httpserver"
	httpmiddleware "github.com/NursultanKoshoev11/CVESearch/internal/platform/httpserver/middleware"
	"github.com/NursultanKoshoev11/CVESearch/packages/database"
	"github.com/NursultanKoshoev11/CVESearch/packages/observability"
	"github.com/NursultanKoshoev11/CVESearch/packages/platform"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("application.failed", "error", err)
		os.Exit(1)
	}
}

func runHealthcheck(endpoint string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create healthcheck request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", response.StatusCode)
	}
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	telemetryShutdown, err := observability.Setup(rootCtx, observability.Config{
		ServiceName: cfg.OTELServiceName,
		Environment: cfg.Environment,
		Endpoint:    cfg.OTELExporterEndpoint,
		Insecure:    cfg.OTELExporterInsecure,
		SampleRatio: cfg.OTELSampleRatio,
	})
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := telemetryShutdown(shutdownCtx); err != nil {
			logger.Error("telemetry.shutdown.failed", "error", err)
		}
	}()

	pool, err := database.OpenPostgres(rootCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisOptions, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("parse Redis URL: %w", err)
	}
	redisClient := redis.NewClient(redisOptions)
	defer func() { _ = redisClient.Close() }()
	pingCtx, cancelPing := context.WithTimeout(rootCtx, 5*time.Second)
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		cancelPing()
		return fmt.Errorf("ping Redis: %w", err)
	}
	cancelPing()

	neo4jDriver, err := neo4j.NewDriverWithContext(cfg.Neo4jURI, neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""))
	if err != nil {
		return fmt.Errorf("create Neo4j driver: %w", err)
	}
	defer func() { _ = neo4jDriver.Close(context.Background()) }()
	neoCtx, cancelNeo := context.WithTimeout(rootCtx, 8*time.Second)
	if err := neo4jDriver.VerifyConnectivity(neoCtx); err != nil {
		cancelNeo()
		return fmt.Errorf("verify Neo4j connectivity: %w", err)
	}
	cancelNeo()

	minioClient, err := minio.New(cfg.S3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		Secure: cfg.S3UseSSL,
	})
	if err != nil {
		return fmt.Errorf("create object storage client: %w", err)
	}
	if err := ensureBucket(rootCtx, minioClient, cfg.S3Bucket); err != nil {
		return err
	}

	tenantID, err := uuid.Parse(cfg.BootstrapTenantID)
	if err != nil {
		return fmt.Errorf("parse BOOTSTRAP_TENANT_ID: %w", err)
	}
	authRepository := auth.NewRepository(pool)
	if err := authRepository.EnsureTenant(rootCtx, tenantID, cfg.BootstrapTenantSlug, cfg.BootstrapTenantName); err != nil {
		return err
	}
	auditRepository := audit.NewRepository(pool, cfg.AuditIPHashKey)

	oidcCtx, cancelOIDC := context.WithTimeout(rootCtx, 15*time.Second)
	oidcProvider, err := auth.NewOIDCProvider(oidcCtx, auth.OIDCProviderConfig{
		IssuerURL:        cfg.OIDCIssuerURL,
		BrowserAuthURL:   cfg.OIDCBrowserAuthURL,
		BrowserLogoutURL: cfg.OIDCBrowserLogoutURL,
		ClientID:         cfg.OIDCClientID,
		ClientSecret:     cfg.OIDCClientSecret,
		RedirectURL:      cfg.OIDCRedirectURL,
	})
	cancelOIDC()
	if err != nil {
		return err
	}

	authStore := auth.NewRedisStore(redisClient, cfg.LoginFlowTTL, cfg.SessionTTL)
	authHandler := auth.NewHandler(oidcProvider, authStore, authRepository, auditRepository, logger, auth.HandlerConfig{
		TenantID:              tenantID,
		DefaultRole:           cfg.OIDCDefaultRole,
		RoleGroupMappings:     cfg.OIDCRoleGroupMappings,
		CookieName:            cfg.SessionCookieName,
		CookieSecure:          cfg.SessionCookieSecure,
		SessionTTL:            cfg.SessionTTL,
		WebPublicURL:          cfg.WebPublicURL,
		PostLogoutRedirectURL: cfg.OIDCPostLogoutRedirect,
		OIDCClientID:          cfg.OIDCClientID,
	})

	healthChecker := platform.NewHealthChecker(3*time.Second, map[string]platform.HealthCheck{
		"postgres": func(ctx context.Context) error { return pool.Ping(ctx) },
		"redis":    func(ctx context.Context) error { return redisClient.Ping(ctx).Err() },
		"neo4j":    func(ctx context.Context) error { return neo4jDriver.VerifyConnectivity(ctx) },
		"object_storage": func(ctx context.Context) error {
			exists, err := minioClient.BucketExists(ctx, cfg.S3Bucket)
			if err != nil {
				return err
			}
			if !exists {
				return errors.New("configured bucket does not exist")
			}
			return nil
		},
	})

	baseRouter := httpserver.NewRouter(httpserver.Dependencies{
		Auth: authHandler, Audit: auditRepository, HealthChecker: healthChecker,
	})
	var handler http.Handler = otelhttp.NewHandler(baseRouter, "cve-atlas.http")
	handler = httpmiddleware.SameOrigin(cfg.WebOrigin)(handler)
	handler = httpmiddleware.CORS(cfg.WebOrigin)(handler)
	handler = httpmiddleware.SecurityHeaders(handler)
	handler = httpmiddleware.AccessLog(logger)(handler)
	handler = httpmiddleware.Recovery(logger)(handler)
	handler = httpmiddleware.RequestID(handler)

	server := &http.Server{
		Addr:              cfg.APIListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("http.server.started", "address", cfg.APIListenAddr, "environment", cfg.Environment)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()

	select {
	case <-rootCtx.Done():
		logger.Info("application.shutdown.requested")
	case err := <-serverErrors:
		if err != nil {
			return fmt.Errorf("HTTP server failed: %w", err)
		}
		return nil
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	return <-serverErrors
}

func ensureBucket(ctx context.Context, client *minio.Client, bucket string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	exists, err := client.BucketExists(checkCtx, bucket)
	if err != nil {
		return fmt.Errorf("check object storage bucket: %w", err)
	}
	if exists {
		return nil
	}
	if err := client.MakeBucket(checkCtx, bucket, minio.MakeBucketOptions{}); err != nil {
		existsAfterRace, checkErr := client.BucketExists(checkCtx, bucket)
		if checkErr == nil && existsAfterRace {
			return nil
		}
		return fmt.Errorf("create object storage bucket: %w", err)
	}
	return nil
}

func newLogger(levelName string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(levelName) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
