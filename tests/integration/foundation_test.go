//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/NursultanKoshoev11/CVESearch/internal/audit"
	"github.com/NursultanKoshoev11/CVESearch/internal/auth"
	"github.com/NursultanKoshoev11/CVESearch/packages/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/redis/go-redis/v9"
)

func TestFoundationDependenciesAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	databaseURL := requiredEnv(t, "DATABASE_URL")
	pool, err := database.OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tenantID := uuid.MustParse(requiredEnv(t, "BOOTSTRAP_TENANT_ID"))
	authRepository := auth.NewRepository(pool)
	if err := authRepository.EnsureTenant(ctx, tenantID, "integration", "Integration Tenant"); err != nil {
		t.Fatal(err)
	}

	auditRepository := audit.NewRepository(pool, requiredEnv(t, "AUDIT_IP_HASH_KEY"))
	if err := auditRepository.Append(ctx, audit.Event{
		TenantID:  tenantID,
		Action:    "integration.foundation.checked",
		Result:    "success",
		RequestID: "req_integration",
		Metadata:  map[string]any{"suite": "foundation"},
	}, "192.0.2.10:443"); err != nil {
		t.Fatal(err)
	}
	events, err := auditRepository.List(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != "integration.foundation.checked" {
		t.Fatalf("unexpected audit events: %#v", events)
	}

	err = database.WithTenantTx(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, updateErr := tx.Exec(ctx, `UPDATE audit_logs SET action = 'tampered' WHERE id = $1`, events[0].ID)
		return updateErr
	})
	if err == nil {
		t.Fatal("append-only audit log accepted an update")
	}

	otherTenant := uuid.New()
	var hiddenCount int
	if err := database.WithTenantTx(ctx, pool, otherTenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1`, tenantID).Scan(&hiddenCount)
	}); err != nil {
		t.Fatal(err)
	}
	if hiddenCount != 0 {
		t.Fatalf("tenant isolation leaked %d audit rows", hiddenCount)
	}
}

func TestRedisNeo4jAndObjectStorage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	redisOptions, err := redis.ParseURL(requiredEnv(t, "REDIS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	redisClient := redis.NewClient(redisOptions)
	defer func() { _ = redisClient.Close() }()
	key := "integration:" + uuid.NewString()
	if err := redisClient.Set(ctx, key, "ok", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if value, err := redisClient.Get(ctx, key).Result(); err != nil || value != "ok" {
		t.Fatalf("Redis value=%q err=%v", value, err)
	}
	if err := redisClient.Del(ctx, key).Err(); err != nil {
		t.Fatal(err)
	}

	driver, err := neo4j.NewDriverWithContext(
		requiredEnv(t, "NEO4J_URI"),
		neo4j.BasicAuth(requiredEnv(t, "NEO4J_USER"), requiredEnv(t, "NEO4J_PASSWORD"), ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = driver.Close(context.Background()) }()
	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := neo4j.ExecuteQuery(ctx, driver, "RETURN 1 AS value", nil, neo4j.EagerResultTransformer)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("unexpected Neo4j result: %#v", result)
	}

	client, err := minio.New(requiredEnv(t, "S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(requiredEnv(t, "S3_ACCESS_KEY"), requiredEnv(t, "S3_SECRET_KEY"), ""),
		Secure: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	bucket := requiredEnv(t, "S3_BUCKET")
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatalf("create integration object storage bucket %q: %v", bucket, err)
		}
	}
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
