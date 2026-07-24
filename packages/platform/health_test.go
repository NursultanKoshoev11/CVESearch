package platform

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHealthCheckerReportsReady(t *testing.T) {
	checker := NewHealthChecker(time.Second, map[string]HealthCheck{
		"database": func(context.Context) error { return nil },
	})
	result, err := checker.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ready" || result.Dependencies["database"].Status != "ok" {
		t.Fatalf("unexpected readiness result: %#v", result)
	}
}

func TestHealthCheckerReportsUnavailableDependency(t *testing.T) {
	checker := NewHealthChecker(time.Second, map[string]HealthCheck{
		"database": func(context.Context) error { return errors.New("down") },
	})
	result, err := checker.Check(context.Background())
	if err == nil {
		t.Fatal("expected readiness failure")
	}
	if result.Status != "not_ready" || result.Dependencies["database"].Status != "unavailable" {
		t.Fatalf("unexpected readiness result: %#v", result)
	}
}
