package platform

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type HealthCheck func(context.Context) error

type DependencyStatus struct {
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
}

type ReadinessResult struct {
	Status       string                      `json:"status"`
	CheckedAt    time.Time                   `json:"checked_at"`
	Dependencies map[string]DependencyStatus `json:"dependencies"`
}

type HealthChecker struct {
	timeout time.Duration
	checks  map[string]HealthCheck
}

func NewHealthChecker(timeout time.Duration, checks map[string]HealthCheck) *HealthChecker {
	return &HealthChecker{timeout: timeout, checks: checks}
}

func (h *HealthChecker) Check(ctx context.Context) (ReadinessResult, error) {
	result := ReadinessResult{
		Status: "ready", CheckedAt: time.Now().UTC(),
		Dependencies: make(map[string]DependencyStatus, len(h.checks)),
	}
	type outcome struct {
		name   string
		status DependencyStatus
		err    error
	}
	outcomes := make(chan outcome, len(h.checks))
	var wg sync.WaitGroup
	for name, check := range h.checks {
		name, check := name, check
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			checkCtx, cancel := context.WithTimeout(ctx, h.timeout)
			defer cancel()
			err := check(checkCtx)
			status := "ok"
			if err != nil {
				status = "unavailable"
			}
			outcomes <- outcome{name: name, status: DependencyStatus{Status: status, LatencyMS: time.Since(started).Milliseconds()}, err: err}
		}()
	}
	wg.Wait()
	close(outcomes)

	var failed []string
	for item := range outcomes {
		result.Dependencies[item.name] = item.status
		if item.err != nil {
			failed = append(failed, item.name)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		result.Status = "not_ready"
		return result, fmt.Errorf("dependencies unavailable: %v", failed)
	}
	return result, nil
}
