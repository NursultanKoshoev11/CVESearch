package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/NursultanKoshoev11/CVESearch/packages/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	ID           uuid.UUID      `json:"id"`
	OccurredAt   time.Time      `json:"occurred_at"`
	ActorID      *uuid.UUID     `json:"actor_id,omitempty"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID     `json:"resource_id,omitempty"`
	Result       string         `json:"result"`
	RequestID    string         `json:"request_id,omitempty"`
	Metadata     map[string]any `json:"metadata"`
}

type Repository struct {
	pool      *pgxpool.Pool
	ipHashKey []byte
}

func NewRepository(pool *pgxpool.Pool, ipHashKey string) *Repository {
	return &Repository{pool: pool, ipHashKey: []byte(ipHashKey)}
}

func (r *Repository) Append(ctx context.Context, event Event, remoteAddress string) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	ipHash := r.hashRemoteAddress(remoteAddress)
	return database.WithTenantTx(ctx, r.pool, event.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO audit_logs (
				actor_id, tenant_id, action, resource_type, resource_id,
				result, request_id, ip_address_hash, metadata
			) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9::jsonb)`,
			event.ActorID, event.TenantID, event.Action, event.ResourceType, event.ResourceID,
			event.Result, event.RequestID, ipHash, metadata)
		if err != nil {
			return fmt.Errorf("append audit event: %w", err)
		}
		return nil
	})
}

func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]Event, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	events := make([]Event, 0, limit)
	err := database.WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, occurred_at, actor_id, tenant_id, action,
			       COALESCE(resource_type, ''), resource_id, result,
			       COALESCE(request_id, ''), metadata
			FROM audit_logs
			WHERE tenant_id = $1
			ORDER BY occurred_at DESC, id DESC
			LIMIT $2 OFFSET $3`, tenantID, limit, offset)
		if err != nil {
			return fmt.Errorf("query audit events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var event Event
			var metadata []byte
			if err := rows.Scan(&event.ID, &event.OccurredAt, &event.ActorID, &event.TenantID,
				&event.Action, &event.ResourceType, &event.ResourceID, &event.Result,
				&event.RequestID, &metadata); err != nil {
				return fmt.Errorf("scan audit event: %w", err)
			}
			if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
				return fmt.Errorf("decode audit metadata: %w", err)
			}
			events = append(events, event)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (r *Repository) hashRemoteAddress(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	mac := hmac.New(sha256.New, r.ipHashKey)
	_, _ = mac.Write([]byte(ip.String()))
	return hex.EncodeToString(mac.Sum(nil))
}
