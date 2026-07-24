package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type LoginFlow struct {
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	ReturnTo     string `json:"return_to"`
}

type Session struct {
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RedisStore struct {
	client       *redis.Client
	loginFlowTTL time.Duration
	sessionTTL   time.Duration
}

func NewRedisStore(client *redis.Client, loginFlowTTL, sessionTTL time.Duration) *RedisStore {
	return &RedisStore{client: client, loginFlowTTL: loginFlowTTL, sessionTTL: sessionTTL}
}

func (s *RedisStore) CreateLoginFlow(ctx context.Context, flow LoginFlow) (string, error) {
	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(flow)
	if err != nil {
		return "", fmt.Errorf("encode login flow: %w", err)
	}
	key := "oidc:flow:" + tokenDigest(state)
	created, err := s.client.SetNX(ctx, key, payload, s.loginFlowTTL).Result()
	if err != nil {
		return "", fmt.Errorf("store login flow: %w", err)
	}
	if !created {
		return "", errors.New("login state collision")
	}
	return state, nil
}

func (s *RedisStore) ConsumeLoginFlow(ctx context.Context, state string) (LoginFlow, error) {
	if state == "" {
		return LoginFlow{}, errors.New("state is empty")
	}
	key := "oidc:flow:" + tokenDigest(state)
	payload, err := s.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return LoginFlow{}, errors.New("login state is invalid, expired, or already used")
	}
	if err != nil {
		return LoginFlow{}, fmt.Errorf("consume login flow: %w", err)
	}
	var flow LoginFlow
	if err := json.Unmarshal(payload, &flow); err != nil {
		return LoginFlow{}, fmt.Errorf("decode login flow: %w", err)
	}
	return flow, nil
}

func (s *RedisStore) CreateSession(ctx context.Context, userID, tenantID string) (string, Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", Session{}, err
	}
	now := time.Now().UTC()
	session := Session{UserID: userID, TenantID: tenantID, CreatedAt: now, ExpiresAt: now.Add(s.sessionTTL)}
	payload, err := json.Marshal(session)
	if err != nil {
		return "", Session{}, fmt.Errorf("encode session: %w", err)
	}
	key := "session:" + tokenDigest(token)
	created, err := s.client.SetNX(ctx, key, payload, s.sessionTTL).Result()
	if err != nil {
		return "", Session{}, fmt.Errorf("store session: %w", err)
	}
	if !created {
		return "", Session{}, errors.New("session token collision")
	}
	return token, session, nil
}

func (s *RedisStore) GetSession(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, errors.New("session token is empty")
	}
	payload, err := s.client.Get(ctx, "session:"+tokenDigest(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, errors.New("session not found")
	}
	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	var session Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return Session{}, fmt.Errorf("decode session: %w", err)
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = s.DeleteSession(ctx, token)
		return Session{}, errors.New("session expired")
	}
	return session, nil
}

func (s *RedisStore) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if err := s.client.Del(ctx, "session:"+tokenDigest(token)).Err(); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
