package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Identity struct {
	Issuer            string
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
	Groups            []string
}

type Provider interface {
	AuthorizationURL(state, nonce, codeChallenge string) string
	ExchangeAndVerify(ctx context.Context, code, codeVerifier, expectedNonce string) (Identity, error)
	LogoutURL() string
}

type OIDCProvider struct {
	issuer           string
	browserAuthURL   string
	browserLogoutURL string
	oauthConfig      oauth2.Config
	verifier         *oidc.IDTokenVerifier
}

type OIDCProviderConfig struct {
	IssuerURL        string
	BrowserAuthURL   string
	BrowserLogoutURL string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
}

func NewOIDCProvider(ctx context.Context, cfg OIDCProviderConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, errors.New("OIDC client ID, secret, and redirect URL are required")
	}
	logoutURL := cfg.BrowserLogoutURL
	if logoutURL == "" {
		var metadata struct {
			EndSessionEndpoint string `json:"end_session_endpoint"`
		}
		if err := provider.Claims(&metadata); err == nil {
			logoutURL = metadata.EndSessionEndpoint
		}
	}
	return &OIDCProvider{
		issuer:           cfg.IssuerURL,
		browserAuthURL:   cfg.BrowserAuthURL,
		browserLogoutURL: logoutURL,
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

func (p *OIDCProvider) AuthorizationURL(state, nonce, codeChallenge string) string {
	cfg := p.oauthConfig
	if p.browserAuthURL != "" {
		cfg.Endpoint.AuthURL = p.browserAuthURL
	}
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *OIDCProvider) ExchangeAndVerify(ctx context.Context, code, codeVerifier, expectedNonce string) (Identity, error) {
	if code == "" || codeVerifier == "" || expectedNonce == "" {
		return Identity{}, errors.New("OIDC callback is missing required values")
	}
	token, err := p.oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, errors.New("OIDC token response did not contain id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify ID token: %w", err)
	}
	var claims struct {
		Nonce             string   `json:"nonce"`
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("decode ID token claims: %w", err)
	}
	if claims.Nonce != expectedNonce {
		return Identity{}, errors.New("OIDC nonce mismatch")
	}
	if idToken.Subject == "" {
		return Identity{}, errors.New("OIDC subject is empty")
	}
	return Identity{
		Issuer:            p.issuer,
		Subject:           idToken.Subject,
		Email:             strings.TrimSpace(claims.Email),
		EmailVerified:     claims.EmailVerified,
		Name:              strings.TrimSpace(claims.Name),
		PreferredUsername: strings.TrimSpace(claims.PreferredUsername),
		Groups:            claims.Groups,
	}, nil
}

func (p *OIDCProvider) LogoutURL() string {
	if p.browserLogoutURL == "" {
		return ""
	}
	if _, err := url.ParseRequestURI(p.browserLogoutURL); err != nil {
		return ""
	}
	return p.browserLogoutURL
}
