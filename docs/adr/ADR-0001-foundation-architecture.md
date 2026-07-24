# ADR-0001: Foundation architecture

- Status: Accepted
- Date: 2026-07-24

## Context

CVE Atlas requires a secure, auditable foundation before passive intelligence collectors or vulnerability correlation are added. PostgreSQL must remain the system of record, while Neo4j is a rebuildable graph projection and Redis is not the sole store of business records.

## Decision

1. Use a Go modular monolith for the initial API. Internal package boundaries match future services, but deployment remains simple during the MVP.
2. Use Next.js with TypeScript for the web application.
3. Use PostgreSQL 18 as the system of record, Redis Streams/cache infrastructure, Neo4j Community as graph projection storage, and S3-compatible object storage.
4. Use standards-based OIDC Authorization Code Flow with PKCE. Do not implement password authentication.
5. Keep provider tokens server-side and issue opaque, short-lived, HTTP-only application sessions.
6. Store audit logs in an append-only PostgreSQL table protected by database triggers.
7. Use OpenTelemetry OTLP for traces and metrics and structured JSON logs for application events.
8. Keep the API contract in OpenAPI 3.1 and validate it in CI.
9. Keep local-development secrets outside Git and render Keycloak configuration from environment variables.

## Consequences

- The modular monolith avoids premature distributed-system complexity while preserving module boundaries.
- Login depends on a reachable OIDC provider; local development uses Keycloak.
- Redis loss invalidates active sessions and login transactions but does not destroy business records.
- Neo4j can be rebuilt later from PostgreSQL.
- Active scanning is impossible in this milestone because no scanner service or endpoint exists.
