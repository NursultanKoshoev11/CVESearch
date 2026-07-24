# CVE Atlas Foundation Architecture

CVE Atlas is passive by default. Milestone 0 establishes the platform foundation only; it contains no regional discovery, Censys integration, RIPEstat integration, scanners, exploit code, or vulnerability correlation.

## Runtime components

- **Web**: Next.js application. It never receives OIDC client secrets or database credentials.
- **API**: Go REST service. It owns authentication callbacks, session management, authorization, audit logging, and health checks.
- **PostgreSQL**: system of record for tenants, users, roles, permissions, and immutable audit events.
- **Redis**: one-time OIDC login transactions and server-side sessions.
- **Neo4j**: graph projection store. Milestone 0 checks connectivity but does not project domain entities.
- **MinIO**: S3-compatible object storage. Milestone 0 verifies the configured bucket and creates it at startup when absent.
- **Keycloak**: local-development OIDC provider only. Production deployments must use an approved OIDC provider.
- **OpenTelemetry Collector**: receives OTLP traces and metrics from the API.

## Trust boundaries

1. The browser communicates with the API over HTTPS in production.
2. The API performs OIDC code exchange server-side using Authorization Code Flow, PKCE, state, and nonce.
3. The browser receives only a random HTTP-only session cookie. Provider tokens are not exposed to frontend JavaScript.
4. Redis stores login transactions and sessions under SHA-256-derived keys with expiration.
5. PostgreSQL audit events are append-only; update and delete operations are rejected by database triggers.
6. Authorization checks combine authenticated principal, tenant, role-derived permissions, and requested operation.

## Data flow for login

1. `GET /api/v1/auth/login` creates state, nonce, and PKCE verifier.
2. The transaction is stored in Redis and the browser is redirected to the OIDC provider.
3. `GET /api/v1/auth/callback` atomically consumes the state, exchanges the code, validates issuer, audience, nonce, and PKCE, then upserts the user.
4. OIDC groups are mapped to internal roles. Unmapped users receive only the configured safe default role.
5. A server-side session is created and a `login.success` audit event is appended.

## Milestone boundary

Authorized validation and all collector workers are explicitly outside Milestone 0. They must not be introduced until their milestones and scope-guard requirements are implemented.
