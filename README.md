# CVE Atlas

CVE Atlas is an External Attack Surface Management, Cyber Asset Intelligence, and Vulnerability Intelligence platform designed to help organizations identify and remediate publicly observable risk without publishing an open catalogue of precise vulnerable assets.

This repository currently implements **Milestone 0 — Foundation**. It deliberately contains no RIPEstat or Censys collectors, DNS/CT discovery, vulnerability correlation, scanner, exploit logic, password attacks, or active requests to arbitrary external targets.

## Authoritative specification

The original uploaded `CVE Atlas.docx` is preserved byte-for-byte in `docs/specification/source-archive/`. The initial repository connector accepted UTF-8 files but not a direct binary DOCX write, so the verified source archive is stored as text-safe parts.

Materialize and verify the unchanged document:

```bash
./scripts/materialize-spec.sh
make verify-spec
```

The reconstructed file is written to `.runtime/specification/CVE Atlas.docx`. Its SHA-256 is:

```text
d2c81279d40c22961438fbc804311c444ae01574ad61766617f32210c180329e
```

Every coding agent must follow `AGENTS.md` and read the complete materialized DOCX before changing the project.

## Implemented foundation

- Go REST API under `/api/v1/` with OpenAPI 3.1.
- Liveness and dependency-readiness endpoints.
- Structured JSON logging, request IDs, panic recovery, CORS, same-origin checks, and security headers.
- OpenTelemetry traces and metrics over OTLP/HTTP.
- OIDC Authorization Code Flow with PKCE, state, nonce, issuer, audience, and ID-token verification.
- Opaque server-side Redis sessions with HTTP-only cookies.
- PostgreSQL-backed users, roles, permissions, tenant isolation, and row-level security.
- Append-only audit logging protected by database triggers.
- Next.js/TypeScript frontend using the real API.
- PostgreSQL, Redis, Neo4j, MinIO, Keycloak, and OpenTelemetry Collector in Docker Compose.
- Unit tests, integration tests, frontend checks, OpenAPI validation, container builds, and full-stack smoke checks in CI.

## Local startup

Requirements: Docker Engine with Compose v2 and OpenSSL.

```bash
./scripts/dev-env.sh
make dev
```

The environment script generates random local secrets in ignored file `.env` with mode `0600` and prints the local analyst password once.

Open:

- Web: `http://localhost:3000`
- API liveness: `http://localhost:8080/health/live`
- API readiness: `http://localhost:8080/health/ready`
- Local Keycloak: `http://keycloak.localhost:8081`

Stop the stack:

```bash
make down
```

Remove all local state:

```bash
docker compose down --volumes --remove-orphans
```

## Development checks

```bash
make verify-spec
make fmt
make lint
make test
make test-integration
make openapi-validate
make compose-config
```

## Foundation API

| Method | Endpoint | Access |
|---|---|---|
| GET | `/health/live` | Public |
| GET | `/health/ready` | Public |
| GET | `/api/v1/auth/login` | Public; starts OIDC |
| GET | `/api/v1/auth/callback` | Public; OIDC callback |
| GET | `/api/v1/auth/me` | Authenticated |
| POST | `/api/v1/auth/logout` | Authenticated and same-origin |
| GET | `/api/v1/audit-events` | Requires `audit.read` |

The API contract is `docs/api/openapi.yaml`.

## Security boundaries

- CVE Atlas has no password-authentication endpoint.
- OIDC client secrets and provider tokens never reach frontend JavaScript.
- Unknown OIDC groups receive only the configured safe default role.
- Effective roles and permissions are reloaded from PostgreSQL for authenticated requests.
- State-changing browser requests require the configured origin.
- Audit rows cannot be updated or deleted by the application role.
- PostgreSQL is the system of record; Neo4j is a rebuildable projection.
- Redis loss invalidates sessions but does not destroy business records.
- Authorized validation does not exist in Milestone 0 and must not be added before verified ownership, approved scope, and a scope guard.

## Repository layout

```text
apps/api/                  Go API
apps/web/                  Next.js frontend
internal/auth/             OIDC, sessions, principals, RBAC
internal/audit/            append-only audit repository
internal/platform/         configuration and HTTP middleware
packages/database/         PostgreSQL and tenant transactions
packages/observability/    OpenTelemetry setup
packages/platform/         API errors and health primitives
migrations/                versioned PostgreSQL migrations
deployments/compose/       local infrastructure initialization
docs/                      specification, API, ADR, security, operations
scripts/                   deterministic setup and verification commands
tests/integration/         live dependency integration tests
```

Worker applications and domain collectors are added only in their approved milestones; empty production stubs are intentionally not committed.
