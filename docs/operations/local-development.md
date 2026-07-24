# Local development runbook

## Bootstrap

1. Run `./scripts/dev-env.sh`.
2. Store the printed analyst password in a local password manager if needed.
3. Run `make verify-spec`.
4. Run `docker compose config --quiet`.
5. Run `make dev`.

The compose startup order is enforced through health and completion dependencies: PostgreSQL role creation, migrations, Keycloak Admin REST provisioning, dependency health, API readiness, then web startup.

## Health verification

```bash
curl --fail --silent http://localhost:8080/health/live
curl --fail --silent http://localhost:8080/health/ready
```

Readiness requires PostgreSQL, Redis, Neo4j, and the configured S3 bucket.

## Logs

```bash
make logs
```

Application logs are JSON. Request logs include request ID, method, path, status, response bytes, and duration; they do not include credentials or session cookies.

## Reset

```bash
docker compose down --volumes --remove-orphans
rm -f .env
./scripts/dev-env.sh
make dev
```

This removes all local development state and rotates all generated secrets.
