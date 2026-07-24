#!/usr/bin/env sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

[ -f .env ] || {
  echo '.env is missing; run ./scripts/dev-env.sh first.' >&2
  exit 1
}

set -a
# shellcheck disable=SC1091
. ./.env
set +a

docker compose up -d --wait postgres redis neo4j minio
docker compose run --rm migrate

export DATABASE_URL="postgres://${POSTGRES_APP_USER}:${POSTGRES_APP_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}?sslmode=disable"
export REDIS_URL="redis://127.0.0.1:6379/0"
export NEO4J_URI="neo4j://127.0.0.1:7687"
export S3_ENDPOINT="127.0.0.1:9000"

go test -tags=integration -count=1 ./tests/integration/...
