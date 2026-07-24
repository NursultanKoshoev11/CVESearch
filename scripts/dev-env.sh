#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET="$ROOT_DIR/.env"
EXAMPLE="$ROOT_DIR/.env.example"

if [ -e "$TARGET" ] && [ "${1:-}" != "--force" ]; then
  echo "$TARGET already exists. Use --force to replace it." >&2
  exit 1
fi

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required to generate local secrets." >&2
  exit 1
}

random_hex() { openssl rand -hex "$1"; }

POSTGRES_SUPERUSER_PASSWORD=$(random_hex 24)
POSTGRES_APP_PASSWORD=$(random_hex 24)
NEO4J_PASSWORD=$(random_hex 24)
MINIO_ACCESS_KEY=$(random_hex 12)
MINIO_SECRET_KEY=$(random_hex 32)
KEYCLOAK_ADMIN_PASSWORD=$(random_hex 24)
OIDC_CLIENT_SECRET=$(random_hex 32)
AUDIT_IP_HASH_KEY=$(random_hex 32)
KEYCLOAK_TEST_PASSWORD=$(random_hex 18)

sed \
  -e "s|CHANGE_ME_RANDOM_32_BYTE_OR_LONGER_VALUE|$AUDIT_IP_HASH_KEY|g" \
  -e "s|CHANGE_ME_POSTGRES_SUPERUSER_PASSWORD|$POSTGRES_SUPERUSER_PASSWORD|g" \
  -e "s|CHANGE_ME_POSTGRES_APP_PASSWORD|$POSTGRES_APP_PASSWORD|g" \
  -e "s|CHANGE_ME_NEO4J_PASSWORD|$NEO4J_PASSWORD|g" \
  -e "s|CHANGE_ME_MINIO_ACCESS_KEY|$MINIO_ACCESS_KEY|g" \
  -e "s|CHANGE_ME_MINIO_SECRET_KEY|$MINIO_SECRET_KEY|g" \
  -e "s|CHANGE_ME_KEYCLOAK_ADMIN_PASSWORD|$KEYCLOAK_ADMIN_PASSWORD|g" \
  -e "s|CHANGE_ME_OIDC_CLIENT_SECRET|$OIDC_CLIENT_SECRET|g" \
  -e "s|CHANGE_ME_KEYCLOAK_TEST_PASSWORD|$KEYCLOAK_TEST_PASSWORD|g" \
  "$EXAMPLE" > "$TARGET"
chmod 600 "$TARGET"

echo "Created $TARGET with mode 0600."
echo "Local analyst username: analyst"
echo "Local analyst password: $KEYCLOAK_TEST_PASSWORD"
