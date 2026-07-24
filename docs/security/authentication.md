# Authentication and authorization

## Authentication

CVE Atlas uses OpenID Connect Authorization Code Flow with PKCE (`S256`), state, and nonce. The API performs token exchange and ID-token validation. No password database or password login endpoint exists in CVE Atlas.

The web session is opaque and server-side:

- the cookie is `HttpOnly`;
- `SameSite=Lax` protects the OIDC redirect flow while limiting cross-site requests;
- `Secure=true` is mandatory outside local HTTP development;
- the cookie value is random and only its SHA-256 digest is used in the Redis key;
- logout deletes the Redis session before clearing the browser cookie.

## Role mapping

OIDC group claims are mapped to internal roles through `OIDC_ROLE_GROUP_MAPPINGS`. The safe default is `public_user`. Unknown groups do not grant permissions.

## Authorization

Route handlers declare required permissions. The authorization middleware loads the current user, tenant, roles, and permissions from PostgreSQL for every authenticated request. A role name alone is never treated as sufficient authorization.

## Local Keycloak

The repository contains an idempotent Keycloak Admin REST initializer, not a realm export with embedded credentials. `scripts/dev-env.sh` generates local secrets into the ignored `.env` file. At startup, `keycloak-init` creates the realm, confidential OIDC client, groups, and one local analyst account using those environment values. Direct Access Grants are disabled for the application client.
