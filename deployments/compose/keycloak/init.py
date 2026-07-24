#!/usr/bin/env python3
"""Idempotently provision the local CVE Atlas Keycloak realm through Admin REST."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

BASE_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak.localhost:8081").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "cve-atlas")
ADMIN = os.environ["KEYCLOAK_ADMIN"]
ADMIN_PASSWORD = os.environ["KEYCLOAK_ADMIN_PASSWORD"]
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
REDIRECT_URI = os.environ["OIDC_REDIRECT_URL"]
WEB_ORIGIN = os.environ["WEB_ORIGIN"]
TEST_USER = os.environ["KEYCLOAK_TEST_USER"]
TEST_PASSWORD = os.environ["KEYCLOAK_TEST_PASSWORD"]
TEST_EMAIL = os.environ.get("KEYCLOAK_TEST_EMAIL", "analyst@cve-atlas.local")


def request(method: str, path: str, *, token: str | None = None, body: Any | None = None,
            form: dict[str, str] | None = None, expected: tuple[int, ...] = (200, 201, 204)) -> Any:
    url = f"{BASE_URL}{path}"
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read()
            if response.status not in expected:
                raise RuntimeError(f"unexpected HTTP {response.status} for {method} {path}")
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode(errors="replace")
        if exc.code in expected:
            return json.loads(payload) if payload else None
        raise RuntimeError(f"Keycloak {method} {path} failed with HTTP {exc.code}: {payload}") from exc


def wait_for_keycloak() -> None:
    for attempt in range(90):
        try:
            request("GET", "/realms/master/.well-known/openid-configuration")
            return
        except Exception as exc:  # noqa: BLE001 - startup retry boundary
            if attempt == 89:
                raise RuntimeError("Keycloak did not become ready") from exc
            time.sleep(2)


def admin_token() -> str:
    response = request(
        "POST",
        "/realms/master/protocol/openid-connect/token",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN,
            "password": ADMIN_PASSWORD,
        },
    )
    return str(response["access_token"])


def find_one(token: str, path: str, key: str, value: str) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({key: value, "exact": "true"})
    items = request("GET", f"{path}?{query}", token=token)
    for item in items:
        if item.get(key) == value:
            return item
    return None


def ensure_realm(token: str) -> None:
    try:
        request("GET", f"/admin/realms/{REALM}", token=token)
    except RuntimeError as exc:
        if "HTTP 404" not in str(exc):
            raise
        request(
            "POST",
            "/admin/realms",
            token=token,
            body={
                "realm": REALM,
                "enabled": True,
                "sslRequired": "external",
                "registrationAllowed": False,
                "resetPasswordAllowed": True,
                "loginWithEmailAllowed": True,
                "duplicateEmailsAllowed": False,
                "bruteForceProtected": True,
                "permanentLockout": False,
                "failureFactor": 5,
                "waitIncrementSeconds": 60,
                "maxFailureWaitSeconds": 900,
                "rememberMe": False,
            },
        )


def ensure_client(token: str) -> None:
    path = f"/admin/realms/{REALM}/clients"
    client = find_one(token, path, "clientId", CLIENT_ID)
    payload = {
        "clientId": CLIENT_ID,
        "name": "CVE Atlas Web",
        "enabled": True,
        "publicClient": False,
        "secret": CLIENT_SECRET,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "implicitFlowEnabled": False,
        "frontchannelLogout": True,
        "redirectUris": [REDIRECT_URI],
        "postLogoutRedirectUris": [WEB_ORIGIN, f"{WEB_ORIGIN}/*"],
        "webOrigins": [WEB_ORIGIN],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": f"{WEB_ORIGIN}##{WEB_ORIGIN}/*",
        },
        "protocol": "openid-connect",
        "protocolMappers": [
            {
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": False,
                "config": {
                    "full.path": "true",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                    "claim.name": "groups",
                },
            }
        ],
    }
    if client is None:
        request("POST", path, token=token, body=payload)
    else:
        request("PUT", f"{path}/{client['id']}", token=token, body={**client, **payload})


def ensure_group(token: str, name: str) -> str:
    path = f"/admin/realms/{REALM}/groups"
    query = urllib.parse.urlencode({"search": name, "exact": "true"})
    groups = request("GET", f"{path}?{query}", token=token)
    for item in groups:
        if item.get("name") == name:
            return str(item["id"])
    request("POST", path, token=token, body={"name": name})
    groups = request("GET", f"{path}?{query}", token=token)
    for item in groups:
        if item.get("name") == name:
            return str(item["id"])
    raise RuntimeError(f"failed to create Keycloak group {name}")


def ensure_user(token: str, analyst_group_id: str) -> None:
    path = f"/admin/realms/{REALM}/users"
    user = find_one(token, path, "username", TEST_USER)
    payload = {
        "username": TEST_USER,
        "email": TEST_EMAIL,
        "emailVerified": True,
        "enabled": True,
        "firstName": "Local",
        "lastName": "Analyst",
        "requiredActions": [],
    }
    if user is None:
        request("POST", path, token=token, body=payload)
        user = find_one(token, path, "username", TEST_USER)
    else:
        request("PUT", f"{path}/{user['id']}", token=token, body={**user, **payload})
    if user is None:
        raise RuntimeError("failed to provision local analyst user")
    user_id = str(user["id"])
    request(
        "PUT",
        f"{path}/{user_id}/reset-password",
        token=token,
        body={"type": "password", "value": TEST_PASSWORD, "temporary": False},
    )
    request("PUT", f"{path}/{user_id}/groups/{analyst_group_id}", token=token)


def main() -> int:
    wait_for_keycloak()
    token = admin_token()
    ensure_realm(token)
    ensure_client(token)
    group_ids = {name: ensure_group(token, name) for name in ("super-administrators", "platform-analysts", "auditors")}
    ensure_user(token, group_ids["platform-analysts"])
    print("Keycloak realm, OIDC client, groups, and local analyst are ready.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - command boundary
        print(f"Keycloak initialization failed: {exc}", file=sys.stderr)
        raise
