"""Decrypt sensitive API request bodies."""

from __future__ import annotations

from typing import Any

from guardian.security.auth import require_e2e_default
from guardian.security.session import SessionManager

SENSITIVE_ROUTES = frozenset({
    "/api/breach/check",
    "/api/breach/watchlist",
    "/api/breach/password-check",
    "/api/breach/password-range",
})


def unwrap_sensitive_body(
    body: dict[str, Any],
    *,
    path: str,
    token: str,
    sessions: SessionManager,
) -> dict[str, Any]:
    """Return plaintext JSON body, decrypting when the client sent an E2E envelope."""
    if not body.get("encrypted"):
        if require_e2e_default() and path in SENSITIVE_ROUTES:
            raise PermissionError("encrypted payload required — reload dashboard to establish secure session")
        return body
    if not token:
        raise PermissionError("X-Guardian-Session header required for encrypted payloads")
    return sessions.decrypt_payload(body, token)
