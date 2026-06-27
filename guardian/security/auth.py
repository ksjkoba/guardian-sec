"""Dashboard API authentication via E2E session tokens."""

from __future__ import annotations

import os
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian.security.session import SessionManager

# Paths reachable without a session token (bootstrap + handshake + login).
# The login/logout endpoints must be reachable before a session exists,
# otherwise a dashboard with both API auth and a password set would deadlock
# (you can't log in to obtain the access token needed to handshake).
_PUBLIC_BASE = frozenset({
    "/api/stats",
    "/api/security/status",
    "/api/security/handshake",
    "/api/security/login",
    "/api/security/logout",
})

# Back-compat alias (local dev); prefer public_api_paths(client_host) in middleware.
PUBLIC_API_PATHS = _PUBLIC_BASE | {"/api/test-alert"}


def test_alert_allowed(client_host: str | None = None) -> bool:
    """Test-alert injection is local-dev only unless explicitly enabled."""
    if os.environ.get("GUARDIAN_DISABLE_TEST_ALERT", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("GUARDIAN_ALLOW_TEST_ALERT", "").lower() in ("1", "true", "yes"):
        return True
    try:
        from guardian.web.deploy import deploy_mode

        if deploy_mode() == "vps":
            return False
    except ImportError:
        pass
    host = (client_host or "").strip().lower()
    if host and host not in ("127.0.0.1", "::1", "localhost"):
        return False
    return True


def public_api_paths(client_host: str | None = None) -> frozenset[str]:
    paths = set(_PUBLIC_BASE)
    if test_alert_allowed(client_host):
        paths.add("/api/test-alert")
    return frozenset(paths)


def api_auth_enabled() -> bool:
    if os.environ.get("GUARDIAN_API_AUTH", "1").lower() in ("0", "false", "no"):
        return False
    try:
        from guardian.security.crypto import has_crypto

        return has_crypto()
    except ImportError:
        return False


def require_e2e_default() -> bool:
    """Sensitive payloads must be encrypted when crypto is available."""
    if os.environ.get("GUARDIAN_ALLOW_PLAINTEXT", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("GUARDIAN_REQUIRE_E2E", "").lower() in ("0", "false", "no"):
        return False
    try:
        from guardian.security.crypto import has_crypto

        return has_crypto()
    except ImportError:
        return False


def verify_request_token(sessions: "SessionManager | None", token: str) -> bool:
    if not token or sessions is None:
        return False
    return sessions.verify_token_any(token)


def constant_time_equal(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
