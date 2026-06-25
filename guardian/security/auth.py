"""Dashboard API authentication via E2E session tokens."""

from __future__ import annotations

import os
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian.security.session import SessionManager

# Paths reachable without a session token (localhost bootstrap + handshake)
PUBLIC_API_PATHS = frozenset({
    "/api/stats",
    "/api/security/status",
    "/api/security/handshake",
    "/api/test-alert",  # localhost dev helper (cli test-alert)
})


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
