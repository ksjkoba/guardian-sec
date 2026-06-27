"""Dashboard access control — a password gate in front of the E2E handshake.

Guardian's E2E session handshake provides *payload encryption*, not *access
control*: anyone who can reach the public handshake endpoint can complete it and
obtain a session token. That is fine for a loopback-only personal dashboard, but
not for anything network-exposed.

This module adds a real authentication gate. When the operator sets a dashboard
password, a client must prove knowledge of it (via ``/api/security/login``)
before any session is issued or any ``/api/*`` route is served. On success the
server hands back a short-lived, random **access token** that the browser sends
on every subsequent request (header ``X-Guardian-Access``) and on the WebSocket
upgrade. Tokens are stored server-side with a TTL and compared in constant time.

Configuration (operator picks one):
  GUARDIAN_DASHBOARD_PASSWORD       plaintext password (simplest)
  GUARDIAN_DASHBOARD_PASSWORD_HASH  sha256 hex of the password (preferred — keeps
                                    the plaintext out of the environment/process
                                    listing). Compute with:
                                        python -c "import hashlib,getpass; \
                                        print(hashlib.sha256(getpass.getpass().encode()).hexdigest())"

When neither is set, login is disabled and behavior is unchanged (no friction
for local use). The serve command warns when a dashboard is bound to a
non-loopback interface without a password set.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time

ACCESS_TTL_SECS = int(os.environ.get("GUARDIAN_ACCESS_TTL", "86400"))  # 24h default
# Cap on stored access tokens so a flood of login attempts can't grow memory
# unbounded. Oldest tokens are evicted first.
MAX_ACCESS_TOKENS = 256


def _configured_password_hash() -> str | None:
    """Return the sha256-hex of the configured password, or None if login is off."""
    explicit_hash = os.environ.get("GUARDIAN_DASHBOARD_PASSWORD_HASH", "").strip().lower()
    if explicit_hash:
        return explicit_hash
    plaintext = os.environ.get("GUARDIAN_DASHBOARD_PASSWORD", "")
    if plaintext:
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return None


def login_required() -> bool:
    """True when a dashboard password is configured (login gate is active)."""
    return _configured_password_hash() is not None


def verify_password(candidate: str) -> bool:
    """Constant-time check of a submitted password against the configured one."""
    expected = _configured_password_hash()
    if expected is None:
        return False
    got = hashlib.sha256((candidate or "").encode("utf-8")).hexdigest()
    return secrets.compare_digest(got, expected)


class AccessManager:
    """Issues and validates short-lived access tokens after password login."""

    def __init__(self, ttl_secs: int = ACCESS_TTL_SECS) -> None:
        self._ttl = ttl_secs
        self._tokens: dict[str, float] = {}  # token -> expires_at
        self._lock = threading.Lock()

    def _purge_expired(self, now: float | None = None) -> None:
        now = now or time.time()
        expired = [t for t, exp in self._tokens.items() if exp <= now]
        for t in expired:
            self._tokens.pop(t, None)

    def issue(self) -> tuple[str, float]:
        """Mint a new access token. Returns (token, expires_at)."""
        token = secrets.token_urlsafe(32)
        expires = time.time() + self._ttl
        with self._lock:
            self._purge_expired()
            # Bound memory: evict oldest if we're at the cap.
            if len(self._tokens) >= MAX_ACCESS_TOKENS:
                oldest = min(self._tokens, key=self._tokens.get)  # type: ignore[arg-type]
                self._tokens.pop(oldest, None)
            self._tokens[token] = expires
        return token, expires

    def verify(self, token: str) -> bool:
        """Constant-time validity check for an access token."""
        if not token:
            return False
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            # Constant-time compare against each stored token so a present/absent
            # token isn't distinguishable by timing.
            valid = False
            for stored in self._tokens:
                if secrets.compare_digest(stored, token):
                    valid = True
            return valid

    def revoke(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)

    def active_count(self) -> int:
        with self._lock:
            self._purge_expired()
            return len(self._tokens)
