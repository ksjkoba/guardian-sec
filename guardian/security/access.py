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
import json
import os
import secrets
import threading
import time

ACCESS_TTL_SECS = int(os.environ.get("GUARDIAN_ACCESS_TTL", "86400"))  # 24h default
# Cap on stored access tokens so a flood of login attempts can't grow memory
# unbounded. Oldest tokens are evicted first.
MAX_ACCESS_TOKENS = 256

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "unknown", ""})


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


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


def _throttle_loopback_exempt() -> bool:
    """Loopback clients skip throttling unless explicitly opted in."""
    return os.environ.get("GUARDIAN_LOGIN_THROTTLE_LOCAL", "").lower() not in (
        "1", "true", "yes", "on",
    )


class LoginThrottle:
    """Per-client brute-force throttle for the dashboard login endpoint.

    After ``max_failures`` failed attempts within ``window_secs``, the client is
    locked out for ``lockout_secs``. A successful login clears the client's
    failure record. Loopback clients are exempt by default (a local operator
    fat-fingering the password shouldn't lock themselves out) unless
    ``GUARDIAN_LOGIN_THROTTLE_LOCAL=1``.

    Config:
      GUARDIAN_LOGIN_MAX_FAILURES   failures before lockout (default 5)
      GUARDIAN_LOGIN_LOCKOUT_SECS   lockout duration in seconds (default 300)
      GUARDIAN_LOGIN_WINDOW_SECS    window over which failures accumulate (default 900)
    """

    def __init__(
        self,
        max_failures: int | None = None,
        lockout_secs: int | None = None,
        window_secs: int | None = None,
    ) -> None:
        self.max_failures = max_failures if max_failures is not None else _env_int(
            "GUARDIAN_LOGIN_MAX_FAILURES", 5, minimum=1
        )
        self.lockout_secs = lockout_secs if lockout_secs is not None else _env_int(
            "GUARDIAN_LOGIN_LOCKOUT_SECS", 300, minimum=1
        )
        self.window_secs = window_secs if window_secs is not None else _env_int(
            "GUARDIAN_LOGIN_WINDOW_SECS", 900, minimum=1
        )
        # client -> {"fails": [timestamps], "until": lockout_expiry}
        self._state: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _exempt(self, client: str) -> bool:
        return client in _LOOPBACK and _throttle_loopback_exempt()

    def locked_for(self, client: str, now: float | None = None) -> float:
        """Seconds remaining on a lockout for ``client`` (0.0 if not locked)."""
        if self._exempt(client):
            return 0.0
        now = now or time.time()
        with self._lock:
            rec = self._state.get(client)
            if not rec:
                return 0.0
            remaining = rec.get("until", 0.0) - now
            return remaining if remaining > 0 else 0.0

    def is_locked(self, client: str) -> bool:
        return self.locked_for(client) > 0.0

    def record_failure(self, client: str, now: float | None = None) -> float:
        """Record a failed attempt. Returns lockout seconds remaining (0 if none)."""
        if self._exempt(client):
            return 0.0
        now = now or time.time()
        with self._lock:
            rec = self._state.setdefault(client, {"fails": [], "until": 0.0})
            # Drop failures outside the sliding window.
            rec["fails"] = [t for t in rec["fails"] if now - t < self.window_secs]
            rec["fails"].append(now)
            if len(rec["fails"]) >= self.max_failures:
                rec["until"] = now + self.lockout_secs
                rec["fails"] = []  # reset the counter while locked out
                return self.lockout_secs
            existing = rec.get("until", 0.0) - now
            return existing if existing > 0 else 0.0

    def record_success(self, client: str) -> None:
        """Clear a client's failure record after a successful login."""
        with self._lock:
            self._state.pop(client, None)

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


def _audit_log_path():
    from guardian.security.vault import data_dir

    return data_dir() / "audit.log"


def log_login_event(event: str, client: str, *, detail: str = "") -> None:
    """Append a login-related event to the audit log (best-effort, never raises).

    Events: ``login_success``, ``login_failure``, ``login_lockout``,
    ``logout``. The audit log is an append-only JSONL file at
    ``<data_dir>/audit.log`` so an operator can review access attempts.
    """
    record = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "event": event,
        "client": client or "unknown",
    }
    if detail:
        record["detail"] = detail
    try:
        path = _audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        # Auditing must never break authentication.
        pass
