"""Per-browser E2E session keys via X25519 ECDH + SHA-256 derivation."""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from typing import Any

from guardian.security.crypto import decrypt_bytes, has_crypto, require_crypto

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _HAS_X25519 = True
except ImportError:
    x25519 = None  # type: ignore[assignment]
    hashes = HKDF = None  # type: ignore[misc, assignment]
    Encoding = PublicFormat = None  # type: ignore[misc, assignment]
    _HAS_X25519 = False

SESSION_TTL_SECS = int(os.environ.get("GUARDIAN_SESSION_TTL", "3600"))
HKDF_INFO = b"guardian-e2e-v1"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive_session_key(shared_secret: bytes) -> bytes:
    return HKDF(  # type: ignore[union-attr]
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)


class SessionManager:
    """Manages ephemeral ECDH sessions for encrypted API payloads."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [sid for sid, s in self._sessions.items() if s["expires"] <= now]
        for sid in expired:
            self._sessions.pop(sid, None)

    def handshake(self, client_public_key_b64: str) -> dict[str, Any]:
        require_crypto()
        if not _HAS_X25519:
            raise ImportError("cryptography X25519 support unavailable")

        try:
            client_public = x25519.X25519PublicKey.from_public_bytes(  # type: ignore[union-attr]
                _b64url_decode(client_public_key_b64)
            )
        except Exception as e:
            raise ValueError("invalid client_public_key") from e

        server_private = x25519.X25519PrivateKey.generate()  # type: ignore[union-attr]
        shared = server_private.exchange(client_public)
        session_key = _derive_session_key(shared)
        session_id = secrets.token_urlsafe(16)
        token = secrets.token_urlsafe(32)
        expires = time.time() + SESSION_TTL_SECS

        with self._lock:
            self._purge_expired()
            self._sessions[session_id] = {
                "key": session_key,
                "token": token,
                "expires": expires,
            }

        server_public = server_private.public_key().public_bytes(
            encoding=Encoding.Raw,  # type: ignore[union-attr]
            format=PublicFormat.Raw,  # type: ignore[union-attr]
        )
        return {
            "session_id": session_id,
            "server_public_key": _b64url_encode(server_public),
            "token": token,
            "expires_at": expires,
            "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
            "ttl_secs": SESSION_TTL_SECS,
        }

    def _get(self, session_id: str, token: str) -> bytes:
        with self._lock:
            self._purge_expired()
            session = self._sessions.get(session_id)
            if session is None or session["token"] != token:
                raise PermissionError("invalid or expired session")
            if session["expires"] <= time.time():
                self._sessions.pop(session_id, None)
                raise PermissionError("session expired")
            return session["key"]

    def verify_token(self, session_id: str, token: str) -> bool:
        try:
            self._get(session_id, token)
            return True
        except PermissionError:
            return False

    def verify_token_any(self, token: str) -> bool:
        """Return True if token matches any active session (dashboard API auth)."""
        if not token:
            return False
        import secrets as _secrets

        with self._lock:
            self._purge_expired()
            for session in self._sessions.values():
                if _secrets.compare_digest(session["token"], token):
                    return True
        return False

    def decrypt_payload(self, body: dict[str, Any], token: str) -> dict[str, Any]:
        if not body.get("encrypted"):
            return body
        session_id = str(body.get("session_id", ""))
        iv_b64 = str(body.get("iv", ""))
        data_b64 = str(body.get("data", ""))
        if not session_id or not iv_b64 or not data_b64:
            raise ValueError("encrypted payload missing session_id, iv, or data")

        key = self._get(session_id, token)
        iv = _b64url_decode(iv_b64)
        ciphertext = _b64url_decode(data_b64)
        blob = iv + ciphertext
        plaintext = decrypt_bytes(key, blob, session_id.encode("utf-8"))
        parsed = json.loads(plaintext.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("decrypted payload must be a JSON object")
        return parsed

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._purge_expired()
            active = len(self._sessions)
        return {
            "e2e_available": _HAS_X25519 and has_crypto(),
            "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
            "active_sessions": active,
            "session_ttl_secs": SESSION_TTL_SECS,
            "at_rest": "AES-256-GCM",
        }
