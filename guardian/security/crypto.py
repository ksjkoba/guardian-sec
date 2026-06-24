"""AES-256-GCM encryption helpers."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAS_CRYPTO = True
except ImportError:
    AESGCM = None  # type: ignore[misc, assignment]
    _HAS_CRYPTO = False

NONCE_SIZE = 12
KEY_SIZE = 32


def has_crypto() -> bool:
    return _HAS_CRYPTO


def require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise ImportError(
            "The cryptography package is required for Guardian encryption.\n"
            "Run: pip install 'guardian-sec[web]'  or  pip install cryptography"
        )


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    require_crypto()
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256-GCM requires a {KEY_SIZE}-byte key")
    nonce = os.urandom(NONCE_SIZE)
    aes = AESGCM(key)
    return nonce + aes.encrypt(nonce, plaintext, associated_data)


def decrypt_bytes(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    require_crypto()
    if len(blob) < NONCE_SIZE + 16:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, associated_data)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def encrypt_text(key: bytes, text: str, *, aad: str = "") -> str:
    aad_bytes = aad.encode("utf-8") if aad else b""
    return _b64url_encode(encrypt_bytes(key, text.encode("utf-8"), aad_bytes))


def decrypt_text(key: bytes, token: str, *, aad: str = "") -> str:
    aad_bytes = aad.encode("utf-8") if aad else b""
    return decrypt_bytes(key, _b64url_decode(token), aad_bytes).decode("utf-8")


def encrypt_json(key: bytes, obj: Any, *, aad: str = "") -> str:
    return encrypt_text(key, json.dumps(obj, separators=(",", ":"), ensure_ascii=False), aad=aad)


def decrypt_json(key: bytes, token: str, *, aad: str = "") -> Any:
    return json.loads(decrypt_text(key, token, aad=aad))
