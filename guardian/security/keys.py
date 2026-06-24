"""Local master key for at-rest encryption (watchlist, secrets)."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import threading
from pathlib import Path

from guardian.security.crypto import KEY_SIZE, require_crypto

_master_key: bytes | None = None
_lock = threading.Lock()


def key_file_path() -> Path:
    base = Path(os.environ.get("GUARDIAN_DATA_DIR", Path.home() / ".guardian"))
    return base / "master.key"


def _parse_env_key(raw: str) -> bytes:
    text = raw.strip()
    if not text:
        raise ValueError("empty key")
    try:
        if len(text) == KEY_SIZE * 2 and all(c in "0123456789abcdefABCDEF" for c in text):
            key = binascii.unhexlify(text)
        else:
            key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError("GUARDIAN_MASTER_KEY must be 64-char hex or base64url") from e
    if len(key) != KEY_SIZE:
        raise ValueError(f"master key must be exactly {KEY_SIZE} bytes")
    return key


def get_master_key() -> bytes:
    """Return the 32-byte AES master key, creating ~/.guardian/master.key if needed."""
    global _master_key
    require_crypto()
    with _lock:
        if _master_key is not None:
            return _master_key

        env_key = os.environ.get("GUARDIAN_MASTER_KEY", "").strip()
        if env_key:
            _master_key = _parse_env_key(env_key)
            return _master_key

        path = key_file_path()
        if path.exists():
            data = path.read_bytes()
            if len(data) != KEY_SIZE:
                raise ValueError(f"invalid master key file: {path} ({len(data)} bytes)")
            _master_key = data
            return _master_key

        path.parent.mkdir(parents=True, exist_ok=True)
        _master_key = secrets.token_bytes(KEY_SIZE)
        path.write_bytes(_master_key)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return _master_key
