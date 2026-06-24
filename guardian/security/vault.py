"""Encrypted at-rest storage for Guardian local data files."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from guardian.security.crypto import decrypt_json, encrypt_json, has_crypto


def data_dir() -> Path:
    return Path(os.environ.get("GUARDIAN_DATA_DIR", Path.home() / ".guardian"))


def seal_file(name: str, obj: Any, *, aad: str | None = None) -> None:
    """Write AES-256-GCM encrypted JSON to ~/.guardian/{name}."""
    if not has_crypto():
        return
    from guardian.security.keys import get_master_key

    path = data_dir() / name
    path.parent.mkdir(parents=True, exist_ok=True)
    token = encrypt_json(get_master_key(), obj, aad=aad or name)
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def unseal_file(name: str, *, aad: str | None = None) -> Any | None:
    """Read and decrypt a vault file; returns None if missing or crypto unavailable."""
    if not has_crypto():
        return None
    path = data_dir() / name
    if not path.exists():
        return None
    from guardian.security.keys import get_master_key

    try:
        return decrypt_json(get_master_key(), path.read_text(encoding="utf-8"), aad=aad or name)
    except Exception:
        return None


def seal_json(obj: Any, *, aad: str) -> str:
    from guardian.security.keys import get_master_key

    return encrypt_json(get_master_key(), obj, aad=aad)


def unseal_json(token: str, *, aad: str) -> Any:
    from guardian.security.keys import get_master_key

    return decrypt_json(get_master_key(), token, aad=aad)
