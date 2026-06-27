"""Encrypted at-rest storage for Guardian local data files."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from guardian.security.crypto import decrypt_json, encrypt_json, has_crypto

_resolved_data_dir: Path | None = None
_fallback_warned = False


def _warn_fallback(preferred: Path, chosen: Path) -> None:
    """Emit a one-time warning that data is going to a non-persistent location."""
    global _fallback_warned
    if _fallback_warned:
        return
    _fallback_warned = True
    print(
        f"[guardian] WARNING: '{preferred}' is not writable; "
        f"using temporary directory '{chosen}' instead.\n"
        f"[guardian] Alerts, watchlist, and settings will NOT persist across restarts. "
        f"Set GUARDIAN_DATA_DIR to a writable path to enable persistence.",
        file=sys.stderr,
    )


def _is_writable(path: Path) -> bool:
    """Return True if path exists (or can be created) and is writable."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".guardian-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def data_dir() -> Path:
    """Return Guardian's data directory, falling back if the preferred one is read-only.

    Order of preference:
      1. ``$GUARDIAN_DATA_DIR`` (if set — honoured even if not yet writable so the
         env override is respected; readonly handling falls through to step 3).
      2. ``~/.guardian``
      3. A per-user temp dir (last-resort fallback so the app degrades gracefully
         in restricted/sandboxed environments instead of crashing on every write).

    The resolved directory is cached so the fallback decision is stable for the
    lifetime of the process.
    """
    global _resolved_data_dir
    if _resolved_data_dir is not None:
        return _resolved_data_dir

    explicit = os.environ.get("GUARDIAN_DATA_DIR")
    persistent: list[Path] = []
    if explicit:
        persistent.append(Path(explicit))
    persistent.append(Path.home() / ".guardian")

    temp_fallback = Path(tempfile.gettempdir()) / (
        f"guardian-{os.getuid()}" if hasattr(os, "getuid") else "guardian-user"
    )

    for candidate in persistent:
        if _is_writable(candidate):
            _resolved_data_dir = candidate
            return _resolved_data_dir

    # No persistent location is writable — fall back to a temp dir so the app
    # keeps working, but warn the user that data won't survive a restart.
    if _is_writable(temp_fallback):
        _warn_fallback(persistent[0], temp_fallback)
        _resolved_data_dir = temp_fallback
        return _resolved_data_dir

    # Nothing writable at all — return the first preference so callers still get
    # a deterministic path (writes will fail, but read paths and tests that mock
    # this still behave predictably).
    _resolved_data_dir = persistent[0]
    return _resolved_data_dir


def reset_data_dir_cache() -> None:
    """Clear the cached data dir (used by tests that swap GUARDIAN_DATA_DIR)."""
    global _resolved_data_dir, _fallback_warned
    _resolved_data_dir = None
    _fallback_warned = False


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
