"""User settings persisted to ~/.guardian/settings.json."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from guardian.security.vault import data_dir

# Keys users may change from the dashboard (applied on save + next serve start)
USER_SETTINGS: dict[str, dict[str, Any]] = {
    "GUARDIAN_BREACH_PROVIDER": {
        "label": "Breach check provider",
        "type": "select",
        "options": ["auto", "mock", "xposedornot", "multi", "hibp"],
        "default": "auto",
    },
    "GUARDIAN_DEPLOY_MODE": {
        "label": "Deployment mode",
        "type": "select",
        "options": ["local", "vps"],
        "default": "local",
    },
    "GUARDIAN_INSECURE_SSL": {
        "label": "Allow insecure SSL (corporate proxy)",
        "type": "bool",
        "default": "1",
    },
    "GUARDIAN_TLS_AUTO": {
        "label": "Auto TLS (self-signed HTTPS)",
        "type": "bool",
        "default": "0",
    },
    "GUARDIAN_PUBLIC_HOST": {
        "label": "Public hostname (VPS)",
        "type": "text",
        "default": "",
    },
}

RESTART_HINT_KEYS = frozenset({
    "GUARDIAN_BREACH_PROVIDER",
    "GUARDIAN_DEPLOY_MODE",
    "GUARDIAN_TLS_AUTO",
    "GUARDIAN_PUBLIC_HOST",
})


def _settings_path() -> Path:
    return data_dir() / "settings.json"


def load_saved() -> dict[str, str]:
    path = _settings_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {str(k): str(v) for k, v in raw.items() if k in USER_SETTINGS}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_user_settings(updates: dict[str, Any]) -> dict[str, str]:
    current = load_saved()
    for key, meta in USER_SETTINGS.items():
        if key not in updates:
            continue
        val = updates[key]
        if meta["type"] == "bool":
            current[key] = "1" if str(val).lower() in ("1", "true", "yes", "on") else "0"
        else:
            current[key] = str(val).strip()
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    apply_saved_settings(current)
    return current


def apply_saved_settings(saved: dict[str, str] | None = None) -> None:
    """Merge saved settings into os.environ (does not override explicit exports)."""
    data = saved if saved is not None else load_saved()
    for key, val in data.items():
        if key in USER_SETTINGS and val != "":
            os.environ[key] = val


def effective_settings() -> dict[str, Any]:
    """Current values for the settings UI."""
    saved = load_saved()
    out: dict[str, Any] = {}
    for key, meta in USER_SETTINGS.items():
        val = os.environ.get(key, saved.get(key, meta["default"]))
        if meta["type"] == "bool":
            out[key] = str(val).lower() in ("1", "true", "yes", "on")
        else:
            out[key] = val
        out[f"_{key}_meta"] = meta
    out["hibp_configured"] = bool(os.environ.get("HIBP_API_KEY", "").strip())
    out["restart_required_after_save"] = list(RESTART_HINT_KEYS)
    return out
