"""Tests for resilient data-dir resolution and the readonly fallback."""

from __future__ import annotations

import tempfile
from pathlib import Path

import guardian.security.vault as vault


def test_explicit_writable_dir_is_used(monkeypatch, tmp_path):
    target = tmp_path / "explicit"
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(target))
    vault.reset_data_dir_cache()

    resolved = vault.data_dir()

    assert resolved == target
    assert resolved.is_dir()


def test_resolved_dir_is_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "a"))
    vault.reset_data_dir_cache()
    first = vault.data_dir()

    # Changing the env after first resolution should NOT change the cached value.
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "b"))
    second = vault.data_dir()

    assert first == second == tmp_path / "a"


def test_falls_back_to_temp_when_preferred_unwritable(monkeypatch, tmp_path, capsys):
    unwritable = tmp_path / "readonly"
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(unwritable))
    vault.reset_data_dir_cache()

    # Force the explicit + ~/.guardian candidates to look unwritable, but let
    # the temp fallback succeed.
    real_is_writable = vault._is_writable

    def fake_is_writable(path: Path) -> bool:
        if path == unwritable or path == Path.home() / ".guardian":
            return False
        return real_is_writable(path)

    monkeypatch.setattr(vault, "_is_writable", fake_is_writable)

    resolved = vault.data_dir()

    assert str(resolved).startswith(tempfile.gettempdir())
    assert resolved.is_dir()

    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "will NOT persist" in err


def test_fallback_warning_emitted_only_once(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "ro"))
    vault.reset_data_dir_cache()

    real_is_writable = vault._is_writable

    def fake_is_writable(path: Path) -> bool:
        if str(path).endswith("/ro") or path == Path.home() / ".guardian":
            return False
        return real_is_writable(path)

    monkeypatch.setattr(vault, "_is_writable", fake_is_writable)

    vault.data_dir()
    first_err = capsys.readouterr().err
    # Subsequent calls hit the cache and must not re-warn.
    vault.data_dir()
    second_err = capsys.readouterr().err

    assert "WARNING" in first_err
    assert second_err == ""


def test_persistence_roundtrip_survives_fallback(monkeypatch, tmp_path):
    """Saving/loading alerts works even when persistence lands in the fallback dir."""
    import guardian.web.persistence as persist

    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "ro"))
    vault.reset_data_dir_cache()
    persist._initialized = False

    real_is_writable = vault._is_writable

    def fake_is_writable(path: Path) -> bool:
        if str(path).endswith("/ro") or path == Path.home() / ".guardian":
            return False
        return real_is_writable(path)

    monkeypatch.setattr(vault, "_is_writable", fake_is_writable)

    persist.save_alert({"id": "fb1", "timestamp": 1.0, "severity": "HIGH", "title": "t"})
    loaded = persist.load_alerts()

    assert any(a["id"] == "fb1" for a in loaded)
