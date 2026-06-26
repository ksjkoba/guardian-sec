"""Shared pytest fixtures — isolate Guardian data dir and in-memory state."""

from __future__ import annotations

import pytest


def _reset_guardian_state() -> None:
    import guardian.intel.breach_lookup as bl
    import guardian.security.keys as keys
    import guardian.web.persistence as persist

    with bl._watchlist_lock:
        bl._watchlist.clear()
        bl._watchlist_values.clear()
        bl._watchlist_alerts.clear()
    bl._watchlist_loaded = False
    bl._watchlist_scheduler_started = False

    with bl._breach_cache_lock:
        bl._breach_cache.clear()

    keys._master_key = None
    persist._initialized = False


@pytest.fixture(autouse=True)
def isolated_guardian_data(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "guardian"))
    _reset_guardian_state()
    yield
    _reset_guardian_state()
