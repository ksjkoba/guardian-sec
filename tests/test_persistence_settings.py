"""Persistence and settings tests."""

import json
import os
import tempfile
from pathlib import Path

from guardian.web import persistence as persist
from guardian.web import settings as cfg


def test_persistence_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(persist, "_initialized", False)
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path))
    persist.init_db()
    alert = {"id": "a1", "timestamp": 1.0, "severity": "HIGH", "title": "t"}
    persist.save_alert(alert)
    loaded = persist.load_alerts()
    assert len(loaded) == 1
    assert loaded[0]["id"] == "a1"


def test_settings_save_and_apply(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path))
    saved = cfg.save_user_settings({"GUARDIAN_BREACH_PROVIDER": "mock"})
    assert saved["GUARDIAN_BREACH_PROVIDER"] == "mock"
    assert os.environ.get("GUARDIAN_BREACH_PROVIDER") == "mock"
    eff = cfg.effective_settings()
    assert eff["GUARDIAN_BREACH_PROVIDER"] == "mock"


def test_rule_based_campaign_narrative():
    from guardian.engine.alert import Alert, Severity
    from guardian.engine.correlator import Campaign, _ensure_baseline_narrative

    c = Campaign(
        alerts=[
            Alert(module="log_analyzer", title="Scan", description="from 1.2.3.4", severity=Severity.HIGH),
            Alert(module="network_monitor", title="Block", description="from 1.2.3.4", severity=Severity.CRITICAL),
        ],
        entities={"1.2.3.4"},
        severity=Severity.CRITICAL,
    )
    _ensure_baseline_narrative(c)
    assert c.synthesis
    assert "2 related alerts" in c.synthesis
