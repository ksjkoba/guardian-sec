"""Tests for the threat correlation engine — no SLM required."""

import time
import pytest
from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import (
    Correlator,
    Campaign,
    CampaignStatus,
    CAMPAIGN_WINDOW_SECS,
    _extract_entities,
    _alerts_are_related,
)


def _make_alert(
    module: str = "log_analyzer",
    title: str = "Test alert",
    description: str = "test",
    severity: Severity = Severity.HIGH,
    evidence: str = "",
    metadata: dict | None = None,
) -> Alert:
    return Alert(
        module=module,
        title=title,
        description=description,
        severity=severity,
        evidence=evidence,
        metadata=metadata or {},
    )


# ─── Entity extraction ────────────────────────────────────────────────────────

def test_extract_ip_from_description():
    alert = _make_alert(description="Connection from 192.168.1.100 blocked")
    entities = _extract_entities(alert)
    assert "192.168.1.100" in entities


def test_extract_ip_from_metadata():
    alert = _make_alert(metadata={"src_ip": "10.0.0.5"})
    entities = _extract_entities(alert)
    assert "10.0.0.5" in entities


def test_extract_user_from_metadata():
    alert = _make_alert(metadata={"user": "root"})
    entities = _extract_entities(alert)
    assert "user:root" in entities


def test_extract_pid_from_metadata():
    alert = _make_alert(metadata={"pid": 1234})
    entities = _extract_entities(alert)
    assert "1234" in entities


def test_extract_file_path():
    alert = _make_alert(evidence="Modified: /etc/passwd")
    entities = _extract_entities(alert)
    assert any("/etc/passwd" in e for e in entities)


# ─── Correlation logic ────────────────────────────────────────────────────────

def test_shared_ip_relates_alerts():
    a1 = _make_alert(metadata={"src_ip": "1.2.3.4"})
    a2 = _make_alert(metadata={"src_ip": "1.2.3.4"})
    e1 = _extract_entities(a1)
    e2 = _extract_entities(a2)
    assert _alerts_are_related(a1, a2, e1, e2)


def test_no_shared_entities_not_related():
    a1 = _make_alert(metadata={"src_ip": "1.2.3.4"})
    a2 = _make_alert(metadata={"src_ip": "9.9.9.9"})
    e1 = _extract_entities(a1)
    e2 = _extract_entities(a2)
    assert not _alerts_are_related(a1, a2, e1, e2)


def test_shared_file_path_relates_alerts():
    a1 = _make_alert(evidence="Modified /tmp/evil.sh")
    a2 = _make_alert(evidence="Executed /tmp/evil.sh")
    e1 = _extract_entities(a1)
    e2 = _extract_entities(a2)
    assert _alerts_are_related(a1, a2, e1, e2)


# ─── Correlator grouping ─────────────────────────────────────────────────────

def test_single_alert_below_threshold():
    c = Correlator(use_slm=False)
    c.start()
    alert = _make_alert(metadata={"src_ip": "1.2.3.4"})
    result = c.ingest(alert)
    # Single alert → below CAMPAIGN_MIN_ALERTS (2) → None
    assert result is None


def test_two_related_alerts_form_campaign():
    c = Correlator(use_slm=False)
    c.start()
    ip = "5.5.5.5"
    a1 = _make_alert(module="log_analyzer", metadata={"src_ip": ip})
    a2 = _make_alert(module="network_monitor", metadata={"src_ip": ip})
    c.ingest(a1)
    campaign = c.ingest(a2)
    assert campaign is not None
    assert len(campaign.alerts) == 2


def test_unrelated_alerts_stay_separate():
    c = Correlator(use_slm=False)
    c.start()
    a1 = _make_alert(module="log_analyzer", metadata={"src_ip": "1.1.1.1"})
    a2 = _make_alert(module="log_analyzer", metadata={"src_ip": "2.2.2.2"})
    c.ingest(a1)
    result = c.ingest(a2)
    assert result is None  # second alert in its own new campaign, below threshold


def test_three_alerts_escalate_severity():
    c = Correlator(use_slm=False)
    c.start()
    ip = "6.6.6.6"
    a1 = _make_alert(severity=Severity.LOW, metadata={"src_ip": ip})
    a2 = _make_alert(severity=Severity.MEDIUM, metadata={"src_ip": ip})
    a3 = _make_alert(severity=Severity.CRITICAL, metadata={"src_ip": ip})
    c.ingest(a1)
    c.ingest(a2)
    campaign = c.ingest(a3)
    assert campaign is not None
    assert campaign.severity == Severity.CRITICAL


def test_campaign_tracks_alert_count():
    c = Correlator(use_slm=False)
    c.start()
    ip = "7.7.7.7"
    for i in range(5):
        c.ingest(_make_alert(metadata={"src_ip": ip}))
    campaigns = c.get_campaigns()
    assert len(campaigns) == 1
    assert len(campaigns[0].alerts) == 5


def test_campaign_expiry():
    c = Correlator(use_slm=False)
    c.start()
    ip = "8.8.8.8"
    a1 = _make_alert(metadata={"src_ip": ip})
    a2 = _make_alert(metadata={"src_ip": ip})
    c.ingest(a1)
    c.ingest(a2)
    # Manually expire
    for camp in c._campaigns.values():
        camp.last_seen = time.time() - CAMPAIGN_WINDOW_SECS * 3
    c._prune()
    active = c.get_campaigns(active_only=True)
    assert len(active) == 0


def test_get_campaign_for_alert():
    c = Correlator(use_slm=False)
    c.start()
    ip = "9.9.9.0"
    a1 = _make_alert(metadata={"src_ip": ip})
    a2 = _make_alert(metadata={"src_ip": ip})
    c.ingest(a1)
    c.ingest(a2)
    found = c.get_campaign_for_alert(a1.id)
    assert found is not None
    assert a1.id in [a.id for a in found.alerts]


def test_kill_chain_techniques_collected():
    c = Correlator(use_slm=False)
    c.start()
    ip = "3.3.3.3"
    a1 = _make_alert(
        title="Port scan detected",
        description="nmap scan from attacker",
        metadata={"src_ip": ip}
    )
    a2 = _make_alert(
        title="Brute force SSH",
        description="hydra credential stuffing",
        metadata={"src_ip": ip}
    )
    c.ingest(a1)
    campaign = c.ingest(a2)
    assert campaign is not None
    ids = [t.id for t in campaign.techniques]
    assert "T1046" in ids   # nmap
    assert "T1110" in ids   # hydra
