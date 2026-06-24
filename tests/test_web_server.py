"""Tests for the Guardian web API — uses FastAPI TestClient (no real server)."""

import json
import time
import pytest

# Skip entire module if fastapi is not installed
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import Campaign, CampaignStatus
from guardian.web.server import create_app, DashboardState


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def ds():
    return DashboardState()


@pytest.fixture
def client(ds, monkeypatch):
    monkeypatch.setenv("GUARDIAN_API_AUTH", "0")
    monkeypatch.setenv("GUARDIAN_ALLOW_PLAINTEXT", "1")
    app = create_app(dashboard_state=ds)
    return TestClient(app), ds


def _make_alert(
    module="log_analyzer",
    title="Test Alert",
    description="something suspicious",
    severity=Severity.HIGH,
    ioc_tag="",
) -> Alert:
    a = Alert(
        module=module,
        title=title,
        description=description,
        severity=severity,
    )
    if ioc_tag:
        a.metadata["ioc_tag"] = ioc_tag
        a.metadata["ioc_matches"] = [{"feed": "TestFeed", "ioc_type": "ip", "malware_family": "", "confidence": 90}]
    return a


# ─── Dashboard HTML ───────────────────────────────────────────────────────────

def test_dashboard_returns_html(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Guardian" in r.text


# ─── /api/alerts ─────────────────────────────────────────────────────────────

def test_alerts_empty(client):
    c, _ = client
    r = c.get("/api/alerts")
    assert r.status_code == 200
    assert r.json() == []


def test_alerts_returns_ingested(client):
    c, ds = client
    ds.ingest_alert(_make_alert(title="Brute force"))
    r = c.get("/api/alerts")
    data = r.json()
    assert len(data) == 1
    assert data[0]["title"] == "Brute force"


def test_alerts_limit(client):
    c, ds = client
    for i in range(10):
        ds.ingest_alert(_make_alert(title=f"Alert {i}"))
    r = c.get("/api/alerts?limit=3")
    assert len(r.json()) == 3


def test_alerts_severity_filter(client):
    c, ds = client
    ds.ingest_alert(_make_alert(severity=Severity.CRITICAL, title="Crit"))
    ds.ingest_alert(_make_alert(severity=Severity.LOW, title="Low"))
    r = c.get("/api/alerts?severity=CRITICAL")
    data = r.json()
    assert len(data) == 1
    assert data[0]["title"] == "Crit"


def test_alerts_include_ioc_tag(client):
    c, ds = client
    a = _make_alert(ioc_tag="IOC:Feodo-C2-IPs")
    ds.ingest_alert(a)
    r = c.get("/api/alerts")
    data = r.json()
    assert data[0]["ioc_tag"] == "IOC:Feodo-C2-IPs"


# ─── /api/campaigns ──────────────────────────────────────────────────────────

def test_campaigns_empty(client):
    c, _ = client
    r = c.get("/api/campaigns")
    assert r.status_code == 200
    assert r.json() == []


def test_campaigns_returns_ingested(client):
    c, ds = client
    camp = Campaign(
        alerts=[_make_alert()],
        title="SSH Brute Force",
        severity=Severity.HIGH,
        status=CampaignStatus.ACTIVE,
    )
    ds.ingest_campaign(camp)
    r = c.get("/api/campaigns")
    data = r.json()
    assert len(data) == 1
    assert data[0]["title"] == "SSH Brute Force"


def test_campaigns_update_in_place(client):
    c, ds = client
    camp = Campaign(
        alerts=[_make_alert()],
        title="Initial",
        severity=Severity.HIGH,
        status=CampaignStatus.ACTIVE,
    )
    ds.ingest_campaign(camp)
    camp.title = "Updated"
    camp.alerts.append(_make_alert())
    ds.ingest_campaign(camp)
    r = c.get("/api/campaigns")
    data = r.json()
    assert len(data) == 1
    assert data[0]["title"] == "Updated"


# ─── /api/stats ──────────────────────────────────────────────────────────────

def test_stats_initial(client):
    c, _ = client
    r = c.get("/api/stats")
    data = r.json()
    assert data["total_alerts"] == 0
    assert data["total_campaigns"] == 0
    assert "uptime_secs" in data


def test_stats_counts_alerts(client):
    c, ds = client
    ds.ingest_alert(_make_alert(severity=Severity.CRITICAL))
    ds.ingest_alert(_make_alert(severity=Severity.HIGH))
    r = c.get("/api/stats")
    data = r.json()
    assert data["total_alerts"] == 2
    assert data["critical"] == 1
    assert data["high"] == 1


def test_stats_counts_ioc_hits(client):
    c, ds = client
    ds.ingest_alert(_make_alert(ioc_tag="IOC:Feodo"))
    r = c.get("/api/stats")
    data = r.json()
    assert data["ioc_hits"] == 1


def test_stats_counts_campaigns(client):
    c, ds = client
    camp = Campaign(alerts=[_make_alert()], severity=Severity.HIGH, status=CampaignStatus.ACTIVE)
    ds.ingest_campaign(camp)
    r = c.get("/api/stats")
    data = r.json()
    assert data["total_campaigns"] == 1


# ─── /api/ioc/check ──────────────────────────────────────────────────────────

def test_ioc_check_missing_value(client):
    c, _ = client
    r = c.post("/api/ioc/check", json={})
    assert r.status_code == 400
    assert "error" in r.json()


def test_ioc_check_returns_structure(client):
    c, _ = client
    # May fail to load feeds (no network in CI) — just check structure
    r = c.post("/api/ioc/check", json={"value": "1.2.3.4"})
    assert r.status_code in (200, 500)
    if r.status_code == 200:
        data = r.json()
        assert "value" in data
        assert "malicious" in data
        assert "matches" in data


# ─── DashboardState unit tests ────────────────────────────────────────────────

def test_dashboard_state_max_alerts():
    ds = DashboardState()
    ds.MAX_ALERTS = 5
    for i in range(10):
        ds.ingest_alert(_make_alert(title=f"A{i}"))
    assert len(ds.get_alerts(limit=100)) == 5


def test_dashboard_state_get_alerts_reversed():
    ds = DashboardState()
    ds.ingest_alert(_make_alert(title="First"))
    ds.ingest_alert(_make_alert(title="Second"))
    alerts = ds.get_alerts()
    # Most recent first
    assert alerts[0]["title"] == "Second"


def test_dashboard_state_severity_filter():
    ds = DashboardState()
    ds.ingest_alert(_make_alert(severity=Severity.CRITICAL))
    ds.ingest_alert(_make_alert(severity=Severity.LOW))
    crit = ds.get_alerts(severity="CRITICAL")
    assert len(crit) == 1
    assert crit[0]["severity"] == "CRITICAL"

def test_websocket_broadcasts_alert(client):
    c, ds = client
    with c.websocket_connect("/ws") as ws:
        snap = ws.receive_json()
        assert snap["type"] == "snapshot"
        ds.ingest_alert(_make_alert(title="WS Live"))
        seen_alert = False
        for _ in range(5):
            msg = ws.receive_json()
            if msg["type"] == "alert":
                assert msg["data"]["title"] == "WS Live"
                seen_alert = True
                break
        assert seen_alert, "expected alert over websocket"


# ─── /api/breach ─────────────────────────────────────────────────────────────

def test_breach_scenarios(client):
    c, _ = client
    r = c.get("/api/breach/scenarios")
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "mock"
    assert len(data["scenarios"]) >= 8


def test_breach_check_clean(client):
    c, _ = client
    r = c.post("/api/breach/check", json={"type": "email", "value": "marcus.hale47@gmail.com"})
    assert r.status_code == 200
    assert r.json()["status"] == "clean"


def test_breach_check_exposed(client):
    c, _ = client
    r = c.post("/api/breach/check", json={"type": "email", "value": "dana.porter1988@outlook.com"})
    data = r.json()
    assert data["status"] == "exposed"
    assert data["breach_count"] == 3


def test_breach_check_invalid(client):
    c, _ = client
    r = c.post("/api/breach/check", json={"type": "email", "value": "bad"})
    assert r.json()["status"] == "invalid"


def test_breach_watchlist(client):
    c, _ = client
    r = c.post("/api/breach/watchlist", json={"type": "email", "value": "marcus.hale47@gmail.com"})
    assert r.status_code == 200
    assert r.json().get("ok")
    r2 = c.get("/api/breach/watchlist")
    assert len(r2.json()) >= 1

