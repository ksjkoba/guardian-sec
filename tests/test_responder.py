"""Tests for the active response engine — dry-run only."""

import pytest
from guardian.engine.alert import Alert, Severity
from guardian.engine.correlator import Campaign
from guardian.engine.responder import (
    kill_process,
    block_ip,
    quarantine_file,
    is_blockable_ip,
    AutoResponder,
    ResponseAction,
    MAX_CAMPAIGN_BLOCKS,
)


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        module="network_monitor",
        title="Test",
        description="test",
        severity=Severity.HIGH,
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def test_kill_process_dry_run():
    result = kill_process(99999, dry_run=True)
    assert result.dry_run is True
    assert result.action == ResponseAction.KILL_PROCESS
    assert result.success is True
    assert "DRY RUN" in result.message


def test_block_ip_dry_run():
    # Use a public IP — private/loopback addresses are now refused by the guard.
    result = block_ip("45.33.32.156", dry_run=True)
    assert result.dry_run is True
    assert result.action == ResponseAction.BLOCK_IP
    assert result.success is True
    assert "DRY RUN" in result.message
    assert "45.33.32.156" in result.message


def test_quarantine_file_dry_run(tmp_path):
    f = tmp_path / "evil.sh"
    f.write_text("#!/bin/bash\nrm -rf /\n")
    result = quarantine_file(str(f), dry_run=True)
    assert result.dry_run is True
    assert result.action == ResponseAction.QUARANTINE_FILE
    assert result.success is True
    # File must still be there — we only simulated
    assert f.exists()


def test_auto_responder_below_threshold_skips():
    responder = AutoResponder(dry_run=True, min_severity=Severity.HIGH)
    alert = _make_alert(severity=Severity.LOW)
    results = responder.respond_to_alert(alert)
    assert results == []


def test_auto_responder_network_alert_blocks_ip():
    responder = AutoResponder(dry_run=True)
    alert = _make_alert(
        module="network_monitor",
        description="Connection to C2 server at 1.2.3.4",
        evidence="1.2.3.4 -> 443",
        severity=Severity.HIGH,
    )
    results = responder.respond_to_alert(alert)
    assert len(results) == 1
    assert results[0].action == ResponseAction.BLOCK_IP
    assert results[0].dry_run is True


def test_auto_responder_process_alert_kills_pid():
    responder = AutoResponder(dry_run=True)
    alert = _make_alert(
        module="file_monitor",
        severity=Severity.HIGH,
        metadata={"pid": 1234},
    )
    results = responder.respond_to_alert(alert)
    assert any(r.action == ResponseAction.KILL_PROCESS for r in results)
    assert all(r.dry_run for r in results)


def test_auto_responder_new_file_quarantines(tmp_path):
    f = tmp_path / "suspicious.sh"
    f.write_text("#!/bin/bash")
    responder = AutoResponder(dry_run=True)
    alert = _make_alert(
        module="file_monitor",
        severity=Severity.HIGH,
        metadata={"event": "NEW_FILE", "path": str(f)},
    )
    results = responder.respond_to_alert(alert)
    assert any(r.action == ResponseAction.QUARANTINE_FILE for r in results)


def test_on_response_callback_called():
    called = []
    responder = AutoResponder(dry_run=True, on_response=lambda r: called.append(r))
    alert = _make_alert(
        module="network_monitor",
        description="attack from 5.5.5.5",
        severity=Severity.CRITICAL,
    )
    responder.respond_to_alert(alert)
    assert len(called) == 1


# ─── IP safety guard ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "8.8.8.8",
    "1.2.3.4",
    "45.33.32.156",
])
def test_is_blockable_public_ips(ip):
    assert is_blockable_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "127.0.0.1",          # loopback
    "0.0.0.0",            # unspecified
    "169.254.1.1",        # link-local
    "224.0.0.1",          # multicast
    "10.0.0.5",           # private
    "192.168.1.1",        # private (gateway)
    "172.16.0.1",         # private
    "999.1.2.3",          # invalid octet
    "1.2.3",              # malformed
    "not-an-ip",          # garbage
    "",                   # empty
])
def test_is_not_blockable_unsafe_ips(ip):
    assert is_blockable_ip(ip) is False


def test_block_ip_refuses_loopback():
    result = block_ip("127.0.0.1", dry_run=False)
    assert result.success is False
    assert "Refused" in result.message
    # Even with dry_run, a refusal is recorded as unsuccessful (nothing to do).
    dry = block_ip("127.0.0.1", dry_run=True)
    assert dry.success is False


def test_block_ip_refuses_private_by_default():
    result = block_ip("192.168.1.1", dry_run=True)
    assert result.success is False


def test_block_ip_allows_private_when_opted_in(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ALLOW_BLOCK_PRIVATE", "1")
    result = block_ip("192.168.1.1", dry_run=True)
    assert result.success is True


def test_auto_responder_skips_loopback_in_alert():
    responder = AutoResponder(dry_run=True)
    alert = _make_alert(
        module="network_monitor",
        description="suspicious traffic involving 127.0.0.1 loopback",
        evidence="127.0.0.1 -> 8080",
        severity=Severity.HIGH,
    )
    results = responder.respond_to_alert(alert)
    # No safe IP to block → no block action emitted.
    assert all(r.action != ResponseAction.BLOCK_IP for r in results)


def test_auto_responder_prefers_public_over_private():
    responder = AutoResponder(dry_run=True)
    alert = _make_alert(
        module="network_monitor",
        description="C2 beacon: local 192.168.1.50 to 45.33.32.156",
        evidence="45.33.32.156:443",
        severity=Severity.HIGH,
    )
    results = responder.respond_to_alert(alert)
    blocks = [r for r in results if r.action == ResponseAction.BLOCK_IP]
    assert len(blocks) == 1
    assert blocks[0].target == "45.33.32.156"


def test_campaign_block_caps_and_filters():
    # Build a campaign that references many IPs, including unsafe ones.
    public_ips = [f"45.33.{i}.156" for i in range(1, 40)]   # 39 public IPs
    unsafe = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
    alerts = [
        _make_alert(description=f"attacker {ip}", severity=Severity.CRITICAL)
        for ip in public_ips + unsafe
    ]
    camp = Campaign(alerts=alerts, severity=Severity.CRITICAL)

    responder = AutoResponder(dry_run=True)
    results = responder.respond_to_campaign(camp)

    # Unsafe IPs filtered out, and total capped.
    assert len(results) <= MAX_CAMPAIGN_BLOCKS
    targets = {r.target for r in results}
    assert "127.0.0.1" not in targets
    assert "10.0.0.1" not in targets
    assert "192.168.1.1" not in targets
