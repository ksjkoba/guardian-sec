"""Tests for the active response engine — dry-run only."""

import pytest
from guardian.engine.alert import Alert, Severity
from guardian.engine.responder import (
    kill_process,
    block_ip,
    quarantine_file,
    AutoResponder,
    ResponseAction,
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
    result = block_ip("192.168.0.1", dry_run=True)
    assert result.dry_run is True
    assert result.action == ResponseAction.BLOCK_IP
    assert result.success is True
    assert "DRY RUN" in result.message
    assert "192.168.0.1" in result.message


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
