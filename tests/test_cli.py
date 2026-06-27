"""Smoke tests for the Guardian CLI command layer.

These invoke commands in-process via Click's CliRunner. They are deliberately
broad and shallow: the goal is to catch runtime errors in the command wiring
(undefined names, bad render calls, option mismatches) that unit tests on the
engine/intel layers do not exercise. The heavy bits (SLM engine, network) are
mocked so the tests stay fast and hermetic.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from guardian.cli import cli
from guardian.engine.alert import Alert, Severity


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _no_engine(monkeypatch):
    """Stub the SLM loader so commands don't try to load a 2.4 GB model."""
    monkeypatch.setattr("guardian.cli._load_engine", lambda *a, **k: None)


def _sample_alert() -> Alert:
    return Alert(
        module="code_scanner",
        title="Command Injection",
        description="User input flows into os.system().",
        severity=Severity.CRITICAL,
        evidence="os.system('echo ' + x)",
        recommendation="Use argument lists, not shell strings.",
    )


# --- top-level -------------------------------------------------------------

def test_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Guardian" in result.output


def test_version(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "command",
    ["scan-code", "scan-config", "scan-logs", "watch-logs", "defend", "serve", "campaigns"],
)
def test_subcommand_help(runner, command):
    """Every command must at least render its own --help without crashing.

    This catches Click option/parameter wiring errors (e.g. a callback that
    references an option that was never declared).
    """
    result = runner.invoke(cli, [command, "--help"])
    assert result.exit_code == 0, result.output


# --- scan-code (exercises render_alert_table) ------------------------------

def test_scan_code_renders_results(runner, tmp_path, monkeypatch):
    """scan-code with findings must render the alert table without error.

    Regression: render_alert_table previously raised NameError on its sort key.
    """
    target = tmp_path / "vuln.py"
    target.write_text("import os\nos.system('echo ' + x)\n")

    monkeypatch.setattr(
        "guardian.modules.code_scanner.scan_file",
        lambda *a, **k: iter([_sample_alert()]),
    )

    result = runner.invoke(cli, ["scan-code", str(target)])
    assert result.exit_code == 0, result.output
    assert "Command Injection" in result.output


def test_scan_code_no_findings(runner, tmp_path, monkeypatch):
    target = tmp_path / "clean.py"
    target.write_text("x = 1 + 2\n")
    monkeypatch.setattr(
        "guardian.modules.code_scanner.scan_file",
        lambda *a, **k: iter([]),
    )

    result = runner.invoke(cli, ["scan-code", str(target)])
    assert result.exit_code == 0, result.output
    assert "No vulnerabilities found" in result.output


def test_scan_code_directory_renders_table(runner, tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("eval(x)\n")
    monkeypatch.setattr(
        "guardian.modules.code_scanner.scan_directory",
        lambda *a, **k: iter([_sample_alert()]),
    )
    result = runner.invoke(cli, ["scan-code", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Code Scan Results" in result.output


# --- scan-config / scan-logs (also render tables) --------------------------

def test_scan_config_renders(runner, tmp_path, monkeypatch):
    cfg = tmp_path / "app.env"
    cfg.write_text("PASSWORD=hunter2\n")
    monkeypatch.setattr(
        "guardian.modules.code_scanner.scan_config",
        lambda *a, **k: iter([_sample_alert()]),
    )
    result = runner.invoke(cli, ["scan-config", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "Config Audit" in result.output


def test_scan_logs_renders(runner, tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root\n")
    monkeypatch.setattr(
        "guardian.modules.log_analyzer.scan_file",
        lambda *a, **k: iter([_sample_alert()]),
    )
    result = runner.invoke(cli, ["scan-logs", str(log)])
    assert result.exit_code == 0, result.output
    assert "Log Scan Results" in result.output


# --- campaigns (no engine / network needed) --------------------------------

def test_campaigns_empty(runner):
    result = runner.invoke(cli, ["campaigns"])
    assert result.exit_code == 0, result.output
    assert "No active campaigns" in result.output


# --- network-dependent commands (feeds mocked) -----------------------------

class _FakeIndex:
    """Minimal stand-in for the TI feed index used by check-ioc."""

    total_iocs = 1234

    def __init__(self, matches=None):
        self._matches = matches or []

    def lookup(self, value):
        return self._matches


def test_check_ioc_clean(runner, monkeypatch):
    monkeypatch.setattr("guardian.intel.feeds.get_index", lambda **k: _FakeIndex())
    monkeypatch.setattr("guardian.intel.heuristics.check_value", lambda v: None)

    result = runner.invoke(cli, ["check-ioc", "8.8.8.8"])
    assert result.exit_code == 0, result.output
    assert "CLEAN" in result.output


def test_check_ioc_malicious(runner, monkeypatch):
    from guardian.intel.feeds import IOCMatch

    match = IOCMatch(
        ioc="1.2.3.4",
        ioc_type="ip",
        feed="ThreatFox",
        malware_family="Cobalt Strike",
        confidence=90,
    )
    monkeypatch.setattr("guardian.intel.feeds.get_index", lambda **k: _FakeIndex([match]))
    monkeypatch.setattr("guardian.intel.heuristics.check_value", lambda v: None)

    result = runner.invoke(cli, ["check-ioc", "1.2.3.4"])
    assert result.exit_code == 0, result.output
    assert "MALICIOUS" in result.output
    assert "ThreatFox" in result.output


def test_feed_status(runner, monkeypatch):
    rows = [
        {
            "feed": "ThreatFox",
            "ioc_type": "ip",
            "cached": True,
            "fresh": True,
            "age_mins": 5,
            "size_kb": 42,
            "ttl_mins": 60,
        }
    ]
    monkeypatch.setattr("guardian.intel.feeds.feed_status", lambda: rows)

    result = runner.invoke(cli, ["feed-status"])
    assert result.exit_code == 0, result.output
    assert "ThreatFox" in result.output


def test_cross_verify_requires_input(runner):
    """With no --ioc/--all/--alert-id, the command should explain and exit non-zero."""
    monkeypatch_msg = runner.invoke(cli, ["cross-verify"])
    assert monkeypatch_msg.exit_code != 0
    assert "Provide one of" in monkeypatch_msg.output


def test_cross_verify_ioc(runner, monkeypatch):
    class _FakeVerification:
        def to_dict(self):
            return {
                "indicator": "http://example.com/bad",
                "classification": "GENUINE",
                "confidence": "high",
                "rationale": "Listed on URLhaus.",
                "corroboration_count": 2,
                "checks": [],
            }

    monkeypatch.setattr(
        "guardian.intel.cross_verify.key_status_message", lambda: None
    )
    monkeypatch.setattr(
        "guardian.intel.cross_verify.verify_alert_dict",
        lambda d: _FakeVerification(),
    )

    result = runner.invoke(cli, ["cross-verify", "--ioc", "http://example.com/bad"])
    assert result.exit_code == 0, result.output
    assert "GENUINE" in result.output
