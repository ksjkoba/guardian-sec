"""Tests for CLI display rendering helpers."""

from __future__ import annotations

from guardian.engine.alert import Alert, Severity
from guardian.utils.display import render_alert_table


def _alert(sev: Severity, title: str) -> Alert:
    return Alert(module="code_scanner", title=title, description="d", severity=sev)


def test_render_alert_table_sorts_by_severity_without_error():
    alerts = [
        _alert(Severity.LOW, "low"),
        _alert(Severity.CRITICAL, "crit"),
        _alert(Severity.MEDIUM, "med"),
    ]

    # Regression: the sort key lambda must reference its own parameter, not a
    # free `alert` variable (previously raised NameError at call time).
    table = render_alert_table(alerts, title="Test")

    assert table is not None
    assert table.row_count == 3


def test_render_alert_table_empty():
    table = render_alert_table([], title="Empty")
    assert table.row_count == 0
