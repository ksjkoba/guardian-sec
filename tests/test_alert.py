"""Unit tests for the Alert data model — no SLM required."""

import pytest
from guardian.engine.alert import Alert, Severity


def test_from_slm_json_valid():
    raw = """
    {
      "title": "SQL Injection",
      "description": "User input concatenated into SQL query",
      "severity": "HIGH",
      "evidence": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "recommendation": "Use parameterized queries"
    }
    """
    alert = Alert.from_slm_json("code_scanner", raw)
    assert alert is not None
    assert alert.title == "SQL Injection"
    assert alert.severity == Severity.HIGH
    assert alert.module == "code_scanner"


def test_from_slm_json_null():
    assert Alert.from_slm_json("code_scanner", "null") is None
    assert Alert.from_slm_json("code_scanner", "NULL") is None


def test_from_slm_json_with_preamble():
    raw = "Here is my analysis:\n\n{\"title\": \"XSS\", \"severity\": \"MEDIUM\", \"description\": \"d\", \"evidence\": \"e\", \"recommendation\": \"r\"}"
    alert = Alert.from_slm_json("code_scanner", raw)
    assert alert is not None
    assert alert.title == "XSS"


def test_severity_ordering():
    severities = [Severity.LOW, Severity.CRITICAL, Severity.HIGH, Severity.INFO, Severity.MEDIUM]
    ordered = sorted(severities, key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(s.value))
    assert ordered[0] == Severity.CRITICAL
    assert ordered[-1] == Severity.INFO


def test_to_dict_round_trip():
    alert = Alert(
        module="test",
        title="Test",
        description="Test description",
        severity=Severity.MEDIUM,
        evidence="test line",
        recommendation="fix it",
    )
    d = alert.to_dict()
    assert d["module"] == "test"
    assert d["severity"] == "MEDIUM"
    assert "timestamp" in d
    assert "id" in d


def test_invalid_json_returns_none():
    assert Alert.from_slm_json("mod", "this is not json at all") is None
