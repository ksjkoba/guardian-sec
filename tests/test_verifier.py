"""Tests for live source verification."""

from guardian.intel.verifier import verify_on_source


def test_verify_missing_input():
    r = verify_on_source("", "ip", "ThreatFox")
    assert r["verified"] is False


def test_verify_test_module_not_global():
    r = verify_on_source("1.2.3.4", "ip", "UnknownSource")
    assert "detail" in r
