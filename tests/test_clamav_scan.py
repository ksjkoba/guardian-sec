"""ClamAV scan tests."""

from pathlib import Path

from guardian.intel import clamav_scan as cs


def test_clamav_status_without_binary(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda _: None)
    st = cs.clamav_status()
    assert st["available"] is False
    assert "apt install" in st["install_hint"]


def test_parse_clam_clean():
    v, msg, sigs = cs._parse_clam_output("/tmp/x: OK\n", "")
    assert v == "CLEAN"
    assert not sigs


def test_parse_clam_found():
    v, msg, sigs = cs._parse_clam_output("/tmp/eicar.com: Eicar-Signature FOUND\n", "")
    assert v == "MALICIOUS"
    assert sigs == ["Eicar-Signature"]


def test_combine_verdicts():
    assert cs._combine_verdicts("CLEAN", "MALICIOUS") == "MALICIOUS"
    assert cs._combine_verdicts("UNAVAILABLE", "CLEAN") == "CLEAN"


def test_scan_file_bytes_small_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "scan_file_path", lambda p: {"verdict": "CLEAN", "available": True, "plain_summary": "ok"})
    monkeypatch.setattr("guardian.intel.unified_scan.scan_ioc", lambda h: {"verdict": "CLEAN", "confidence": 0})
    monkeypatch.setattr("guardian.security.vault.data_dir", lambda: tmp_path)
    out = cs.scan_file_bytes(b"hello", "test.txt")
    assert out["verdict"] == "CLEAN"
    assert len(out["sha256"]) == 64
