"""Regression tests for FileIntegrityMonitor resource usage.

The monitor previously re-hashed every file under /etc, /tmp and /var/tmp every
2 seconds, which pegged CPU/I/O when those dirs held large files. These tests
lock in the two mitigations: large files use a cheap size+mtime signature
instead of a full SHA-256, and the default scan cadence is no longer sub-second.
"""

from __future__ import annotations

from guardian.modules import file_monitor as fm
from guardian.modules.file_monitor import FileIntegrityMonitor, _sha256


def test_small_file_is_fully_hashed(tmp_path):
    f = tmp_path / "small.txt"
    f.write_text("hello world")
    digest = _sha256(f)
    # A real SHA-256 hex digest is 64 chars and not the cheap meta signature.
    assert len(digest) == 64
    assert not digest.startswith("meta:")


def test_large_file_uses_cheap_signature(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "_MAX_HASH_BYTES", 16)
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 64)  # exceeds the patched 16-byte cap
    sig = _sha256(f)
    assert sig.startswith("meta:")
    # Signature encodes size so a size change is detected.
    assert ":64:" in sig


def test_large_file_signature_changes_on_modification(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "_MAX_HASH_BYTES", 16)
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 64)
    before = _sha256(f)
    f.write_bytes(b"x" * 128)
    after = _sha256(f)
    assert before != after


def test_default_scan_interval_is_not_aggressive():
    mon = FileIntegrityMonitor([], callback=lambda a: None)
    assert mon.interval >= 10.0


def test_change_detection_roundtrip(tmp_path):
    """The monitor should detect a new file via a one-shot scan."""
    alerts = []
    mon = FileIntegrityMonitor([tmp_path], callback=alerts.append)
    mon.build_baseline()

    # Stub the SLM so the event is recorded without real inference.
    def _fake_analyze(path, event, details):
        from guardian.engine.alert import Alert, Severity

        mon.callback(
            Alert(
                module="file_monitor",
                title="new file",
                description=details,
                severity=Severity.INFO,
                evidence=details,
                recommendation="review",
            )
        )

    mon._analyze_file_event = _fake_analyze  # type: ignore[assignment]
    (tmp_path / "created.txt").write_text("payload")
    mon._scan_once()

    assert any("created.txt" in a.description for a in alerts)
