"""Tests for monitors offloading SLM analysis to the shared worker queue.

Live mode (after ``start()``) must enqueue inference instead of running it
inline on the detection loop. One-shot/direct use must stay synchronous so CLI
scans and PCAP analysis return complete results.
"""

from __future__ import annotations

import guardian.engine.analysis_queue as aq
from guardian.modules.file_monitor import FileIntegrityMonitor, ProcessMonitor
from guardian.modules.log_analyzer import LogAnalyzer
from guardian.modules.network_monitor import HeuristicTracker, ConnEvent


def test_process_monitor_oneshot_is_synchronous(monkeypatch):
    """Without start(), analysis runs inline (no queue)."""
    submitted = []
    monkeypatch.setattr(
        "guardian.modules.file_monitor.submit_analysis",
        lambda fn: submitted.append(fn),
    )
    ran = []
    mon = ProcessMonitor(callback=lambda a: None)
    monkeypatch.setattr(mon, "_run_process_analysis", lambda *a: ran.append(a))

    mon._analyze_process(123, "kill -9 1", "root")

    assert ran, "one-shot analysis should run inline"
    assert not submitted, "one-shot analysis should not enqueue"


def test_process_monitor_live_offloads(monkeypatch):
    """After start(), analysis is enqueued rather than run inline."""
    submitted = []
    monkeypatch.setattr(
        "guardian.modules.file_monitor.submit_analysis",
        lambda fn: submitted.append(fn),
    )
    ran = []
    mon = ProcessMonitor(callback=lambda a: None)
    monkeypatch.setattr(mon, "_run_process_analysis", lambda *a: ran.append(a))
    mon._async_analysis = True  # what start() sets

    mon._analyze_process(123, "kill -9 1", "root")

    assert submitted, "live analysis should be enqueued"
    assert not ran, "live analysis must not run inline on the scan loop"
    # The enqueued job, when run by the worker, performs the analysis.
    submitted[0]()
    assert ran


def test_file_monitor_live_offloads(monkeypatch):
    submitted = []
    monkeypatch.setattr(
        "guardian.modules.file_monitor.submit_analysis",
        lambda fn: submitted.append(fn),
    )
    mon = FileIntegrityMonitor([], callback=lambda a: None)
    mon._async_analysis = True
    from pathlib import Path

    mon._analyze_file_event(Path("/tmp/x"), "NEW_FILE", "created")
    assert submitted


def test_log_analyzer_oneshot_synchronous(monkeypatch):
    submitted = []
    monkeypatch.setattr(
        "guardian.modules.log_analyzer.submit_analysis",
        lambda fn: submitted.append(fn),
    )
    ran = []
    la = LogAnalyzer([], callback=lambda a: None)
    monkeypatch.setattr(la, "_run_batch_analysis", lambda *a: ran.append(a))

    from pathlib import Path

    la._analyze_batch(["bad line"], Path("/var/log/x"))
    assert ran and not submitted


def test_network_tracker_pcap_mode_is_synchronous(monkeypatch):
    """Default tracker (PCAP/one-shot) dispatches synchronously."""
    monkeypatch.setattr(aq, "submit_analysis", lambda fn: fn())
    calls = []
    tracker = HeuristicTracker(lambda evts, ctx: calls.append((len(evts), ctx)))

    # Drive a port scan past the threshold so it flags synchronously.
    for port in range(60):
        tracker.ingest(ConnEvent("10.0.0.1", "10.0.0.2", port, "tcp"))

    assert calls, "PCAP-mode tracker should dispatch synchronously"


def test_network_tracker_live_mode_enqueues(monkeypatch):
    submitted = []
    monkeypatch.setattr(
        "guardian.modules.network_monitor.submit_analysis",
        lambda fn: submitted.append(fn),
    )
    tracker = HeuristicTracker(lambda evts, ctx: None, async_dispatch=True)

    for port in range(60):
        tracker.ingest(ConnEvent("10.0.0.1", "10.0.0.2", port, "tcp"))

    assert submitted, "live tracker should enqueue analysis"
