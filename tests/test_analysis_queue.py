"""Tests for the bounded SLM analysis worker queue.

The queue must: run jobs on a single background worker (serial inference),
never block the submitter, drop the oldest pending job under backpressure, and
survive a job that raises.
"""

from __future__ import annotations

import threading
import time

import pytest

from guardian.engine.analysis_queue import AnalysisQueue, reset_analysis_queue


@pytest.fixture(autouse=True)
def _reset_global_queue():
    reset_analysis_queue()
    yield
    reset_analysis_queue()


def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_jobs_run_on_a_background_worker():
    q = AnalysisQueue()
    ran = threading.Event()
    worker_thread_name = {}

    def job():
        worker_thread_name["name"] = threading.current_thread().name
        ran.set()

    assert q.submit(job) is True
    assert ran.wait(timeout=2.0)
    # Executed off the calling (main) thread, on the named worker.
    assert worker_thread_name["name"] != threading.current_thread().name
    assert "slm-analysis-worker" in worker_thread_name["name"]


def test_submit_does_not_block_caller():
    q = AnalysisQueue()
    release = threading.Event()

    def slow_job():
        release.wait(timeout=2.0)

    start = time.monotonic()
    q.submit(slow_job)   # occupies the worker
    q.submit(lambda: None)  # must not block even though worker is busy
    elapsed = time.monotonic() - start
    assert elapsed < 0.5
    release.set()


def test_single_worker_serializes_jobs():
    q = AnalysisQueue()
    concurrent = {"max": 0, "now": 0}
    lock = threading.Lock()

    def job():
        with lock:
            concurrent["now"] += 1
            concurrent["max"] = max(concurrent["max"], concurrent["now"])
        time.sleep(0.02)
        with lock:
            concurrent["now"] -= 1

    for _ in range(10):
        q.submit(job)

    assert _wait_until(lambda: q.stats()["processed"] == 10, timeout=3.0)
    # Never more than one job running at a time.
    assert concurrent["max"] == 1


def test_full_queue_drops_oldest():
    q = AnalysisQueue(max_pending=2)
    gate = threading.Event()
    order: list[int] = []

    def first_job():
        gate.wait(timeout=2.0)  # pin the worker so the queue fills behind it

    q.submit(first_job)
    # Wait for the worker to pick up first_job so the queue is empty again,
    # then flood it while it is blocked.
    time.sleep(0.05)

    def make(n):
        return lambda: order.append(n)

    # Fill (2) then overflow — oldest pending should be evicted.
    for n in range(6):
        q.submit(make(n))

    gate.set()
    assert _wait_until(lambda: q.stats()["pending"] == 0, timeout=3.0)

    stats = q.stats()
    assert stats["dropped"] >= 1
    # The most recent submissions survive; earliest overflow ones were dropped.
    assert 5 in order
    assert order == sorted(order)  # FIFO among survivors


def test_bad_job_does_not_kill_worker():
    q = AnalysisQueue()
    survived = threading.Event()

    q.submit(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    q.submit(lambda: survived.set())

    assert survived.wait(timeout=2.0)
    assert q.stats()["processed"] >= 2
