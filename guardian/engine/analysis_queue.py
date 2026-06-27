"""Bounded, single-worker queue for monitor-originated SLM analysis.

Defense monitors (log/file/process/network) detect candidate events with cheap
heuristics, then ask the SLM to assess them. SLM inference is slow (seconds) and
CPU-heavy, so calling it inline blocks the monitor's loop, and spawning a thread
per event (as the network monitor did) can create unbounded concurrent
inferences that saturate the CPU.

This module decouples detection from inference:

  * Monitors call ``submit(fn)`` and return immediately.
  * A single worker thread drains the queue and runs each job serially. The SLM
    is internally lock-guarded, so serial execution costs nothing in throughput
    while capping CPU to one inference at a time.
  * The queue is bounded. When full, the oldest pending job is dropped so the
    newest detection is preferred and memory/CPU stay bounded under bursts.

The worker is lazy: it starts on first ``submit`` and the model itself still
loads on first inference (see ``guardian.engine.slm``).
"""

from __future__ import annotations

import queue
import threading
from typing import Callable

# Default backlog before we start dropping the oldest pending job. Small on
# purpose: under a burst we want recent events analyzed, not a deep stale queue.
DEFAULT_MAX_PENDING = 32

Job = Callable[[], None]


class AnalysisQueue:
    """Serializes SLM analysis jobs through a single bounded worker."""

    def __init__(self, max_pending: int = DEFAULT_MAX_PENDING):
        self._queue: "queue.Queue[Job]" = queue.Queue(maxsize=max_pending)
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._submitted = 0
        self._dropped = 0
        self._processed = 0

    def submit(self, fn: Job) -> bool:
        """Enqueue a job. Returns True if queued, False if it replaced/dropped.

        Never blocks the caller. If the queue is full, the oldest pending job is
        evicted to make room for ``fn`` (newest detection wins).
        """
        self._ensure_worker()
        with self._lock:
            self._submitted += 1
        while True:
            try:
                self._queue.put_nowait(fn)
                return True
            except queue.Full:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                    with self._lock:
                        self._dropped += 1
                except queue.Empty:
                    # Raced with the worker draining it; retry the put.
                    continue

    def _ensure_worker(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._stop.clear()
            self._worker = threading.Thread(
                target=self._run, name="slm-analysis-worker", daemon=True
            )
            self._worker.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                fn = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                fn()
            except Exception:
                # A single bad job must never kill the worker.
                pass
            finally:
                self._queue.task_done()
                with self._lock:
                    self._processed += 1

    def stop(self, drain: bool = False) -> None:
        if drain:
            self._queue.join()
        self._stop.set()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "submitted": self._submitted,
                "processed": self._processed,
                "dropped": self._dropped,
                "pending": self._queue.qsize(),
            }


_instance: AnalysisQueue | None = None
_instance_lock = threading.Lock()


def get_analysis_queue() -> AnalysisQueue:
    """Return the process-wide analysis queue, creating it on first use."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = AnalysisQueue()
    return _instance


def submit_analysis(fn: Job) -> bool:
    """Convenience wrapper: submit a job to the global analysis queue."""
    return get_analysis_queue().submit(fn)


def queue_stats() -> dict:
    """Report global-queue stats without creating the queue.

    Returns ``{"active": False, ...}`` when no analysis has been submitted yet
    (the worker is lazy), so callers can render an idle state cheaply.
    """
    with _instance_lock:
        inst = _instance
    if inst is None:
        return {
            "active": False,
            "submitted": 0,
            "processed": 0,
            "dropped": 0,
            "pending": 0,
        }
    stats = inst.stats()
    stats["active"] = True
    return stats


def reset_analysis_queue() -> None:
    """Tear down the global queue (test isolation)."""
    global _instance
    with _instance_lock:
        if _instance is not None:
            _instance.stop()
        _instance = None
