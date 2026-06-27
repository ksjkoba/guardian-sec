"""Log analysis & anomaly detection module."""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Iterator

from guardian.engine.alert import Alert
from guardian.engine.slm import get_engine

MODULE = "log_analyzer"

# Regex pre-filters — only send these to the SLM to keep inference cost low
_SUSPICIOUS_PATTERNS = [
    re.compile(r"(failed|invalid|unauthorized|denied|forbidden)", re.IGNORECASE),
    re.compile(r"(sudo|su |privilege|escalat)", re.IGNORECASE),
    re.compile(r"(nmap|nikto|sqlmap|metasploit|msfconsole|hydra|john)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|\.ssh/)", re.IGNORECASE),
    re.compile(r"(command injection|shell shock|log4j|\$\{jndi)", re.IGNORECASE),
    re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(failed|blocked|attack)", re.IGNORECASE),
    re.compile(r"(segfault|kernel panic|oom killer|out of memory)", re.IGNORECASE),
    re.compile(r"(cron|at |systemctl).*(start|stop|enable|disable)", re.IGNORECASE),
]

_BATCH_SIZE = 20       # lines to batch before SLM analysis
_BATCH_TIMEOUT = 10.0  # seconds before flushing partial batch


def _is_suspicious(line: str) -> bool:
    return any(p.search(line) for p in _SUSPICIOUS_PATTERNS)


def _build_prompt(lines: list[str]) -> str:
    block = "\n".join(lines)
    return (
        "Analyze the following log lines for security threats, anomalies, or suspicious activity.\n"
        "Return a JSON object with this exact structure (or null if no threat found):\n"
        "{\n"
        '  "title": "short threat title",\n'
        '  "description": "what is happening and why it is suspicious",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "evidence": "the specific log lines that triggered this",\n'
        '  "recommendation": "what the defender should do"\n'
        "}\n\n"
        f"Log lines:\n```\n{block}\n```"
    )


class LogAnalyzer:
    """Tail one or more log files and stream alerts via the SLM."""

    def __init__(self, paths: list[str | Path], callback: Callable[[Alert], None]):
        self.paths = [Path(p) for p in paths]
        self.callback = callback
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for path in self.paths:
            t = threading.Thread(target=self._tail_file, args=(path,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    def _tail_file(self, path: Path) -> None:
        if not path.exists():
            return
        buffer: deque[str] = deque()
        last_flush = time.monotonic()
        try:
            with open(path, "r", errors="replace") as fh:
                fh.seek(0, 2)  # start at end of file
                while not self._stop.is_set():
                    line = fh.readline()
                    if line:
                        line = line.rstrip()
                        if _is_suspicious(line):
                            buffer.append(line)
                    if len(buffer) >= _BATCH_SIZE or (
                        buffer and time.monotonic() - last_flush > _BATCH_TIMEOUT
                    ):
                        self._analyze_batch(list(buffer), path)
                        buffer.clear()
                        last_flush = time.monotonic()
                    else:
                        time.sleep(0.1)
        except (OSError, PermissionError):
            pass

    def _analyze_batch(self, lines: list[str], source: Path) -> None:
        try:
            engine = get_engine()
            raw = engine.analyze(_build_prompt(lines), max_tokens=300)
            if raw.strip().lower() == "null":
                return
            alert = Alert.from_slm_json(MODULE, raw, fallback_evidence="\n".join(lines[:5]))
            if alert:
                alert.metadata["source_file"] = str(source)
                self.callback(alert)
        except Exception:
            pass


def scan_file(path: str | Path, tail: bool = False) -> Iterator[Alert]:
    """One-shot scan of a log file (or tail if tail=True). Yields alerts."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    results: list[Alert] = []

    def _cb(alert: Alert) -> None:
        results.append(alert)

    if tail:
        analyzer = LogAnalyzer([path], _cb)
        analyzer.start()
        try:
            while True:
                time.sleep(0.5)
                while results:
                    yield results.pop(0)
        except KeyboardInterrupt:
            analyzer.stop()
    else:
        engine = get_engine()
        buffer: list[str] = []
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                if _is_suspicious(line):
                    buffer.append(line)
                if len(buffer) >= _BATCH_SIZE:
                    raw = engine.analyze(_build_prompt(buffer), max_tokens=300)
                    if raw.strip().lower() != "null":
                        alert = Alert.from_slm_json(
                            MODULE, raw, fallback_evidence="\n".join(buffer[:5])
                        )
                        if alert:
                            alert.metadata["source_file"] = str(path)
                            yield alert
                    buffer.clear()
        if buffer:
            raw = engine.analyze(_build_prompt(buffer), max_tokens=300)
            if raw.strip().lower() != "null":
                alert = Alert.from_slm_json(MODULE, raw, fallback_evidence="\n".join(buffer[:5]))
                if alert:
                    alert.metadata["source_file"] = str(path)
                    yield alert
