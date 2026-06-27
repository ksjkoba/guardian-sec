"""File & process monitoring module — malware detection, integrity, behavior."""

from __future__ import annotations

import hashlib
import re
import threading
import time
from pathlib import Path
from typing import Callable

from guardian.engine.alert import Alert
from guardian.engine.slm import get_engine

MODULE = "file_monitor"

_SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
    "/etc/ssh/sshd_config", "/root/.ssh/", "/home",
]

_MALICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".sh", ".py", ".rb", ".pl", ".php",  # in unusual directories
}

_SUSPICIOUS_PROC_PATTERNS = [
    re.compile(r"(nc|ncat|netcat)\s+-[lLe]", re.IGNORECASE),
    re.compile(r"(python|perl|ruby|php)\s+-[ce]", re.IGNORECASE),
    re.compile(r"(curl|wget).*(http|ftp).*\|\s*(bash|sh|python|perl)", re.IGNORECASE),
    re.compile(r"base64\s+(-d|--decode)", re.IGNORECASE),
    re.compile(r"(chmod|chown)\s+\+s", re.IGNORECASE),
    re.compile(r"(dd|cat)\s+.*\s+/dev/(sd|nvme|xvd)", re.IGNORECASE),
    re.compile(r"(kill|pkill|killall)\s+-9", re.IGNORECASE),
    re.compile(r"(crontab|at)\s+-", re.IGNORECASE),
    re.compile(r"LD_PRELOAD\s*=", re.IGNORECASE),
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _build_file_prompt(path: Path, event_type: str, details: str) -> str:
    return (
        f"A filesystem event occurred:\n"
        f"Event: {event_type}\n"
        f"Path: {path}\n"
        f"Details: {details}\n\n"
        "Is this suspicious from a cybersecurity perspective?\n"
        "Return a JSON object or null:\n"
        "{\n"
        '  "title": "threat name",\n'
        '  "description": "why this is suspicious",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "evidence": "specific indicators",\n'
        '  "recommendation": "what to do"\n'
        "}"
    )


def _build_proc_prompt(pid: int, cmdline: str, user: str) -> str:
    return (
        f"A running process has suspicious characteristics:\n"
        f"PID: {pid}\n"
        f"User: {user}\n"
        f"Command: {cmdline}\n\n"
        "Analyze for malware, persistence mechanisms, or attacker tools.\n"
        "Return JSON or null:\n"
        "{\n"
        '  "title": "threat name",\n'
        '  "description": "why this process is suspicious",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "evidence": "command line indicators",\n'
        '  "recommendation": "action to take"\n'
        "}"
    )


class FileIntegrityMonitor:
    """Watch files/directories for changes and analyze with SLM."""

    def __init__(
        self,
        paths: list[str | Path],
        callback: Callable[[Alert], None],
        interval: float = 2.0,
    ):
        self.paths = [Path(p) for p in paths]
        self.callback = callback
        self.interval = interval
        self._stop = threading.Event()
        self._baseline: dict[str, str] = {}

    def build_baseline(self) -> None:
        for path in self.paths:
            if path.is_file():
                self._baseline[str(path)] = _sha256(path)
            elif path.is_dir():
                for f in path.rglob("*"):
                    if f.is_file():
                        self._baseline[str(f)] = _sha256(f)

    def start(self) -> None:
        self.build_baseline()
        t = threading.Thread(target=self._watch_loop, daemon=True)
        t.start()

    def stop(self) -> None:
        self._stop.set()

    def _watch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception:
                pass
            time.sleep(self.interval)

    def _scan_once(self) -> None:
        current: dict[str, str] = {}
        for path in self.paths:
            if path.is_file():
                current[str(path)] = _sha256(path)
            elif path.is_dir():
                for f in path.rglob("*"):
                    if f.is_file():
                        current[str(f)] = _sha256(f)

        for fpath, digest in current.items():
            p = Path(fpath)
            if fpath not in self._baseline:
                self._analyze_file_event(p, "NEW_FILE", f"File created: {fpath}")
                self._baseline[fpath] = digest
            elif self._baseline[fpath] != digest:
                self._analyze_file_event(
                    p, "MODIFIED",
                    f"Hash changed: {self._baseline[fpath][:16]}... -> {digest[:16]}..."
                )
                self._baseline[fpath] = digest

        for fpath in list(self._baseline):
            if fpath not in current:
                self._analyze_file_event(
                    Path(fpath), "DELETED", f"File removed: {fpath}"
                )
                del self._baseline[fpath]

    def _analyze_file_event(self, path: Path, event: str, details: str) -> None:
        try:
            engine = get_engine()
            raw = engine.analyze(_build_file_prompt(path, event, details), max_tokens=256)
            if raw.strip().lower() == "null":
                return
            alert = Alert.from_slm_json(MODULE, raw, fallback_evidence=details)
            if alert:
                alert.metadata.update({"event": event, "path": str(path)})
                self.callback(alert)
        except Exception:
            pass


class ProcessMonitor:
    """Periodic process table scanner — detects suspicious running processes."""

    def __init__(self, callback: Callable[[Alert], None], interval: float = 5.0):
        self.callback = callback
        self.interval = interval
        self._stop = threading.Event()
        self._seen_pids: set[int] = set()

    def start(self) -> None:
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._scan_processes()
            except Exception:
                pass
            time.sleep(self.interval)

    def _scan_processes(self) -> None:
        try:
            import psutil
        except ImportError:
            return

        for proc in psutil.process_iter(["pid", "cmdline", "username"]):
            try:
                pid = proc.info["pid"]
                if pid in self._seen_pids:
                    continue
                cmdline = " ".join(proc.info["cmdline"] or [])
                user = proc.info["username"] or "unknown"

                if any(p.search(cmdline) for p in _SUSPICIOUS_PROC_PATTERNS):
                    self._seen_pids.add(pid)
                    self._analyze_process(pid, cmdline, user)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _analyze_process(self, pid: int, cmdline: str, user: str) -> None:
        try:
            engine = get_engine()
            raw = engine.analyze(_build_proc_prompt(pid, cmdline, user), max_tokens=256)
            if raw.strip().lower() == "null":
                return
            alert = Alert.from_slm_json(
                MODULE, raw,
                fallback_evidence=f"PID {pid} ({user}): {cmdline[:200]}"
            )
            if alert:
                alert.metadata.update({"pid": pid, "user": user, "cmdline": cmdline[:500]})
                self.callback(alert)
        except Exception:
            pass


def scan_processes_once() -> list[Alert]:
    """One-shot process scan. Returns alerts."""
    alerts: list[Alert] = []

    def _cb(a: Alert) -> None:
        alerts.append(a)

    mon = ProcessMonitor(_cb)
    mon._scan_processes()
    return alerts
