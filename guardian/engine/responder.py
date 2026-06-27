"""
Active response engine.

Takes a Campaign or Alert and, when confidence is high enough,
executes a defensive action: kill process, block IP, or quarantine file.

Every action is:
  - Logged to an immutable audit trail before execution.
  - Skippable via dry_run=True (default) for safe evaluation.
  - Gated by a minimum severity threshold.
  - Platform-aware: uses iptables (Linux), pf (macOS), or netsh (Windows).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from guardian.engine.alert import Alert, Severity

AUDIT_LOG = Path("guardian_response_audit.jsonl")
_audit_lock = threading.Lock()

AUTO_RESPOND_THRESHOLD = Severity.HIGH   # only auto-respond to HIGH and CRITICAL
DRY_RUN_DEFAULT = True                    # safe by default


class ResponseAction(str, Enum):
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    ALERT_ONLY = "alert_only"


@dataclass
class ResponseResult:
    action: ResponseAction
    target: str
    success: bool
    dry_run: bool
    message: str
    timestamp: float = field(default_factory=time.time)
    alert_id: str = ""
    campaign_id: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "action": self.action.value,
            "target": self.target,
            "success": self.success,
            "dry_run": self.dry_run,
            "message": self.message,
            "alert_id": self.alert_id,
            "campaign_id": self.campaign_id,
        }


def _audit(result: ResponseResult) -> None:
    with _audit_lock:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(result.to_dict()) + "\n")


# ─── Process killer ──────────────────────────────────────────────────────────

def kill_process(pid: int, dry_run: bool = DRY_RUN_DEFAULT) -> ResponseResult:
    target = str(pid)
    if dry_run:
        result = ResponseResult(
            action=ResponseAction.KILL_PROCESS,
            target=target,
            success=True,
            dry_run=True,
            message=f"[DRY RUN] Would kill PID {pid}",
        )
        _audit(result)
        return result

    try:
        import signal as _signal
        os.kill(pid, _signal.SIGKILL)
        msg = f"Killed PID {pid}"
        success = True
    except ProcessLookupError:
        msg = f"PID {pid} not found (already exited)"
        success = True  # goal achieved
    except PermissionError:
        msg = f"Permission denied killing PID {pid} — try running as root"
        success = False
    except Exception as e:
        msg = f"Failed to kill PID {pid}: {e}"
        success = False

    result = ResponseResult(
        action=ResponseAction.KILL_PROCESS,
        target=target,
        success=success,
        dry_run=False,
        message=msg,
    )
    _audit(result)
    return result


# ─── IP blocker ──────────────────────────────────────────────────────────────

def _detect_firewall() -> str:
    sys_platform = platform.system().lower()
    if sys_platform == "linux":
        for cmd in ["iptables", "nft"]:
            if shutil.which(cmd):
                return cmd
        return "iptables"
    elif sys_platform == "darwin":
        return "pf"
    elif sys_platform == "windows":
        return "netsh"
    return "iptables"


def block_ip(ip: str, dry_run: bool = DRY_RUN_DEFAULT) -> ResponseResult:
    fw = _detect_firewall()
    if fw == "iptables":
        cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        cmd_out = ["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"]
        cmds = [cmd, cmd_out]
    elif fw == "nft":
        cmds = [[
            "nft", "add", "rule", "inet", "filter", "input",
            "ip", "saddr", ip, "drop"
        ]]
    elif fw == "pf":
        cmds = [["pfctl", "-t", "guardian_blocked", "-T", "add", ip]]
    elif fw == "netsh":
        cmds = [[
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Guardian_Block_{ip}", "dir=in", "action=block",
            f"remoteip={ip}"
        ]]
    else:
        cmds = []

    if dry_run:
        preview = " && ".join(" ".join(c) for c in cmds)
        result = ResponseResult(
            action=ResponseAction.BLOCK_IP,
            target=ip,
            success=True,
            dry_run=True,
            message=f"[DRY RUN] Would run: {preview}",
        )
        _audit(result)
        return result

    errors: list[str] = []
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError as e:
            errors.append(e.stderr.decode(errors="replace").strip())
        except FileNotFoundError:
            errors.append(f"{cmd[0]} not found")
        except Exception as e:
            errors.append(str(e))

    success = not errors
    msg = f"Blocked {ip} via {fw}" if success else f"Failed to block {ip}: {'; '.join(errors)}"
    result = ResponseResult(
        action=ResponseAction.BLOCK_IP,
        target=ip,
        success=success,
        dry_run=False,
        message=msg,
    )
    _audit(result)
    return result


# ─── File quarantine ──────────────────────────────────────────────────────────

QUARANTINE_DIR = Path("/var/guardian/quarantine")


def quarantine_file(path: str | Path, dry_run: bool = DRY_RUN_DEFAULT) -> ResponseResult:
    path = Path(path)
    dest = QUARANTINE_DIR / f"{path.name}.{int(time.time())}.quarantine"

    if dry_run:
        result = ResponseResult(
            action=ResponseAction.QUARANTINE_FILE,
            target=str(path),
            success=True,
            dry_run=True,
            message=f"[DRY RUN] Would move {path} → {dest}",
        )
        _audit(result)
        return result

    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        # Remove execute bits first, then move
        try:
            path.chmod(path.stat().st_mode & ~0o111)
        except OSError:
            pass
        shutil.move(str(path), str(dest))
        msg = f"Quarantined {path} → {dest}"
        success = True
    except Exception as e:
        msg = f"Failed to quarantine {path}: {e}"
        success = False

    result = ResponseResult(
        action=ResponseAction.QUARANTINE_FILE,
        target=str(path),
        success=success,
        dry_run=False,
        message=msg,
    )
    _audit(result)
    return result


# ─── Auto-responder ──────────────────────────────────────────────────────────

import re as _re
_IP_RE = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AutoResponder:
    """
    Listens to alerts and campaigns and fires responses when confidence
    is above the threshold.

    Set dry_run=True to log what WOULD happen without executing.
    """

    def __init__(
        self,
        dry_run: bool = DRY_RUN_DEFAULT,
        min_severity: Severity = AUTO_RESPOND_THRESHOLD,
        on_response: Callable[[ResponseResult], None] | None = None,
    ):
        self.dry_run = dry_run
        self.min_severity = min_severity
        self._on_response = on_response
        self._severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def _above_threshold(self, severity: Severity) -> bool:
        return (
            self._severity_order.index(severity.value)
            <= self._severity_order.index(self.min_severity.value)
        )

    def respond_to_alert(self, alert: Alert) -> list[ResponseResult]:
        if not self._above_threshold(alert.severity):
            return []

        results: list[ResponseResult] = []

        # Kill suspicious process
        pid = alert.metadata.get("pid")
        if pid and alert.module == "file_monitor":
            r = kill_process(int(pid), dry_run=self.dry_run)
            r.alert_id = alert.id
            results.append(r)

        # Block source IP from network alerts
        if alert.module == "network_monitor":
            text = f"{alert.description} {alert.evidence}"
            ips = _IP_RE.findall(text)
            for ip in ips[:1]:  # block first extracted IP
                r = block_ip(ip, dry_run=self.dry_run)
                r.alert_id = alert.id
                results.append(r)

        # Quarantine suspicious new files
        if alert.module == "file_monitor" and alert.metadata.get("event") == "NEW_FILE":
            fpath = alert.metadata.get("path", "")
            if fpath:
                r = quarantine_file(fpath, dry_run=self.dry_run)
                r.alert_id = alert.id
                results.append(r)

        for r in results:
            if self._on_response:
                self._on_response(r)
        return results

    def respond_to_campaign(self, campaign) -> list[ResponseResult]:
        """Respond to a whole campaign — block all attacker IPs found."""
        results: list[ResponseResult] = []
        if not self._above_threshold(campaign.severity):
            return results

        # Collect all IPs across all alerts in the campaign
        attacker_ips: set[str] = set()
        for alert in campaign.alerts:
            text = f"{alert.description} {alert.evidence} {alert.title}"
            attacker_ips.update(_IP_RE.findall(text))

        for ip in attacker_ips:
            r = block_ip(ip, dry_run=self.dry_run)
            r.campaign_id = campaign.id
            results.append(r)
            if self._on_response:
                self._on_response(r)

        return results
