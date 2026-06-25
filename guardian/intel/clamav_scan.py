"""Local ClamAV file scanning — free alternative to cloud AV uploads."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

MAX_SCAN_BYTES = int(os.environ.get("GUARDIAN_SCAN_MAX_BYTES", str(32 * 1024 * 1024)))
_SCAN_TIMEOUT = int(os.environ.get("GUARDIAN_CLAMAV_TIMEOUT", "120"))

_FOUND_RE = re.compile(r":\s+(.+?)\s+FOUND\s*$", re.MULTILINE)


def _clamscan_bin() -> str | None:
    for name in ("clamdscan", "clamscan"):
        path = shutil.which(name)
        if path:
            return path
    return None


def clamav_status() -> dict[str, Any]:
    """Report whether ClamAV CLI is available on this host."""
    bin_path = _clamscan_bin()
    version = ""
    if bin_path:
        try:
            proc = subprocess.run(
                [bin_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            version = (proc.stdout or proc.stderr or "").strip().split("\n")[0]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {
        "available": bool(bin_path),
        "binary": bin_path or "",
        "version": version,
        "max_bytes": MAX_SCAN_BYTES,
        "install_hint": (
            "sudo apt install clamav && sudo freshclam"
            if not bin_path
            else ""
        ),
    }


def _parse_clam_output(stdout: str, stderr: str) -> tuple[str, str, list[str]]:
    """Return (verdict, summary, signatures)."""
    text = f"{stdout}\n{stderr}"
    if "OK" in text and "FOUND" not in text:
        return "CLEAN", "No threats detected by ClamAV.", []
    sigs = _FOUND_RE.findall(text)
    if sigs:
        return "MALICIOUS", f"ClamAV detected {len(sigs)} threat(s).", sigs
    if "ERROR" in text.upper():
        return "ERROR", "ClamAV scan error — see logs.", []
    return "CLEAN", "No threats detected by ClamAV.", []


def scan_file_path(path: Path) -> dict[str, Any]:
    """Scan a file on disk with clamscan/clamdscan."""
    started = time.time()
    bin_path = _clamscan_bin()
    if not bin_path:
        return {
            "verdict": "UNAVAILABLE",
            "available": False,
            "plain_summary": "ClamAV not installed on this machine.",
            "install_hint": "sudo apt install clamav && sudo freshclam",
        }

    if not path.is_file():
        return {"verdict": "ERROR", "error": "file not found", "available": True}

    size = path.stat().st_size
    if size > MAX_SCAN_BYTES:
        return {
            "verdict": "ERROR",
            "available": True,
            "error": f"file exceeds limit ({MAX_SCAN_BYTES} bytes)",
            "size_bytes": size,
        }

    args = [bin_path, "--no-summary", str(path)]
    if os.path.basename(bin_path) == "clamscan":
        args.insert(1, "--infected")

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "verdict": "ERROR",
            "available": True,
            "error": "scan timed out",
            "scan_time_ms": int((time.time() - started) * 1000),
        }

    verdict, summary, sigs = _parse_clam_output(proc.stdout, proc.stderr)
    return {
        "verdict": verdict,
        "available": True,
        "plain_summary": summary,
        "signatures": sigs,
        "exit_code": proc.returncode,
        "binary": bin_path,
        "size_bytes": size,
        "scan_time_ms": int((time.time() - started) * 1000),
    }


def scan_file_bytes(content: bytes, filename: str = "upload") -> dict[str, Any]:
    """
    Scan uploaded bytes with ClamAV, then cross-check SHA-256 via unified IOC engine.
    Temp file is deleted after scan.
    """
    from guardian.security.vault import data_dir

    if len(content) > MAX_SCAN_BYTES:
        return {
            "verdict": "ERROR",
            "error": f"File exceeds {MAX_SCAN_BYTES // (1024 * 1024)} MB limit",
            "filename": filename,
        }

    sha256 = hashlib.sha256(content).hexdigest()
    tmp_dir = data_dir() / "scan_temp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name.replace("..", "_") or "upload"
    tmp_path = tmp_dir / f"guardian-scan-{sha256[:12]}-{safe_name}"

    try:
        tmp_path.write_bytes(content)
        try:
            tmp_path.chmod(0o600)
        except OSError:
            pass
        clam = scan_file_path(tmp_path)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    ioc: dict[str, Any] = {}
    try:
        from guardian.intel.unified_scan import scan_ioc
        ioc = scan_ioc(sha256)
    except Exception as e:
        ioc = {"error": str(e)}

    combined = _combine_verdicts(clam.get("verdict", "UNAVAILABLE"), ioc.get("verdict", "CLEAN"))
    return {
        "filename": safe_name,
        "sha256": sha256,
        "size_bytes": len(content),
        "clamav": clam,
        "hash_intel": ioc,
        "verdict": combined,
        "plain_summary": _combined_summary(clam, ioc, combined),
        "engine": "guardian_clamav_unified",
    }


def _combine_verdicts(clam: str, ioc: str) -> str:
    order = {"MALICIOUS": 3, "SUSPICIOUS": 2, "ERROR": 1, "UNAVAILABLE": 0, "CLEAN": 0}
    best = "CLEAN"
    for v in (clam, ioc):
        if order.get(v, 0) > order.get(best, 0):
            best = v
    if clam == "MALICIOUS" or ioc == "MALICIOUS":
        return "MALICIOUS"
    if ioc == "SUSPICIOUS":
        return "SUSPICIOUS"
    if clam == "CLEAN" and ioc == "CLEAN":
        return "CLEAN"
    if clam in ("ERROR", "UNAVAILABLE") and ioc == "CLEAN":
        return ioc if clam == "UNAVAILABLE" else "ERROR"
    return best


def _combined_summary(clam: dict, ioc: dict, verdict: str) -> str:
    parts: list[str] = []
    if clam.get("available"):
        parts.append(clam.get("plain_summary", "ClamAV scan complete."))
    else:
        parts.append("ClamAV not installed — hash intelligence only.")
    if ioc.get("verdict") and ioc.get("verdict") != "CLEAN":
        parts.append(f"Hash intel: {ioc.get('verdict')} ({ioc.get('confidence', 0)}% confidence).")
    elif ioc.get("verdict") == "CLEAN" and clam.get("verdict") == "CLEAN":
        parts.append("Hash not found in threat feeds.")
    return " ".join(parts) if parts else f"Verdict: {verdict}"
