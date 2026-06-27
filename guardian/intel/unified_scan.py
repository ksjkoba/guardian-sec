"""
Unified free intelligence scan — parallel local feeds + live abuse.ch APIs.

Designed as a no-cost alternative stack (no HIBP, no VirusTotal API):
  - Local TI cache (feeds.py) — 100k+ IOCs
  - Live ThreatFox, URLhaus, MalwareBazaar (abuse.ch, free)
  - Heuristic suspicious-platform detection
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

_IOC_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_IOC_CACHE_LOCK = threading.Lock()
_IOC_CACHE_SECS = int(__import__("os").environ.get("GUARDIAN_IOC_CACHE_SECS", "300"))
_SCAN_TIMEOUT = float(__import__("os").environ.get("GUARDIAN_IOC_SCAN_TIMEOUT", "12"))

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_URL_RE = re.compile(r"^https?://", re.I)


def classify_ioc(value: str) -> str:
    v = value.strip()
    if _HASH_RE.match(v):
        return "hash"
    if _URL_RE.match(v):
        return "url"
    try:
        ipaddress.ip_address(v.split("/")[0].split(":")[0])
        return "ip"
    except ValueError:
        pass
    if "." in v:
        return "domain"
    return "unknown"


def _cache_get(value: str) -> dict[str, Any] | None:
    key = hashlib.sha256(value.strip().lower().encode()).hexdigest()
    with _IOC_CACHE_LOCK:
        hit = _IOC_CACHE.get(key)
        if hit and time.time() - hit[0] < _IOC_CACHE_SECS:
            return hit[1]
    return None


def _cache_set(value: str, result: dict[str, Any]) -> None:
    key = hashlib.sha256(value.strip().lower().encode()).hexdigest()
    with _IOC_CACHE_LOCK:
        _IOC_CACHE[key] = (time.time(), result)


def _scan_local(value: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    from guardian.intel.feeds import get_index
    from guardian.intel.heuristics import check_value

    index = get_index()
    matches = index.lookup(value)
    suspicious = check_value(value)
    local_matches = [
        {
            "feed": m.feed,
            "ioc_type": m.ioc_type,
            "malware_family": m.malware_family,
            "confidence": m.confidence,
            "source": "local_feed",
        }
        for m in matches
    ]
    susp = None
    if suspicious:
        susp = {
            "category": suspicious.category,
            "reason": suspicious.reason,
            "confidence": suspicious.confidence,
            "example_abuse": suspicious.example_abuse,
        }
    return local_matches, susp


def _scan_threatfox(value: str) -> dict[str, Any]:
    from guardian.intel.global_ticker import http_post_json

    try:
        data = http_post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "search_ioc", "search_term": value.strip()},
        )
        if data.get("query_status") != "ok":
            return {"source": "ThreatFox", "hit": False, "detail": data.get("query_status", "miss")}
        rows = data.get("data") or []
        if not rows:
            return {"source": "ThreatFox", "hit": False, "detail": "no match"}
        row = rows[0]
        malware = row.get("malware_printable") or row.get("malware") or ""
        ioc_id = row.get("id", "")
        return {
            "source": "ThreatFox",
            "hit": True,
            "malware_family": malware,
            "confidence": int(row.get("confidence_level") or 85),
            "detail": f"IOC listed — {malware or 'malware'}",
            "reference": f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else "",
        }
    except Exception as e:
        return {"source": "ThreatFox", "hit": False, "error": repr(e)}


def _scan_urlhaus(value: str, ioc_type: str) -> dict[str, Any]:
    from guardian.intel.global_ticker import http_post_json

    v = value.strip()
    try:
        if ioc_type == "url":
            payload = {"url": v}
            endpoint = "url"
        else:
            host = urlparse(v).hostname if ioc_type == "url" else v.split("/")[0]
            if not host:
                host = v
            payload = {"host": host}
            endpoint = "host"
        data = http_post_json(f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", payload)
        if data.get("query_status") != "ok":
            return {"source": "URLhaus", "hit": False, "detail": data.get("query_status", "miss")}
        if endpoint == "url":
            threat = data.get("threat") or data.get("url_status") or "malicious"
            if data.get("url_status") in ("online", "offline") or data.get("threat"):
                return {
                    "source": "URLhaus",
                    "hit": True,
                    "malware_family": str(data.get("threat", "")),
                    "confidence": 90,
                    "detail": f"URL {threat}",
                    "reference": data.get("urlhaus_reference", ""),
                }
        else:
            if int(data.get("url_count") or 0) > 0:
                return {
                    "source": "URLhaus",
                    "hit": True,
                    "confidence": 88,
                    "detail": f"{data.get('url_count')} malicious URL(s) on host",
                    "reference": "",
                }
        return {"source": "URLhaus", "hit": False, "detail": "clean"}
    except Exception as e:
        return {"source": "URLhaus", "hit": False, "error": repr(e)}


def _scan_malwarebazaar(value: str) -> dict[str, Any]:
    from guardian.intel.global_ticker import http_post_json

    try:
        data = http_post_json(
            "https://bazaar.abuse.ch/api/v1/",
            {"query": "get_info", "hash": value.strip().lower()},
        )
        if data.get("query_status") != "ok":
            return {"source": "MalwareBazaar", "hit": False, "detail": data.get("query_status", "miss")}
        info = data.get("data") or []
        if not info:
            return {"source": "MalwareBazaar", "hit": False, "detail": "unknown hash"}
        row = info[0] if isinstance(info, list) else info
        sig = row.get("signature") or row.get("malware") or "malware"
        return {
            "source": "MalwareBazaar",
            "hit": True,
            "malware_family": str(sig),
            "confidence": 95,
            "detail": f"Known malware sample — {sig}",
            "reference": f"https://bazaar.abuse.ch/sample/{value.strip().lower()}/",
        }
    except Exception as e:
        return {"source": "MalwareBazaar", "hit": False, "error": repr(e)}


def scan_ioc(value: str) -> dict[str, Any]:
    """Parallel unified IOC scan — local feeds + live abuse.ch APIs."""
    v = value.strip()
    if not v:
        return {"error": "value required"}

    cached = _cache_get(v)
    if cached:
        cached = dict(cached)
        cached["from_cache"] = True
        return cached

    started = time.time()
    ioc_type = classify_ioc(v)
    live_hits: list[dict[str, Any]] = []
    sources_checked = ["Local TI cache", "Heuristics"]
    source_errors: list[str] = []

    local_matches, suspicious = _scan_local(v)

    tasks: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        tasks["threatfox"] = pool.submit(_scan_threatfox, v)
        if ioc_type in ("url", "domain"):
            tasks["urlhaus"] = pool.submit(_scan_urlhaus, v, "url" if ioc_type == "url" else "domain")
        elif ioc_type == "hash":
            tasks["malwarebazaar"] = pool.submit(_scan_malwarebazaar, v)

        labels = {"threatfox": "ThreatFox", "urlhaus": "URLhaus", "malwarebazaar": "MalwareBazaar"}
        for name, fut in tasks.items():
            sources_checked.append(labels[name])
            try:
                res = fut.result(timeout=_SCAN_TIMEOUT)
                if res.get("hit"):
                    live_hits.append(res)
                elif res.get("error"):
                    source_errors.append(f"{labels[name]}: {res['error']}")
            except Exception as e:
                source_errors.append(f"{labels[name]}: {e!r}")

    malicious_local = len(local_matches) > 0
    malicious_live = any(h.get("hit") for h in live_hits if isinstance(h, dict))
    suspicious_flag = suspicious is not None and not malicious_local and not malicious_live

    if malicious_live or malicious_local:
        verdict = "MALICIOUS"
        confidence = max(
            [m.get("confidence", 80) for m in local_matches]
            + [h.get("confidence", 85) for h in live_hits if h.get("hit")]
            or [85]
        )
    elif suspicious_flag:
        verdict = "SUSPICIOUS"
        confidence = suspicious.get("confidence", 60) if suspicious else 55
    else:
        verdict = "CLEAN"
        confidence = 0

    try:
        from guardian.intel.feeds import get_index
        total_iocs = get_index().total_iocs
    except Exception:
        total_iocs = 0

    out: dict[str, Any] = {
        "value": v,
        "ioc_type": ioc_type,
        "verdict": verdict,
        "malicious": verdict == "MALICIOUS",
        "suspicious": verdict == "SUSPICIOUS",
        "confidence": confidence,
        "matches": local_matches,
        "live_hits": live_hits,
        "sources_checked": sources_checked,
        "source_errors": source_errors,
        "suspicious_platform": suspicious,
        "total_iocs_checked": total_iocs,
        "scan_time_ms": int((time.time() - started) * 1000),
        "engine": "guardian_unified_free",
    }
    _cache_set(v, out)
    return out
