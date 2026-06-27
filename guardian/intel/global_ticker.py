"""
Global threat ticker — polls worldwide TI sources and pushes new IOCs/alerts
to the live dashboard. Also supports inbound webhook pushes from external systems.
"""

from __future__ import annotations

import csv
import json
import os
import re
import ssl
import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from guardian.engine.alert import Alert, Severity

MODULE = "global_feed"
USER_AGENT = "Guardian-TI/1.0 (security research)"
REQUEST_TIMEOUT = 20
PER_SOURCE_FETCH_TIMEOUT = REQUEST_TIMEOUT + 8
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
PHISHTANK_CACHE_SECS = 900  # 15 min — large feed; avoid rate limits
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_SECS = 900
BLOCKLIST_DE_FEED_URL = "https://lists.blocklist.de/lists/all.txt"
BLOCKLIST_DE_CACHE_SECS = 900
TOR_EXIT_FEED_URL = "https://check.torproject.org/torbulkexitlist"
TOR_EXIT_CACHE_SECS = 900
SSLBL_FEED_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

_phishtank_csv_cache: tuple[float, str] | None = None
_openphish_cache: tuple[float, list[str]] | None = None
_blocklist_de_cache: tuple[float, set[str]] | None = None
_tor_exit_cache: tuple[float, set[str]] | None = None


def _phishtank_csv_text(force: bool = False) -> str:
    global _phishtank_csv_cache
    now = time.time()
    if not force and _phishtank_csv_cache and now - _phishtank_csv_cache[0] < PHISHTANK_CACHE_SECS:
        return _phishtank_csv_cache[1]
    try:
        text = http_get(PHISHTANK_FEED_URL).decode(errors="replace")
        _phishtank_csv_cache = (now, text)
        return text
    except Exception as e:
        err = repr(e)
        if _phishtank_csv_cache and ("429" in err or "404" in err or "Too Many" in err):
            age = int(now - _phishtank_csv_cache[0])
            print(f"[global_feed] PhishTank: using cached CSV ({age}s old) — {err}")
            return _phishtank_csv_cache[1]
        raise


def load_phishtank_entries(force: bool = False, limit: int | None = None) -> list[dict]:
    """Parse PhishTank verified-online CSV (community-verified phishing URLs)."""
    text = _phishtank_csv_text(force=force)
    entries: list[dict] = []
    for row in csv.DictReader(text.splitlines()):
        if row.get("verified") != "yes" or row.get("online") != "yes":
            continue
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        entries.append(dict(row))
        if limit and len(entries) >= limit:
            break
    return entries


def load_openphish_urls(force: bool = False) -> list[str]:
    """Load OpenPhish active URL feed with cache + stale fallback on proxy errors."""
    global _openphish_cache
    now = time.time()
    if not force and _openphish_cache and now - _openphish_cache[0] < OPENPHISH_CACHE_SECS:
        return _openphish_cache[1]
    try:
        raw = http_get(OPENPHISH_FEED_URL).decode(errors="replace")
        urls = [line.strip() for line in raw.splitlines() if line.strip().startswith("http")]
        _openphish_cache = (now, urls)
        return urls
    except Exception as e:
        err = repr(e)
        if _openphish_cache and (
            "reset" in err.lower() or "429" in err or "404" in err or "Connection" in err
        ):
            age = int(now - _openphish_cache[0])
            print(f"[global_feed] OpenPhish: using cached feed ({age}s old) — {err}")
            return _openphish_cache[1]
        raise


def load_blocklist_de_ips(force: bool = False) -> set[str]:
    """Parse blocklist.de all-IPs list with cache."""
    global _blocklist_de_cache
    now = time.time()
    if not force and _blocklist_de_cache and now - _blocklist_de_cache[0] < BLOCKLIST_DE_CACHE_SECS:
        return _blocklist_de_cache[1]
    try:
        text = http_get(BLOCKLIST_DE_FEED_URL).decode(errors="replace")
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split()[0].strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                ips.add(ip)
        _blocklist_de_cache = (now, ips)
        return ips
    except Exception as e:
        err = repr(e)
        if _blocklist_de_cache and ("429" in err or "404" in err):
            age = int(now - _blocklist_de_cache[0])
            print(f"[global_feed] blocklist.de: using cached list ({age}s old) — {err}")
            return _blocklist_de_cache[1]
        raise


def load_tor_exit_ips(force: bool = False) -> set[str]:
    """Load Tor Project bulk exit node list with cache."""
    global _tor_exit_cache
    now = time.time()
    if not force and _tor_exit_cache and now - _tor_exit_cache[0] < TOR_EXIT_CACHE_SECS:
        return _tor_exit_cache[1]
    try:
        text = http_get(TOR_EXIT_FEED_URL).decode(errors="replace")
        ips = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                ips.add(line)
        _tor_exit_cache = (now, ips)
        return ips
    except Exception as e:
        err = repr(e)
        if _tor_exit_cache and ("429" in err or "404" in err):
            age = int(now - _tor_exit_cache[0])
            print(f"[global_feed] Tor Exit: using cached list ({age}s old) — {err}")
            return _tor_exit_cache[1]
        raise

# Official source registry — shown on dashboard with links
SOURCE_REGISTRY: dict[str, dict[str, str]] = {
    "ThreatFox": {
        "homepage": "https://threatfox.abuse.ch/",
        "label": "ThreatFox (abuse.ch)",
        "description": "Community-reported malware command-and-control servers and indicators, curated by abuse.ch.",
        "refresh": "Export refreshed about every hour",
    },
    "URLhaus": {
        "homepage": "https://urlhaus.abuse.ch/",
        "label": "URLhaus (abuse.ch)",
        "description": "Database of websites hosting or distributing malware.",
        "refresh": "Updated continuously by researchers worldwide",
    },
    "MalwareBazaar": {
        "homepage": "https://bazaar.abuse.ch/",
        "label": "MalwareBazaar (abuse.ch)",
        "description": "Repository of newly discovered malware file samples (hashes).",
        "refresh": "New samples added as they are submitted",
    },
    "CISA-KEV": {
        "homepage": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "label": "CISA Known Exploited Vulnerabilities",
        "description": "U.S. government catalog of vulnerabilities actively exploited in the wild.",
        "refresh": "Updated when CISA adds new entries",
    },
    "OpenPhish": {
        "homepage": "https://openphish.com/",
        "label": "OpenPhish",
        "description": "Feed of currently active phishing websites.",
        "refresh": "Updated every few minutes",
    },
    "Feodo Tracker": {
        "homepage": "https://feodotracker.abuse.ch/",
        "label": "Feodo Tracker (abuse.ch)",
        "description": "Botnet command-and-control IP blocklist (Emotet, Dridex, QakBot, etc.).",
        "refresh": "Updated as C2 servers are discovered",
    },
    "PhishTank": {
        "homepage": "https://www.phishtank.com/",
        "label": "PhishTank (OpenDNS/Cisco)",
        "description": "Community-verified active phishing URLs.",
        "refresh": "Updated continuously; only verified-online entries ingested",
    },
    "Spamhaus DROP": {
        "homepage": "https://www.spamhaus.org/drop/",
        "label": "Spamhaus DROP",
        "description": "Hijacked network ranges that should not appear in global routing.",
        "refresh": "Updated when Spamhaus adds or removes netblocks",
    },
    "URLhaus-Hosts": {
        "homepage": "https://urlhaus.abuse.ch/",
        "label": "URLhaus Hosts (abuse.ch)",
        "description": "Malicious hostnames seen distributing malware (host file export).",
        "refresh": "Updated continuously",
    },
    "SSLBL": {
        "homepage": "https://sslbl.abuse.ch/",
        "label": "SSLBL (abuse.ch)",
        "description": "Malicious SSL/TLS endpoints linked to botnet and malware infrastructure.",
        "refresh": "Updated as new malicious SSL IPs are discovered",
    },
    "blocklist.de": {
        "homepage": "https://www.blocklist.de/",
        "label": "blocklist.de",
        "description": "Community-reported IPs from SSH, mail, and web brute-force attacks.",
        "refresh": "Updated continuously from abuse reports",
    },
    "Tor Exit Nodes": {
        "homepage": "https://www.torproject.org/",
        "label": "Tor Exit Nodes",
        "description": "Official Tor Project bulk exit node list — awareness only (Tor is not inherently malicious).",
        "refresh": "Updated by the Tor Project",
    },
}

SEVERITY_PLAIN = {
    "CRITICAL": "Urgent — needs immediate attention",
    "HIGH": "Serious threat",
    "MEDIUM": "Worth investigating",
    "LOW": "Low priority",
    "INFO": "For your awareness",
}

# Max items pulled per provider each poll (balanced — no single source dominates)
DEFAULT_PER_SOURCE_QUOTA = 6

_RANSOMWARE_FAMILIES = frozenset({
    "emotet", "cobalt strike", "cobalt", "asyncrat", "remcos", "quasar",
    "agent tesla", "redline", "vidar", "lockbit", "blackcat", "ransom",
})

# Generic / reporter labels on MalwareBazaar — not distinct malware families
_GENERIC_MB_SIGNATURES = frozenset({
    "abuse_ch", "unknown", "generic", "test", "n/a", "na",
})
_REPORTER_MB_SIGNATURES = frozenset({
    "bitsight", "securiteinfocom", "virustotal", "anyrun",
})

# URLhaus tags that usually indicate commodity droppers, not targeted attacks
_LOW_PRIORITY_URL_TAGS = frozenset({
    "ua-wget", "wget", "elf", "32-bit", "mips", "mirai",
})


def classify_severity(
    source: str,
    threat_type: str = "",
    ioc_type: str = "ip",
    malware_family: str = "",
    tags: tuple[str, ...] = (),
    confidence: int = 0,
) -> Severity:
    """Map provider + context to a realistic severity distribution."""
    tt = threat_type.lower().replace(" ", "_")
    fam = (malware_family or "").lower().strip()
    tagset = {t.lower() for t in tags if t}

    if source == "OpenPhish":
        # Global phishing URLs — awareness, not direct local impact
        return Severity.LOW

    if source == "CISA-KEV":
        return Severity.CRITICAL

    if source == "MalwareBazaar":
        if not fam or fam in _GENERIC_MB_SIGNATURES or "unknown" in fam:
            return Severity.LOW
        if fam in _REPORTER_MB_SIGNATURES:
            return Severity.LOW
        if any(r in fam for r in _RANSOMWARE_FAMILIES):
            return Severity.HIGH
        return Severity.MEDIUM

    if source == "URLhaus":
        if "phish" in tt or any("phish" in t for t in tagset):
            return Severity.LOW
        if any(r in fam for r in _RANSOMWARE_FAMILIES) or "stealer" in tagset:
            return Severity.HIGH
        if "malware" in tt:
            lowish = tagset and tagset.issubset(_LOW_PRIORITY_URL_TAGS | {"malware"})
            if lowish or fam in _LOW_PRIORITY_URL_TAGS:
                return Severity.LOW
            return Severity.MEDIUM
        return Severity.MEDIUM

    if source == "ThreatFox":
        if "botnet" in tt or "c2" in tt or "cc" in tt:
            if confidence >= 90:
                return Severity.CRITICAL
            if confidence >= 70:
                return Severity.HIGH
            return Severity.MEDIUM
        if "payload" in tt:
            if confidence and confidence < 60:
                return Severity.LOW
            return Severity.MEDIUM
        if "phish" in tt or "skimming" in tt:
            return Severity.LOW
        if confidence and confidence < 50:
            return Severity.LOW
        return Severity.MEDIUM

    if source == "PhishTank":
        return Severity.LOW

    if source == "Feodo Tracker":
        if "online" in tagset:
            return Severity.HIGH
        return Severity.MEDIUM

    if source == "Spamhaus DROP":
        return Severity.MEDIUM

    if source == "URLhaus-Hosts":
        return Severity.LOW

    if source == "SSLBL":
        return Severity.MEDIUM

    if source == "blocklist.de":
        return Severity.LOW

    if source == "Tor Exit Nodes":
        return Severity.LOW

    return Severity.MEDIUM

# ─── HTTP helpers (corporate proxy / SSL tolerant) ───────────────────────────

def _ssl_contexts() -> list[ssl.SSLContext]:
    contexts: list[ssl.SSLContext] = []
    if os.environ.get("GUARDIAN_INSECURE_SSL", "").lower() in ("1", "true", "yes"):
        contexts.append(ssl._create_unverified_context())
    pem = Path(os.environ.get("GUARDIAN_CA_BUNDLE", Path.home() / "guardian" / "proxy-chain.pem"))
    if pem.exists():
        try:
            contexts.append(ssl.create_default_context(cafile=str(pem)))
        except ssl.SSLError:
            pass
    contexts.append(ssl.create_default_context())
    # Last resort for broken corporate TLS interception
    contexts.append(ssl._create_unverified_context())
    seen: set[int] = set()
    unique: list[ssl.SSLContext] = []
    for ctx in contexts:
        key = id(ctx)
        if key not in seen:
            seen.add(key)
            unique.append(ctx)
    return unique


def http_get(url: str, headers: dict[str, str] | None = None) -> bytes:
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    last_err: Exception | None = None
    for ctx in _ssl_contexts():
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
                return resp.read()
        except Exception as e:
            last_err = e
    raise last_err or RuntimeError(f"GET failed: {url}")


def http_post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> dict:
    hdrs = {"User-Agent": USER_AGENT, "Content-Type": "application/json", **(headers or {})}
    data = json.dumps(payload).encode()
    last_err: Exception | None = None
    for ctx in _ssl_contexts():
        try:
            req = urllib.request.Request(url, data=data, method="POST", headers=hdrs)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            last_err = e
    raise last_err or RuntimeError(f"POST failed: {url}")


# ─── Threat item model ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GlobalThreatItem:
    source: str
    ioc_type: str          # ip, domain, url, hash, cve, phishing
    value: str
    title: str
    description: str
    malware_family: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    reference: str = ""
    external_id: str = ""
    severity: Severity = Severity.MEDIUM
    threat_type: str = ""
    confidence: int = 0

    @property
    def dedup_key(self) -> str:
        return f"{self.source}:{self.external_id or self.value}"

    @property
    def canonical_ioc_key(self) -> str:
        return normalize_ioc(self.ioc_type, self.value)


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Cross-source dedup key — same IOC from different providers maps to one key."""
    v = (value or "").strip()
    t = (ioc_type or "").strip().lower()
    if t in ("url", "phishing"):
        t = "url"
        v = v.lower().rstrip("/")
    elif t == "domain":
        v = v.lower().strip(".")
    elif t == "ip":
        v = v.strip()
    elif t == "hash":
        v = v.lower()
    elif t == "cve":
        v = v.upper()
    elif t == "cidr":
        v = v.strip()
    return f"{t}:{v}"


def item_to_alert(item: GlobalThreatItem) -> Alert:
    src = SOURCE_REGISTRY.get(item.source, {})
    homepage = src.get("homepage", "")
    ref = item.reference if item.reference and item.reference.lower() != "none" else homepage

    if item.ioc_type == "ip":
        plain = (
            f"A known malicious server ({item.malware_family or 'unknown malware'}) "
            f"was reported at {item.value}. Sourced from {item.source}, a global threat database."
        )
    elif item.ioc_type in ("url", "phishing"):
        plain = f"A harmful website was reported by {item.source}: {item.value[:100]}"
    elif item.ioc_type == "hash":
        plain = f"A new malware file (hash) was added to {item.source} — signature: {item.malware_family or 'unknown'}."
    elif item.ioc_type == "cve":
        plain = f"A security flaw ({item.value}) is being actively exploited in the wild, per CISA."
    elif item.ioc_type == "cidr":
        plain = (
            f"A hijacked network range ({item.value}) is listed on Spamhaus DROP — "
            f"traffic to this block should not be routed on the public internet."
        )
    elif item.ioc_type == "domain":
        plain = f"A malicious hostname was reported by {item.source}: {item.value}"
    else:
        plain = item.description

    rec_plain = (
        "You do not need to act unless this appeared on your own network or devices. "
        "If unsure, share this alert with your IT or security team."
    )

    meta: dict[str, Any] = {
        "global_source": item.source,
        "source_label": src.get("label", item.source),
        "source_homepage": homepage,
        "source_description": src.get("description", ""),
        "reference_url": ref,
        "ioc_type": item.ioc_type,
        "ioc_value": item.value,
        "tags": list(item.tags),
        "plain_summary": plain,
        "severity_plain": SEVERITY_PLAIN.get(item.severity.value, ""),
        "recommendation_plain": rec_plain,
        "is_global_feed": True,
        "threat_type": item.threat_type,
        "confidence": item.confidence,
        "verified": True,
        "verified_at": time.time(),
        "verified_method": "ingested_from_live_feed",
        "verified_detail": f"Pulled live from {item.source} — not generated by AI.",
        "verified_found": True,
    }
    if item.malware_family:
        meta["malware_family"] = item.malware_family
        meta["ioc_tag"] = f"GLOBAL:{item.source}"
        meta["ioc_matches"] = [{
            "feed": item.source,
            "ioc_type": item.ioc_type,
            "malware_family": item.malware_family,
            "confidence": 85,
        }]
    return Alert(
        module=MODULE,
        title=item.title,
        description=item.description,
        severity=item.severity,
        evidence=item.value,
        recommendation=rec_plain,
        metadata=meta,
    )


def push_payload_to_alert(payload: dict) -> Alert:
    """Convert an inbound webhook JSON body to a dashboard alert."""
    sev_name = str(payload.get("severity", "MEDIUM")).upper()
    try:
        severity = Severity[sev_name]
    except KeyError:
        severity = Severity.MEDIUM

    source = str(payload.get("source", "external"))
    ioc_type = str(payload.get("ioc_type", ""))
    ioc_value = str(payload.get("ioc_value", payload.get("value", "")))
    meta: dict[str, Any] = {
        "global_source": source,
        "source_label": str(payload.get("source_label", source)),
        "source_homepage": str(payload.get("source_homepage", "")),
        "reference_url": str(payload.get("reference_url", payload.get("reference", ""))),
        "tags": payload.get("tags", []),
        "external_id": payload.get("external_id", ""),
        "plain_summary": str(payload.get("plain_summary", payload.get("description", ""))),
        "is_global_feed": True,
    }
    if ioc_type and ioc_value:
        meta["ioc_type"] = ioc_type
        meta["ioc_value"] = ioc_value

    return Alert(
        module=MODULE,
        title=str(payload.get("title", "External threat report")),
        description=str(payload.get("description", "")),
        severity=severity,
        evidence=str(payload.get("evidence", ioc_value)),
        recommendation=str(payload.get("recommendation", "Investigate and correlate with local telemetry.")),
        metadata=meta,
    )


# ─── Source fetchers ─────────────────────────────────────────────────────────

def _abuse_headers() -> dict[str, str]:
    key = os.environ.get("ABUSE_CH_AUTH_KEY") or os.environ.get("GUARDIAN_ABUSE_CH_KEY", "")
    return {"Auth-Key": key} if key else {}


def _parse_threatfox_recent_rows(raw: bytes) -> list[dict[str, str]]:
    """Parse ThreatFox recent CSV using the header row for correct column mapping."""
    rows: list[dict[str, str]] = []
    headers: list[str] = []
    for line in raw.decode(errors="replace").splitlines():
        if not line or (line.startswith("#") and "ioc_id" not in line):
            continue
        if "ioc_id" in line and line.startswith("#"):
            header_line = line.lstrip("# ").strip()
            try:
                headers = [h.strip().strip('"') for h in next(csv.reader([header_line], quotechar='"'))]
            except Exception:
                headers = []
            continue
        try:
            cols = next(csv.reader([line], quotechar='"'))
        except Exception:
            continue
        if headers and len(cols) >= len(headers):
            data = {headers[i]: cols[i].strip().strip('"') for i in range(len(headers))}
        elif len(cols) >= 13:
            data = {
                "ioc_id": cols[1].strip().strip('"'),
                "ioc_value": cols[2].strip().strip('"'),
                "threat_type": cols[4].strip().strip('"'),
                "fk_malware": cols[5].strip().strip('"'),
                "malware_printable": cols[7].strip().strip('"'),
                "reference": cols[11].strip().strip('"'),
                "tags": cols[12].strip().strip('"'),
            }
        else:
            continue

        ioc_raw = data.get("ioc_value", "")
        ioc = ioc_raw.rsplit(":", 1)[0] if ":" in ioc_raw and not ioc_raw.startswith("http") else ioc_raw
        ioc_id = data.get("ioc_id", "")
        malware = data.get("malware_printable") or data.get("fk_malware") or "unknown malware"
        ref = data.get("reference", "")
        if not ref or ref.lower() == "none":
            ref = f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
        conf = 0
        try:
            conf = int(data.get("confidence_level", 0) or 0)
        except (TypeError, ValueError):
            pass

        rows.append({
            "ioc_id": ioc_id,
            "ioc": ioc,
            "malware": malware,
            "threat_type": data.get("threat_type", ""),
            "tags": data.get("tags", ""),
            "reference": ref,
            "confidence": conf,
        })
    return rows


def fetch_threatfox_export(limit: int = 40) -> list[GlobalThreatItem]:
    items: list[GlobalThreatItem] = []
    raw = http_get("https://threatfox.abuse.ch/export/csv/ip-port/recent/")
    for row in _parse_threatfox_recent_rows(raw):
        malware = row["malware"]
        ioc = row["ioc"]
        threat = row["threat_type"].replace("_", " ")
        tags = tuple(t for t in row["tags"].split(",") if t.strip()) or ("threatfox", "global")
        conf = int(row.get("confidence", 0) or 0)
        sev = classify_severity("ThreatFox", row["threat_type"], "ip", malware, tags, conf)
        items.append(GlobalThreatItem(
            source="ThreatFox",
            ioc_type="ip",
            value=ioc,
            title=f"ThreatFox: {malware or threat} on {ioc}",
            description=f"Global {threat or 'threat'} — {ioc} linked to {malware or 'unknown malware'}.",
            malware_family=malware,
            tags=tags,
            reference=row["reference"],
            external_id=f"tf:{row['ioc_id']}",
            severity=sev,
            threat_type=row["threat_type"],
            confidence=conf,
        ))
        if len(items) >= limit:
            break
    return items


def fetch_threatfox_api(limit: int = 40) -> list[GlobalThreatItem]:
    if not _abuse_headers().get("Auth-Key"):
        return []
    data = http_post_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        {"query": "get_iocs", "days": 1},
        headers=_abuse_headers(),
    )
    items: list[GlobalThreatItem] = []
    for row in data.get("data", []):
        ioc = str(row.get("ioc", ""))
        if not ioc:
            continue
        ioc_type = str(row.get("ioc_type", "ip"))
        malware = str(row.get("malware_printable") or row.get("malware") or "")
        items.append(GlobalThreatItem(
            source="ThreatFox",
            ioc_type=ioc_type,
            value=ioc,
            title=f"ThreatFox: {malware or ioc_type} threat",
            description=str(row.get("threat_type_desc") or f"Global {ioc_type} IOC observed."),
            malware_family=malware,
            tags=tuple(row.get("tags", []) or ("threatfox", "global")),
            reference=f"https://threatfox.abuse.ch/ioc/{row.get('id', '')}/",
            external_id=f"tfapi:{row.get('id', ioc)}",
            severity=Severity.HIGH,
        ))
        if len(items) >= limit:
            break
    return items


def fetch_urlhaus_export(limit: int = 40) -> list[GlobalThreatItem]:
    raw = http_get("https://urlhaus.abuse.ch/downloads/csv_recent/").decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            row = next(csv.reader([line], quotechar='"'))
        except Exception:
            continue
        if len(row) < 6:
            continue
        url_id = row[0].strip().strip('"')
        url = row[2].strip().strip('"')
        threat = row[5].strip().strip('"').replace("_", " ") if len(row) > 5 else "malware"
        tags_str = row[6].strip().strip('"') if len(row) > 6 else ""
        ref = row[7].strip().strip('"') if len(row) > 7 and row[7].strip() else f"https://urlhaus.abuse.ch/url/{url_id}/"
        if not url.startswith("http"):
            continue
        tag_list = tuple(t.strip() for t in tags_str.split(",") if t.strip()) or ("urlhaus", "global")
        family = next((t for t in tag_list if t not in ("urlhaus", "malware", "global", "32-bit", "64-bit", "elf")), threat)
        sev = classify_severity("URLhaus", threat.replace(" ", "_"), "url", family, tag_list)
        items.append(GlobalThreatItem(
            source="URLhaus",
            ioc_type="url",
            value=url,
            title=f"URLhaus: {threat} — {url[:60]}",
            description=f"Harmful website reported globally — distributes {threat}.",
            malware_family=family,
            tags=tag_list,
            reference=ref,
            external_id=f"uh:{url_id}",
            severity=sev,
            threat_type=threat.replace(" ", "_"),
        ))
        if len(items) >= limit:
            break
    return items


def fetch_malwarebazaar_export(limit: int = 30) -> list[GlobalThreatItem]:
    raw = http_get("https://bazaar.abuse.ch/export/csv/recent/").decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            row = next(csv.reader([line], quotechar='"'))
        except Exception:
            continue
        if len(row) < 5:
            continue
        sha256 = row[1].strip().strip('"')
        sig = row[4].strip().strip('"') if len(row) > 4 else ""
        if len(sha256) != 64:
            continue
        sev = classify_severity("MalwareBazaar", "", "hash", sig, ("malwarebazaar", "hash"))
        items.append(GlobalThreatItem(
            source="MalwareBazaar",
            ioc_type="hash",
            value=sha256,
            title=f"MalwareBazaar: {sig or 'new malware sample'}",
            description=f"Fresh malware hash observed globally — {sha256[:16]}…",
            malware_family=sig,
            tags=("malwarebazaar", "hash", "global"),
            reference=f"https://bazaar.abuse.ch/sample/{sha256}/",
            external_id=f"mb:{sha256}",
            severity=sev,
        ))
        if len(items) >= limit:
            break
    return items


def fetch_cisa_kev(days: int = 30, limit: int = 15) -> list[GlobalThreatItem]:
    raw = http_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    data = json.loads(raw.decode())
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
    today = datetime.now(timezone.utc).date()
    items: list[GlobalThreatItem] = []
    for vuln in reversed(data.get("vulnerabilities", [])):
        added = vuln.get("dateAdded", "")
        try:
            added_date = datetime.strptime(added, "%Y-%m-%d").date()
        except ValueError:
            continue
        if added_date < cutoff:
            continue
        cve = vuln.get("cveID", "")
        age_days = (today - added_date).days
        if age_days <= 3:
            sev = Severity.CRITICAL
        elif age_days <= 14:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        items.append(GlobalThreatItem(
            source="CISA-KEV",
            ioc_type="cve",
            value=cve,
            title=f"CISA KEV: {cve} — {vuln.get('vendorProject', '')} {vuln.get('product', '')}",
            description=vuln.get("shortDescription", ""),
            tags=("kev", "vulnerability", "global"),
            reference=vuln.get("notes", f"https://nvd.nist.gov/vuln/detail/{cve}"),
            external_id=f"kev:{cve}",
            severity=sev,
            threat_type="known_exploited",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_openphish(limit: int = 25) -> list[GlobalThreatItem]:
    urls = load_openphish_urls()
    items: list[GlobalThreatItem] = []
    for url in urls:
        sev = classify_severity("OpenPhish", "phishing", "url", "", ("phishing",))
        items.append(GlobalThreatItem(
            source="OpenPhish",
            ioc_type="phishing",
            value=url,
            title="OpenPhish: active phishing URL",
            description=f"Globally active phishing site — {url[:120]}",
            tags=("phishing", "openphish", "global"),
            reference=url,
            external_id=f"op:{hash(url) & 0xFFFFFFFF:08x}",
            severity=sev,
            threat_type="phishing",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_feodo_tracker(limit: int = 30) -> list[GlobalThreatItem]:
    raw = http_get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if not row or row[0] == "first_seen_utc":
            continue
        if len(row) < 6:
            continue
        _first, ip, port, status, _last, malware = row[:6]
        status = status.strip().lower()
        malware = malware.strip()
        sev = classify_severity(
            "Feodo Tracker", "botnet_cc", "ip", malware, (status, "c2"),
            confidence=90 if status == "online" else 50,
        )
        items.append(GlobalThreatItem(
            source="Feodo Tracker",
            ioc_type="ip",
            value=ip.strip(),
            title=f"Feodo Tracker: {malware} C2 on {ip}:{port}",
            description=f"Botnet command-and-control ({malware}) — status {status}.",
            malware_family=malware,
            tags=("botnet", "c2", status),
            reference=f"https://feodotracker.abuse.ch/browse/host/{ip.strip()}/",
            external_id=f"feodo:{ip.strip()}:{port.strip()}",
            severity=sev,
            threat_type="botnet_cc",
            confidence=90 if status == "online" else 50,
        ))
        if len(items) >= limit:
            break
    return items


def fetch_phishtank(limit: int = 30) -> list[GlobalThreatItem]:
    entries = load_phishtank_entries(limit=limit)
    items: list[GlobalThreatItem] = []
    for entry in entries:
        if entry.get("verified") != "yes" or entry.get("online") != "yes":
            continue
        url = str(entry.get("url") or "").strip()
        if not url:
            continue
        phish_id = str(entry.get("phish_id") or "")
        target = str(entry.get("target") or "Phishing")
        detail = str(
            entry.get("phish_detail_url")
            or f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
        )
        sev = classify_severity("PhishTank", "phishing", "url", target, ("verified", "phishing"))
        items.append(GlobalThreatItem(
            source="PhishTank",
            ioc_type="url",
            value=url,
            title=f"PhishTank: {target} phishing — {url[:70]}",
            description=f"Community-verified active phishing site impersonating {target}.",
            malware_family=target,
            tags=("phishing", "verified", target.lower().replace(" ", "_")),
            reference=detail,
            external_id=f"pt:{phish_id}",
            severity=sev,
            threat_type="phishing",
            confidence=90,
        ))
        if len(items) >= limit:
            break
    return items


def fetch_spamhaus_drop(limit: int = 30) -> list[GlobalThreatItem]:
    raw = http_get("https://www.spamhaus.org/drop/drop.txt").decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";")
        cidr = parts[0].strip()
        sbl = parts[1].strip() if len(parts) > 1 else ""
        if not cidr or "/" not in cidr:
            continue
        sev = classify_severity("Spamhaus DROP", "hijacked_network", "cidr", sbl, ("drop", "spamhaus"))
        items.append(GlobalThreatItem(
            source="Spamhaus DROP",
            ioc_type="cidr",
            value=cidr,
            title=f"Spamhaus DROP: hijacked netblock {cidr}",
            description=f"Hijacked network range on Spamhaus DROP ({sbl or 'should not be routed'}).",
            tags=("drop", "spamhaus", "netblock"),
            reference="https://www.spamhaus.org/drop/",
            external_id=f"drop:{cidr}",
            severity=sev,
            threat_type="hijacked_network",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_urlhaus_hosts(limit: int = 30) -> list[GlobalThreatItem]:
    raw = http_get("https://urlhaus.abuse.ch/downloads/hostfile/").decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("	")
        if len(parts) < 2:
            continue
        ip, hostname = parts[0].strip(), parts[1].strip()
        # URLhaus hostfile uses 127.0.0.1 as the sinkhole placeholder for every entry
        if not hostname or hostname in ("localhost",):
            continue
        sev = classify_severity("URLhaus-Hosts", "malware_host", "domain", hostname, ("hostfile",))
        items.append(GlobalThreatItem(
            source="URLhaus-Hosts",
            ioc_type="domain",
            value=hostname,
            title=f"URLhaus host: {hostname}",
            description=f"Malicious hostname in URLhaus host file (resolves to {ip}).",
            malware_family=hostname,
            tags=("hostfile", "domain"),
            reference=f"https://urlhaus.abuse.ch/host/{hostname}/",
            external_id=f"uhhost:{hostname.lower()}",
            severity=sev,
            threat_type="malware_host",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_sslbl(limit: int = 30) -> list[GlobalThreatItem]:
    raw = http_get(SSLBL_FEED_URL).decode(errors="replace")
    items: list[GlobalThreatItem] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if not row or row[0].lower().startswith("first"):
            continue
        if len(row) < 2:
            continue
        ip = row[1].strip() if len(row) > 1 else row[0].strip()
        reason = row[3].strip() if len(row) > 3 else (row[2].strip() if len(row) > 2 else "malicious SSL")
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            continue
        sev = classify_severity("SSLBL", "malicious_ssl", "ip", reason, ("sslbl",))
        items.append(GlobalThreatItem(
            source="SSLBL",
            ioc_type="ip",
            value=ip,
            title=f"SSLBL: malicious SSL endpoint {ip}",
            description=f"IP linked to malicious SSL/TLS activity — {reason}.",
            malware_family=reason,
            tags=("sslbl", "ssl", "global"),
            reference=f"https://sslbl.abuse.ch/sslblip/{ip}/",
            external_id=f"sslbl:{ip}",
            severity=sev,
            threat_type="malicious_ssl",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_blocklist_de(limit: int = 30) -> list[GlobalThreatItem]:
    ips = load_blocklist_de_ips()
    items: list[GlobalThreatItem] = []
    for ip in sorted(ips):
        sev = classify_severity("blocklist.de", "brute_force", "ip", "", ("blocklist",))
        items.append(GlobalThreatItem(
            source="blocklist.de",
            ioc_type="ip",
            value=ip,
            title=f"blocklist.de: attack source {ip}",
            description="IP reported for brute-force or abuse activity on blocklist.de.",
            tags=("blocklist", "brute_force", "global"),
            reference="https://www.blocklist.de/en/view.html?ip=" + ip,
            external_id=f"bld:{ip}",
            severity=sev,
            threat_type="brute_force",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_tor_exits(limit: int = 30) -> list[GlobalThreatItem]:
    ips = load_tor_exit_ips()
    items: list[GlobalThreatItem] = []
    for ip in sorted(ips):
        sev = classify_severity("Tor Exit Nodes", "tor_exit", "ip", "", ("tor", "exit"))
        items.append(GlobalThreatItem(
            source="Tor Exit Nodes",
            ioc_type="ip",
            value=ip,
            title=f"Tor exit node: {ip}",
            description="Official Tor Project exit node — awareness only, not inherently malicious.",
            tags=("tor", "exit", "global"),
            reference="https://check.torproject.org/",
            external_id=f"tor:{ip}",
            severity=sev,
            threat_type="tor_exit",
        ))
        if len(items) >= limit:
            break
    return items


def fetch_all_global_threats(
    per_source_quota: int = DEFAULT_PER_SOURCE_QUOTA,
) -> tuple[list[GlobalThreatItem], list[str], list[str]]:
    """Fetch a balanced slice from every provider (round-robin, not ThreatFox-first)."""
    fetchers: list[tuple[str, Callable[[], list[GlobalThreatItem]]]] = [
        ("ThreatFox", lambda: fetch_threatfox_export(per_source_quota)),
        ("URLhaus", lambda: fetch_urlhaus_export(per_source_quota)),
        ("MalwareBazaar", lambda: fetch_malwarebazaar_export(per_source_quota)),
        ("CISA-KEV", lambda: fetch_cisa_kev(limit=per_source_quota)),
        ("OpenPhish", lambda: fetch_openphish(per_source_quota)),
        ("Feodo Tracker", lambda: fetch_feodo_tracker(per_source_quota)),
        ("PhishTank", lambda: fetch_phishtank(per_source_quota)),
        ("Spamhaus DROP", lambda: fetch_spamhaus_drop(per_source_quota)),
        ("URLhaus-Hosts", lambda: fetch_urlhaus_hosts(per_source_quota)),
        ("SSLBL", lambda: fetch_sslbl(per_source_quota)),
        ("blocklist.de", lambda: fetch_blocklist_de(per_source_quota)),
        ("Tor Exit Nodes", lambda: fetch_tor_exits(per_source_quota)),
    ]
    if _abuse_headers().get("Auth-Key"):
        fetchers.insert(0, ("ThreatFox-API", lambda: fetch_threatfox_api(per_source_quota)))

    buckets: dict[str, list[GlobalThreatItem]] = {}
    sources_ok: list[str] = []
    sources_failed: list[str] = []
    source_order = [
        "ThreatFox", "URLhaus", "MalwareBazaar", "CISA-KEV", "OpenPhish",
        "Feodo Tracker", "PhishTank", "Spamhaus DROP", "URLhaus-Hosts",
        "SSLBL", "blocklist.de", "Tor Exit Nodes",
    ]

    def _run_fetch(name: str, fn: Callable[[], list[GlobalThreatItem]]) -> tuple[str, str, list[GlobalThreatItem] | None, str | None]:
        bucket_key = "ThreatFox" if name.startswith("ThreatFox") else name
        try:
            return name, bucket_key, fn(), None
        except Exception as e:
            return name, bucket_key, None, repr(e)

    def _record_result(fut) -> None:
        submit_name = future_map[fut]
        bucket_key = "ThreatFox" if submit_name.startswith("ThreatFox") else submit_name
        try:
            name, bucket_key, batch, err = fut.result()
        except Exception as e:
            sources_failed.append(bucket_key)
            print(f"[global_feed] {submit_name} fetch failed: {e!r}")
            return
        if err is not None or batch is None:
            sources_failed.append(bucket_key)
            print(f"[global_feed] {name} fetch failed: {err}")
            return
        buckets.setdefault(bucket_key, []).extend(batch)
        sources_ok.append(bucket_key)
        print(f"[global_feed] {name}: {len(batch)} item(s)")

    pool = ThreadPoolExecutor(max_workers=min(8, len(fetchers)))
    try:
        future_map = {
            pool.submit(_run_fetch, name, fn): name
            for name, fn in fetchers
        }
        poll_seconds = PER_SOURCE_FETCH_TIMEOUT + 5
        deadline = time.monotonic() + poll_seconds
        pending = set(future_map.keys())
        processed: set = set()
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            for fut in done:
                processed.add(fut)
                _record_result(fut)
        for fut, submit_name in future_map.items():
            if fut in processed:
                continue
            if fut.done():
                _record_result(fut)
                continue
            bucket_key = "ThreatFox" if submit_name.startswith("ThreatFox") else submit_name
            sources_failed.append(bucket_key)
            print(f"[global_feed] {submit_name} fetch timed out (poll deadline {poll_seconds}s)")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # Round-robin interleave so the dashboard shows all sources, not just ThreatFox
    out: list[GlobalThreatItem] = []
    max_len = max((len(buckets.get(k, [])) for k in source_order), default=0)
    for i in range(max_len):
        for key in source_order:
            batch = buckets.get(key, [])
            if i < len(batch):
                out.append(batch[i])
    return out, sorted(set(sources_ok)), sorted(set(sources_failed))


# ─── Ticker engine ───────────────────────────────────────────────────────────

@dataclass
class TickerStatus:
    running: bool = False
    last_poll: float | None = None
    last_error: str = ""
    total_ingested: int = 0
    last_batch: int = 0
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)


class GlobalThreatTicker:
    """Background poller that surfaces new global threats on the dashboard."""

    def __init__(
        self,
        callback: Callable[[Alert], None],
        interval_secs: int = 120,
        max_per_poll: int = 30,
        per_source_quota: int = DEFAULT_PER_SOURCE_QUOTA,
        bootstrap: bool = True,
    ) -> None:
        self._callback = callback
        self._interval = max(30, interval_secs)
        self._max_per_poll = max_per_poll
        self._per_source_quota = per_source_quota
        self._bootstrap = bootstrap
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque(maxlen=50_000)
        self._seen_ioc: dict[str, str] = {}
        self._seen_ioc_order: deque[str] = deque(maxlen=50_000)
        self._status = TickerStatus()
        self._lock = threading.Lock()

    @property
    def status(self) -> TickerStatus:
        with self._lock:
            return TickerStatus(
                running=self._status.running,
                last_poll=self._status.last_poll,
                last_error=self._status.last_error,
                total_ingested=self._status.total_ingested,
                last_batch=self._status.last_batch,
                sources_ok=list(self._status.sources_ok),
                sources_failed=list(self._status.sources_failed),
            )

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="global-threat-ticker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def ingest_external(self, payload: dict) -> Alert:
        alert = push_payload_to_alert(payload)
        self._callback(alert)
        with self._lock:
            self._status.total_ingested += 1
        return alert

    def _remember(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        self._seen_order.append(key)
        if len(self._seen_order) == self._seen_order.maxlen:
            oldest = self._seen_order[0]
            self._seen.discard(oldest)
        return True

    def _remember_ioc(self, item: GlobalThreatItem, *, quiet: bool = False) -> bool:
        """Cross-source dedup — skip if same IOC already surfaced from another provider."""
        key = item.canonical_ioc_key
        if not key or key == ":":
            return True
        existing = self._seen_ioc.get(key)
        if existing and existing != item.source:
            if not quiet:
                print(
                    f"[global_feed] dedup skip: {item.value[:80]} already from {existing} "
                    f"(skipped {item.source})"
                )
            return False
        if key not in self._seen_ioc:
            self._seen_ioc[key] = item.source
            self._seen_ioc_order.append(key)
            if len(self._seen_ioc_order) == self._seen_ioc_order.maxlen:
                oldest = self._seen_ioc_order[0]
                self._seen_ioc.pop(oldest, None)
        return True

    def _poll_once(self) -> int:
        items, sources_ok, sources_failed = fetch_all_global_threats(
            per_source_quota=self._per_source_quota
        )
        sources = sorted({i.source for i in items})
        new_items: list[GlobalThreatItem] = []

        if self._bootstrap and not self._seen:
            for item in items:
                self._seen.add(item.dedup_key)
                self._seen_order.append(item.dedup_key)
                self._remember_ioc(item, quiet=True)
            snapshot: list[GlobalThreatItem] = []
            snapshot_iocs: set[str] = set()
            for item in items:
                key = item.canonical_ioc_key
                if key in snapshot_iocs:
                    continue
                snapshot_iocs.add(key)
                snapshot.append(item)
                if len(snapshot) >= self._max_per_poll:
                    break
            for item in snapshot:
                self._callback(item_to_alert(item))
            with self._lock:
                self._status.sources_ok = sources_ok
                self._status.sources_failed = sources_failed
                self._status.last_poll = time.time()
                self._status.last_batch = len(snapshot)
                self._status.total_ingested += len(snapshot)
            src_counts = {s: sum(1 for i in snapshot if i.source == s) for s in sources}
            print(
                f"[global_feed] initial snapshot: {len(snapshot)} global threat(s) "
                f"from {src_counts}; tracking {len(items)} IOCs"
            )
            return len(snapshot)

        for item in items:
            if self._remember(item.dedup_key) and self._remember_ioc(item):
                new_items.append(item)

        # Emit round-robin across sources so one poll doesn't flood a single provider
        by_source: dict[str, list[GlobalThreatItem]] = {}
        for item in new_items:
            by_source.setdefault(item.source, []).append(item)
        emitted_items: list[GlobalThreatItem] = []
        while len(emitted_items) < self._max_per_poll:
            added = False
            for src in sorted(by_source.keys()):
                batch = by_source[src]
                if batch:
                    emitted_items.append(batch.pop(0))
                    added = True
                    if len(emitted_items) >= self._max_per_poll:
                        break
            if not added:
                break

        for item in emitted_items:
            self._callback(item_to_alert(item))
        emitted = len(emitted_items)

        with self._lock:
            self._status.last_poll = time.time()
            self._status.last_batch = emitted
            self._status.total_ingested += emitted
            self._status.sources_ok = sources_ok
            self._status.sources_failed = sources_failed
            self._status.last_error = ""
        if emitted:
            print(f"[global_feed] surfaced {emitted} new global threat(s)")
        return emitted

    def _loop(self) -> None:
        with self._lock:
            self._status.running = True
        # First poll quickly after start
        time.sleep(3)
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception as e:
                with self._lock:
                    self._status.last_error = repr(e)
                print(f"[global_feed] poll error: {e!r}")
            self._stop.wait(self._interval)
        with self._lock:
            self._status.running = False


_ticker: GlobalThreatTicker | None = None


def get_ticker() -> GlobalThreatTicker | None:
    return _ticker


def start_global_ticker(
    callback: Callable[[Alert], None],
    interval_secs: int = 120,
    max_per_poll: int = 30,
    per_source_quota: int = DEFAULT_PER_SOURCE_QUOTA,
) -> GlobalThreatTicker:
    global _ticker
    if _ticker is None:
        _ticker = GlobalThreatTicker(
            callback=callback,
            interval_secs=interval_secs,
            max_per_poll=max_per_poll,
            per_source_quota=per_source_quota,
        )
    _ticker.start()
    return _ticker
