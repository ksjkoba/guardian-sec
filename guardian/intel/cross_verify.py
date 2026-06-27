"""
5-stage cross-source alert verification pipeline.

Stage 1 — Parse alert (extract verifiable fields)
Stage 2 — Route to matching open APIs
Stage 3 — Cross-check (query each source, read named fields)
Stage 4 — Classify (GENUINE / UNVERIFIED / FALSE POSITIVE)
Stage 5 — Reference & output (one row per alert + summary)

Non-negotiable rules:
- No GENUINE without populated reference (source + endpoint + data point).
- CISA KEV presence → GENUINE / Critical (overrides NVD severity).
- Flag every source skipped due to missing auth or rate limits.
"""

from __future__ import annotations

import csv
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError

from guardian.intel.global_ticker import (
    _parse_threatfox_recent_rows,
    http_get,
    http_post_json,
)

# ─── API keys (env) ───────────────────────────────────────────────────────────

_PLACEHOLDER_KEY_MARKERS = (
    "your-key", "your-real-key", "your-real-key-from", "changeme",
    "replace-me", "example", "placeholder", "insert", "xxx",
)


def _abuse_ch_key() -> str:
    import os
    return os.environ.get("ABUSE_CH_AUTH_KEY") or os.environ.get("GUARDIAN_ABUSE_CH_KEY", "")


def _usable_abuse_ch_key() -> str:
    """Return key only if set and not an obvious placeholder string."""
    key = _abuse_ch_key().strip()
    if not key:
        return ""
    low = key.lower()
    if any(m in low for m in _PLACEHOLDER_KEY_MARKERS):
        return ""
    return key


def key_status_message() -> str | None:
    """Human-readable warning when abuse.ch auth is missing or placeholder."""
    raw = _abuse_ch_key().strip()
    if not raw:
        return (
            "ABUSE_CH_AUTH_KEY not set — using free abuse.ch CSV exports "
            "(get a key at https://auth.abuse.ch/)."
        )
    if not _usable_abuse_ch_key():
        return (
            f"ABUSE_CH_AUTH_KEY looks like a placeholder ({raw!r}) — "
            "using free CSV exports instead. Set a real key from https://auth.abuse.ch/."
        )
    return None


def _abuseipdb_key() -> str:
    import os
    return os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("GUARDIAN_ABUSEIPDB_KEY", "")


def _nvd_key() -> str:
    import os
    return os.environ.get("NVD_API_KEY") or os.environ.get("GUARDIAN_NVD_API_KEY", "")


# ─── Models ───────────────────────────────────────────────────────────────────

_IOC_TYPE_ALIASES = {
    "ipv4": "ip",
    "ipv6": "ip",
    "phishing": "url",
    "sha256": "hash",
    "md5": "hash",
    "sha1": "hash",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}$"
    r"|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


@dataclass
class ParsedAlert:
    """Stage 1 output — verifiable fields extracted from a dashboard alert."""

    alert_id: str
    ioc_type: str
    ioc_value: str
    claim: str
    timestamp: float | None
    age_secs: int | None
    source_raised: str
    source_fields: dict[str, Any]
    raw_title: str
    raw_description: str

    def checklist_stage1(self) -> dict[str, Any]:
        return {
            "1_indicator_type": self.ioc_type,
            "2_indicator_value": self.ioc_value,
            "3_claim": self.claim,
            "4_timestamp": self._ts_iso(),
            "4_recency": self._recency_label(),
            "5_source_raised": self.source_raised,
            "5_source_fields": self.source_fields,
        }

    def _ts_iso(self) -> str | None:
        if self.timestamp is None:
            return None
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    def _recency_label(self) -> str:
        if self.age_secs is None:
            return "unknown"
        if self.age_secs < 3600:
            return f"{self.age_secs // 60}m ago (very recent)"
        if self.age_secs < 86400:
            return f"{self.age_secs // 3600}h ago (recent)"
        return f"{self.age_secs // 86400}d ago"


@dataclass
class SourceRoute:
    """Stage 2 — which API to query for this indicator."""

    name: str
    endpoint: str
    method: str
    auth_required: bool
    field_to_parse: str
    hit_condition: str
    primary: bool = True


@dataclass
class CheckResult:
    """Stage 3 — result from one API query."""

    source: str
    endpoint: str
    method: str
    status: str  # hit | miss | refute | skipped | error
    data_point: str
    detail: str
    reference: str = ""
    skipped_reason: str = ""
    is_authoritative_hit: bool = False
    is_corroborating: bool = False
    is_refute: bool = False


@dataclass
class AlertVerification:
    """Stage 4 + 5 — full outcome for one alert."""

    parsed: ParsedAlert
    routes: list[SourceRoute]
    checks: list[CheckResult]
    classification: str
    confidence: str
    references: list[dict[str, str]]
    skipped_sources: list[str]
    corroboration_count: int
    rationale: str
    checklist: dict[str, Any]
    row: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.parsed.alert_id,
            "indicator": f"{self.parsed.ioc_type}:{self.parsed.ioc_value}",
            "claim": self.parsed.claim,
            "classification": self.classification,
            "confidence": self.confidence,
            "corroboration_count": self.corroboration_count,
            "rationale": self.rationale,
            "references": self.references,
            "skipped_sources": self.skipped_sources,
            "checklist": self.checklist,
            "row": self.row,
            "checks": [
                {
                    "source": c.source,
                    "endpoint": c.endpoint,
                    "status": c.status,
                    "data_point": c.data_point,
                    "detail": c.detail,
                    "reference": c.reference,
                    "skipped_reason": c.skipped_reason,
                }
                for c in self.checks
            ],
        }


@dataclass
class VerificationSummary:
    """Stage 5 batch summary."""

    total: int = 0
    genuine: int = 0
    unverified: int = 0
    false_positive: int = 0
    skipped_auth_sources: list[str] = field(default_factory=list)
    results: list[AlertVerification] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_alerts": self.total,
                "genuine": self.genuine,
                "unverified": self.unverified,
                "false_positive": self.false_positive,
                "skipped_auth_sources": sorted(set(self.skipped_auth_sources)),
            },
            "rows": [r.row for r in self.results],
            "results": [r.to_dict() for r in self.results],
        }


# ─── Stage 1: Parse ─────────────────────────────────────────────────────────

def _infer_ioc_type(value: str) -> str:
    v = value.strip()
    if _CVE_RE.match(v):
        return "cve"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if _HASH_RE.match(v):
        return "hash"
    if "/" in v:
        base = v.split("/", 1)[0]
        if _IP_RE.match(base):
            return "cidr"
    if _IP_RE.match(v):
        return "ip"
    if "." in v and " " not in v:
        return "domain"
    return "unknown"


def _normalize_ioc_type(raw: str, value: str) -> str:
    t = (raw or "").strip().lower()
    t = _IOC_TYPE_ALIASES.get(t, t)
    if t in ("ip", "domain", "url", "hash", "cve", "cidr"):
        return t
    return _infer_ioc_type(value)


def parse_alert(alert: dict[str, Any]) -> ParsedAlert:
    """Extract verifiable fields from a dashboard alert dict."""
    meta = alert.get("metadata") or {}
    evidence = str(alert.get("evidence") or "").strip()
    ioc_value = str(meta.get("ioc_value") or evidence).strip()
    ioc_type = _normalize_ioc_type(str(meta.get("ioc_type") or ""), ioc_value)

    if ioc_type == "unknown" and not ioc_value:
        ioc_value = evidence

    ts = alert.get("timestamp") or meta.get("timestamp") or meta.get("verified_at")
    try:
        timestamp = float(ts) if ts is not None else None
    except (TypeError, ValueError):
        timestamp = None

    age_secs: int | None = None
    if timestamp is not None:
        age_secs = max(0, int(time.time() - timestamp))

    claim_parts = [
        str(alert.get("title") or ""),
        str(meta.get("plain_summary") or ""),
        str(alert.get("description") or ""),
        str(meta.get("threat_type") or meta.get("malware_family") or ""),
    ]
    claim = " — ".join(p for p in claim_parts if p) or "unspecified threat"

    source_raised = str(
        meta.get("global_source") or alert.get("global_source") or alert.get("module") or ""
    )

    source_fields = {
        k: meta[k]
        for k in (
            "global_source", "source_label", "reference_url", "malware_family",
            "threat_type", "confidence", "tags", "verified", "verified_method",
            "ioc_type", "ioc_value", "plain_summary",
        )
        if k in meta
    }

    return ParsedAlert(
        alert_id=str(alert.get("id") or ""),
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        claim=claim,
        timestamp=timestamp,
        age_secs=age_secs,
        source_raised=source_raised,
        source_fields=source_fields,
        raw_title=str(alert.get("title") or ""),
        raw_description=str(alert.get("description") or ""),
    )


# ─── Stage 2: Route ───────────────────────────────────────────────────────────

def route_sources(parsed: ParsedAlert) -> list[SourceRoute]:
    """Map indicator type to matching API(s)."""
    t = parsed.ioc_type
    routes: list[SourceRoute] = []

    if t == "ip":
        routes.extend([
            SourceRoute(
                "Feodo Tracker",
                "GET https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "GET",
                auth_required=False,
                field_to_parse="dst_ip, c2_status, malware",
                hit_condition="IP on Feodo C2 blocklist → botnet C2 confirmed",
            ),
            SourceRoute(
                "SSLBL",
                "GET https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
                "GET",
                auth_required=False,
                field_to_parse="DstIP, Listing Reason",
                hit_condition="IP on SSLBL → malicious SSL endpoint",
            ),
            SourceRoute(
                "blocklist.de",
                "GET https://lists.blocklist.de/lists/all.txt",
                "GET",
                auth_required=False,
                field_to_parse="ip",
                hit_condition="IP on blocklist.de → abuse/brute-force reports",
                primary=False,
            ),
            SourceRoute(
                "Tor Exit Nodes",
                "GET https://check.torproject.org/torbulkexitlist",
                "GET",
                auth_required=False,
                field_to_parse="exit_ip",
                hit_condition="IP on Tor exit list → awareness corroboration",
                primary=False,
            ),
            SourceRoute(
                "AbuseIPDB",
                "GET https://api.abuseipdb.com/api/v2/check",
                "GET",
                auth_required=True,
                field_to_parse="data.abuseConfidenceScore, data.totalReports",
                hit_condition="score ≥ 75 → malicious; 25–74 → suspicious",
            ),
            SourceRoute(
                "ThreatFox",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="data[].malware, confidence_level",
                hit_condition="query_status=ok → IOC confirmed",
            ),
            SourceRoute(
                "abuse.ch Hunting",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="dataset match + confidence_level",
                hit_condition="any match → corroborating hit",
                primary=False,
            ),
        ])
    elif t == "domain":
        routes.extend([
            SourceRoute(
                "URLhaus-Hosts",
                "GET https://urlhaus.abuse.ch/downloads/hostfile/",
                "GET",
                auth_required=False,
                field_to_parse="hostname in host file",
                hit_condition="host listed → malware domain confirmed",
            ),
            SourceRoute(
                "ThreatFox",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="data[].malware, confidence_level",
                hit_condition="query_status=ok → IOC confirmed",
            ),
            SourceRoute(
                "abuse.ch Hunting",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="dataset match + confidence_level",
                hit_condition="any match → corroborating hit",
                primary=False,
            ),
            SourceRoute(
                "URLhaus",
                "POST https://urlhaus-api.abuse.ch/v1/host/",
                "POST",
                auth_required=True,
                field_to_parse="query_status, url_count",
                hit_condition="host known → corroborating",
                primary=False,
            ),
        ])
    elif t == "url":
        routes.extend([
            SourceRoute(
                "PhishTank",
                "GET https://data.phishtank.com/data/online-valid.csv",
                "GET",
                auth_required=False,
                field_to_parse="verified, online, url",
                hit_condition="verified=yes & online=yes → phishing confirmed",
            ),
            SourceRoute(
                "URLhaus",
                "POST https://urlhaus-api.abuse.ch/v1/url/",
                "POST",
                auth_required=True,
                field_to_parse="query_status, url_status, threat",
                hit_condition="ok & online → active malware URL",
            ),
            SourceRoute(
                "OpenPhish",
                "GET https://openphish.com/feed.txt",
                "GET",
                auth_required=False,
                field_to_parse="feed line match",
                hit_condition="URL on active feed → phishing confirmed",
            ),
            SourceRoute(
                "abuse.ch Hunting",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="dataset match + confidence_level",
                hit_condition="any match → corroborating hit",
                primary=False,
            ),
        ])
        # Phishing-sourced alerts: OpenPhish is the authoritative check, not URLhaus
        if parsed.source_raised in ("OpenPhish", "PhishTank"):
            for i, r in enumerate(routes):
                if r.name == parsed.source_raised:
                    routes[i] = SourceRoute(
                        r.name, r.endpoint, r.method, r.auth_required,
                        r.field_to_parse, r.hit_condition, primary=True,
                    )
                    break
    elif t == "hash":
        routes.extend([
            SourceRoute(
                "MalwareBazaar",
                "POST https://mb-api.abuse.ch/api/v1/ (get_info)",
                "POST",
                auth_required=True,
                field_to_parse="data[].signature, file_type",
                hit_condition="query_status=ok → known malware",
            ),
            SourceRoute(
                "abuse.ch Hunting",
                "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)",
                "POST",
                auth_required=True,
                field_to_parse="dataset match + confidence_level",
                hit_condition="any match → corroborating hit",
                primary=False,
            ),
        ])
    elif t == "cidr":
        routes.extend([
            SourceRoute(
                "Spamhaus DROP",
                "GET https://www.spamhaus.org/drop/drop.txt",
                "GET",
                auth_required=False,
                field_to_parse="CIDR on DROP list",
                hit_condition="prefix listed → hijacked netblock confirmed",
            ),
        ])
    elif t == "cve":
        routes.extend([
            SourceRoute(
                "CISA KEV",
                "GET https://www.cisa.gov/.../known_exploited_vulnerabilities.json",
                "GET",
                auth_required=False,
                field_to_parse="vulnerabilities[].cveID",
                hit_condition="present → known-exploited (top priority)",
            ),
            SourceRoute(
                "NVD",
                "GET https://services.nvd.nist.gov/rest/json/cves/2.0",
                "GET",
                auth_required=False,
                field_to_parse="cvssData.baseScore, baseSeverity",
                hit_condition="record exists → valid CVE",
                primary=False,
            ),
        ])

    return routes


def _checklist_stage2(parsed: ParsedAlert, routes: list[SourceRoute]) -> dict[str, Any]:
    apis = [r.name for r in routes]
    multi = len(apis) > 1
    cve_kev = parsed.ioc_type == "cve" and any(r.name == "CISA KEV" for r in routes)
    missing: list[str] = []
    for r in routes:
        if r.auth_required and r.name == "AbuseIPDB" and not _abuseipdb_key():
            missing.append(f"{r.name} (ABUSEIPDB_API_KEY)")
        elif r.auth_required and r.name not in ("AbuseIPDB", "CISA KEV", "NVD"):
            if not _usable_abuse_ch_key():
                missing.append(
                    f"{r.name} API skipped — using CSV fallback "
                    f"(set ABUSE_CH_AUTH_KEY from https://auth.abuse.ch/)"
                )
    return {
        "6_matching_apis": apis,
        "7_multi_source_check": multi,
        "8_cve_kev_checked": cve_kev,
        "9_missing_auth_or_rate_limited": missing,
    }


# ─── Stage 3: Cross-check queries ─────────────────────────────────────────────

def _http_get_with_headers(url: str, headers: dict[str, str]) -> bytes:
    import ssl
    import urllib.request

    last_err: Exception | None = None
    for ctx in (ssl.create_default_context(), ssl._create_unverified_context()):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
                return resp.read()
        except Exception as e:
            last_err = e
    raise last_err or RuntimeError(f"GET failed: {url}")


def _skipped(name: str, endpoint: str, method: str, reason: str) -> CheckResult:
    return CheckResult(
        source=name,
        endpoint=endpoint,
        method=method,
        status="skipped",
        data_point="",
        detail=reason,
        skipped_reason=reason,
    )


def _rate_limited(exc: Exception) -> bool:
    return isinstance(exc, HTTPError) and exc.code == 429


def _auth_failure(exc: Exception) -> bool:
    return isinstance(exc, HTTPError) and exc.code in (401, 403)


# ─── CSV fallbacks (no API key required) ──────────────────────────────────────

_urlhaus_csv_cache: tuple[float, str] | None = None
_mb_csv_cache: tuple[float, str] | None = None
_tf_csv_cache: tuple[float, bytes] | None = None
_openphish_feed_cache: tuple[float, set[str]] | None = None
_feodo_csv_cache: tuple[float, str] | None = None
_phishtank_cache: tuple[float, set[str]] | None = None
_spamhaus_drop_cache: tuple[float, set[str]] | None = None
_urlhaus_hosts_cache: tuple[float, set[str]] | None = None


def _feodo_csv_text() -> str:
    global _feodo_csv_cache
    now = time.time()
    if _feodo_csv_cache and now - _feodo_csv_cache[0] < 300:
        return _feodo_csv_cache[1]
    text = http_get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").decode(errors="replace")
    _feodo_csv_cache = (now, text)
    return text


def _check_feodo_ip(ip: str) -> CheckResult:
    endpoint = "GET https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    try:
        for line in _feodo_csv_text().splitlines():
            if not line or line.startswith("#") or line.startswith("first_seen"):
                continue
            row = next(csv.reader([line]))
            if len(row) >= 6 and row[1].strip() == ip.strip():
                status = row[3].strip()
                malware = row[5].strip()
                dp = f"c2_status={status}, malware={malware}"
                return CheckResult(
                    source="Feodo Tracker",
                    endpoint=endpoint,
                    method="GET",
                    status="hit",
                    data_point=dp,
                    detail=f"IP on Feodo Tracker blocklist ({malware}, {status})",
                    reference=f"https://feodotracker.abuse.ch/browse/host/{ip.strip()}/",
                    is_authoritative_hit=status.lower() == "online",
                    is_corroborating=status.lower() != "online",
                )
        return CheckResult(
            source="Feodo Tracker", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_blocklist", detail="IP not on Feodo Tracker blocklist",
        )
    except Exception as e:
        return CheckResult(
            source="Feodo Tracker", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _phishtank_urls() -> set[str]:
    global _phishtank_cache
    now = time.time()
    if _phishtank_cache and now - _phishtank_cache[0] < 300:
        return _phishtank_cache[1]
    from guardian.intel.global_ticker import load_phishtank_entries
    entries = load_phishtank_entries()
    urls = {
        str(e.get("url", "")).strip()
        for e in entries
        if e.get("verified") == "yes" and e.get("online") == "yes" and e.get("url")
    }
    _phishtank_cache = (now, urls)
    return urls



def _check_phishtank(url: str) -> CheckResult:
    endpoint = "GET https://data.phishtank.com/data/online-valid.csv"
    try:
        if url.strip() in _phishtank_urls():
            return CheckResult(
                source="PhishTank",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point="verified_online_phishing",
                detail="URL on PhishTank verified-online feed",
                reference=url.strip(),
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="PhishTank", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_verified_feed",
            detail="URL not on PhishTank verified-online feed",
        )
    except Exception as e:
        return CheckResult(
            source="PhishTank", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _spamhaus_drop_cidrs() -> set[str]:
    global _spamhaus_drop_cache
    now = time.time()
    if _spamhaus_drop_cache and now - _spamhaus_drop_cache[0] < 600:
        return _spamhaus_drop_cache[1]
    raw = http_get("https://www.spamhaus.org/drop/drop.txt").decode(errors="replace")
    cidrs = {
        line.split(";")[0].strip()
        for line in raw.splitlines()
        if line.strip() and not line.startswith(";") and "/" in line
    }
    _spamhaus_drop_cache = (now, cidrs)
    return cidrs


def _check_spamhaus_drop(cidr: str) -> CheckResult:
    endpoint = "GET https://www.spamhaus.org/drop/drop.txt"
    try:
        cidrs = _spamhaus_drop_cidrs()
        if cidr.strip() in cidrs:
            return CheckResult(
                source="Spamhaus DROP",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point="on_drop_list",
                detail=f"Netblock {cidr} listed on Spamhaus DROP",
                reference="https://www.spamhaus.org/drop/",
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="Spamhaus DROP", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_drop_list", detail="CIDR not on Spamhaus DROP list",
        )
    except Exception as e:
        return CheckResult(
            source="Spamhaus DROP", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _urlhaus_hostnames() -> set[str]:
    global _urlhaus_hosts_cache
    now = time.time()
    if _urlhaus_hosts_cache and now - _urlhaus_hosts_cache[0] < 300:
        return _urlhaus_hosts_cache[1]
    raw = http_get("https://urlhaus.abuse.ch/downloads/hostfile/").decode(errors="replace")
    hosts = set()
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("	")
        if len(parts) >= 2:
            hosts.add(parts[1].strip().lower())
    _urlhaus_hosts_cache = (now, hosts)
    return hosts


def _check_urlhaus_hosts(domain: str) -> CheckResult:
    endpoint = "GET https://urlhaus.abuse.ch/downloads/hostfile/"
    try:
        hosts = _urlhaus_hostnames()
        if domain.strip().lower() in hosts:
            return CheckResult(
                source="URLhaus-Hosts",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point="on_hostfile",
                detail="Domain listed in URLhaus host file",
                reference=f"https://urlhaus.abuse.ch/host/{domain.strip()}/",
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="URLhaus-Hosts", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_hostfile", detail="Domain not on URLhaus host file",
        )
    except Exception as e:
        return CheckResult(
            source="URLhaus-Hosts", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_sslbl(ip: str) -> CheckResult:
    from guardian.intel.global_ticker import SSLBL_FEED_URL
    endpoint = f"GET {SSLBL_FEED_URL}"
    try:
        raw = http_get(SSLBL_FEED_URL).decode(errors="replace")
        for line in raw.splitlines():
            if not line or line.startswith("#"):
                continue
            row = next(csv.reader([line]))
            if len(row) >= 2 and row[1].strip() == ip.strip():
                reason = row[3].strip() if len(row) > 3 else "malicious SSL"
                return CheckResult(
                    source="SSLBL", endpoint=endpoint, method="GET", status="hit",
                    data_point=f"reason={reason}",
                    detail=f"IP on SSLBL malicious SSL list ({reason})",
                    reference=f"https://sslbl.abuse.ch/sslblip/{ip.strip()}/",
                    is_authoritative_hit=True,
                )
        return CheckResult(
            source="SSLBL", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_sslbl", detail="IP not on SSLBL feed",
        )
    except Exception as e:
        return CheckResult(
            source="SSLBL", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_blocklist_de(ip: str) -> CheckResult:
    endpoint = "GET https://lists.blocklist.de/lists/all.txt"
    try:
        from guardian.intel.global_ticker import load_blocklist_de_ips
        if ip.strip() in load_blocklist_de_ips():
            return CheckResult(
                source="blocklist.de", endpoint=endpoint, method="GET", status="hit",
                data_point="on_blocklist",
                detail="IP listed on blocklist.de abuse reports",
                reference=f"https://www.blocklist.de/en/view.html?ip={ip.strip()}",
                is_corroborating=True,
            )
        return CheckResult(
            source="blocklist.de", endpoint=endpoint, method="GET", status="miss",
            data_point="not_on_blocklist", detail="IP not on blocklist.de",
        )
    except Exception as e:
        return CheckResult(
            source="blocklist.de", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_tor_exit(ip: str) -> CheckResult:
    endpoint = "GET https://check.torproject.org/torbulkexitlist"
    try:
        from guardian.intel.global_ticker import load_tor_exit_ips
        if ip.strip() in load_tor_exit_ips():
            return CheckResult(
                source="Tor Exit Nodes", endpoint=endpoint, method="GET", status="hit",
                data_point="tor_exit",
                detail="IP is a Tor exit node (official list)",
                reference="https://check.torproject.org/",
                is_corroborating=True,
            )
        return CheckResult(
            source="Tor Exit Nodes", endpoint=endpoint, method="GET", status="miss",
            data_point="not_tor_exit", detail="IP not on Tor exit list",
        )
    except Exception as e:
        return CheckResult(
            source="Tor Exit Nodes", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _openphish_urls() -> set[str]:
    from guardian.intel.global_ticker import load_openphish_urls
    return set(load_openphish_urls())


def _check_openphish(url: str) -> CheckResult:
    endpoint = "GET https://openphish.com/feed.txt"
    try:
        feed = _openphish_urls()
        target = url.strip().rstrip("/").lower()
        if target in {u.strip().rstrip("/").lower() for u in feed}:
            return CheckResult(
                source="OpenPhish",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point="on_active_phishing_feed",
                detail="URL listed on OpenPhish active phishing feed",
                reference=url,
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="OpenPhish",
            endpoint=endpoint,
            method="GET",
            status="miss",
            data_point="not_on_active_feed",
            detail="URL no longer on OpenPhish active feed (may have aged off)",
        )
    except Exception as e:
        return CheckResult(
            source="OpenPhish", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _urlhaus_csv_text() -> str:
    global _urlhaus_csv_cache
    now = time.time()
    if _urlhaus_csv_cache and now - _urlhaus_csv_cache[0] < 300:
        return _urlhaus_csv_cache[1]
    text = http_get("https://urlhaus.abuse.ch/downloads/csv_recent/").decode(errors="replace")
    _urlhaus_csv_cache = (now, text)
    return text


def _malwarebazaar_csv_text() -> str:
    global _mb_csv_cache
    now = time.time()
    if _mb_csv_cache and now - _mb_csv_cache[0] < 300:
        return _mb_csv_cache[1]
    text = http_get("https://bazaar.abuse.ch/export/csv/recent/").decode(errors="replace")
    _mb_csv_cache = (now, text)
    return text


def _threatfox_csv_raw() -> bytes:
    global _tf_csv_cache
    now = time.time()
    if _tf_csv_cache and now - _tf_csv_cache[0] < 300:
        return _tf_csv_cache[1]
    raw = http_get("https://threatfox.abuse.ch/export/csv/ip-port/recent/")
    _tf_csv_cache = (now, raw)
    return raw


def _check_urlhaus_url_csv(url: str) -> CheckResult:
    import csv

    endpoint = "GET https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        for line in _urlhaus_csv_text().splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line], quotechar='"'))
            except Exception:
                continue
            if len(row) < 6:
                continue
            row_url = row[2].strip().strip('"')
            if row_url != url:
                continue
            url_status = row[3].strip().strip('"').lower()
            threat = row[5].strip().strip('"')
            ref = row[7].strip().strip('"') if len(row) > 7 else ""
            dp = f"url_status={url_status}, threat={threat}"
            online = url_status == "online"
            return CheckResult(
                source="URLhaus",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point=dp,
                detail="URL found in URLhaus recent CSV export"
                + (" (online)" if online else " (offline/archived)"),
                reference=ref or "https://urlhaus.abuse.ch/",
                is_authoritative_hit=online,
                is_corroborating=not online,
            )
        return CheckResult(
            source="URLhaus",
            endpoint=endpoint,
            method="GET",
            status="refute",
            data_point="not_in_recent_csv",
            detail="URL not in URLhaus recent CSV export",
            is_refute=True,
        )
    except Exception as e:
        return CheckResult(
            source="URLhaus", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_malwarebazaar_csv(hash_value: str) -> CheckResult:
    import csv

    endpoint = "GET https://bazaar.abuse.ch/export/csv/recent/"
    h = hash_value.lower().strip()
    try:
        for line in _malwarebazaar_csv_text().splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line], quotechar='"'))
            except Exception:
                continue
            if len(row) < 5:
                continue
            sha = row[1].strip().strip('"').lower()
            if sha != h:
                continue
            sig = row[4].strip().strip('"') if len(row) > 4 else ""
            dp = f"signature={sig or 'unknown'}"
            return CheckResult(
                source="MalwareBazaar",
                endpoint=endpoint,
                method="GET",
                status="hit",
                data_point=dp,
                detail="Hash found in MalwareBazaar recent CSV export",
                reference=f"https://bazaar.abuse.ch/sample/{h}/",
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="MalwareBazaar",
            endpoint=endpoint,
            method="GET",
            status="refute",
            data_point="not_in_recent_csv",
            detail="Hash not in MalwareBazaar recent CSV export",
            is_refute=True,
        )
    except Exception as e:
        return CheckResult(
            source="MalwareBazaar", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_threatfox_csv(term: str, label: str = "ThreatFox") -> CheckResult:
    endpoint = "GET https://threatfox.abuse.ch/export/csv/ip-port/recent/"
    try:
        rows = _parse_threatfox_recent_rows(_threatfox_csv_raw())
        for row in rows:
            if row["ioc"] == term or term in row.get("ioc", ""):
                malware = row.get("malware", "unknown")
                dp = f"malware={malware}, threat_type={row.get('threat_type', '')}"
                return CheckResult(
                    source=label,
                    endpoint=endpoint,
                    method="GET",
                    status="hit",
                    data_point=dp,
                    detail=f"IOC found in ThreatFox recent CSV ({malware})",
                    reference=row.get("reference", "https://threatfox.abuse.ch/"),
                    is_authoritative_hit=label == "ThreatFox",
                    is_corroborating=label == "abuse.ch Hunting",
                )
        return CheckResult(
            source=label,
            endpoint=endpoint,
            method="GET",
            status="miss",
            data_point="not_in_recent_csv",
            detail="IOC not in ThreatFox recent CSV export",
        )
    except Exception as e:
        return CheckResult(
            source=label, endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_abuseipdb(ip: str) -> CheckResult:
    endpoint = "GET https://api.abuseipdb.com/api/v2/check"
    key = _abuseipdb_key()
    if not key:
        return _skipped("AbuseIPDB", endpoint, "GET", "missing ABUSEIPDB_API_KEY")

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        raw = _http_get_with_headers(url, {"Key": key, "Accept": "application/json"})
        data = json.loads(raw.decode())
        score = int((data.get("data") or {}).get("abuseConfidenceScore") or 0)
        reports = int((data.get("data") or {}).get("totalReports") or 0)
        dp = f"abuseConfidenceScore={score}, totalReports={reports}"
        if score >= 75:
            return CheckResult(
                source="AbuseIPDB", endpoint=endpoint, method="GET", status="hit",
                data_point=dp, detail="AbuseIPDB reports malicious confidence",
                reference=f"https://www.abuseipdb.com/check/{ip}",
                is_authoritative_hit=True,
            )
        if score >= 25:
            return CheckResult(
                source="AbuseIPDB", endpoint=endpoint, method="GET", status="hit",
                data_point=dp, detail="AbuseIPDB reports suspicious confidence",
                reference=f"https://www.abuseipdb.com/check/{ip}",
                is_corroborating=True,
            )
        if reports == 0 and score == 0:
            return CheckResult(
                source="AbuseIPDB", endpoint=endpoint, method="GET", status="refute",
                data_point=dp, detail="AbuseIPDB reports no abuse",
                reference=f"https://www.abuseipdb.com/check/{ip}",
                is_refute=True,
            )
        return CheckResult(
            source="AbuseIPDB", endpoint=endpoint, method="GET", status="miss",
            data_point=dp, detail="Below hit threshold",
            reference=f"https://www.abuseipdb.com/check/{ip}",
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped("AbuseIPDB", endpoint, "GET", "rate limited (HTTP 429)")
        return CheckResult(
            source="AbuseIPDB", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_threatfox_search(term: str, label: str = "ThreatFox") -> CheckResult:
    endpoint = "POST https://threatfox-api.abuse.ch/api/v1/ (search_ioc)"
    key = _usable_abuse_ch_key()
    if not key:
        return _check_threatfox_csv(term, label)

    try:
        data = http_post_json(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "search_ioc", "search_term": term},
            headers={"Auth-Key": key},
        )
        if data.get("query_status") != "ok":
            csv_result = _check_threatfox_csv(term, label)
            if csv_result.status == "hit":
                return csv_result
            return CheckResult(
                source=label, endpoint=endpoint, method="POST", status="miss",
                data_point=f"query_status={data.get('query_status')}",
                detail="No IOC match in ThreatFox API",
            )
        rows = data.get("data") or []
        if not rows:
            csv_result = _check_threatfox_csv(term, label)
            return csv_result if csv_result.status == "hit" else CheckResult(
                source=label, endpoint=endpoint, method="POST", status="miss",
                data_point="data=[]", detail="Empty result set",
            )
        row = rows[0]
        malware = row.get("malware_printable") or row.get("malware") or "unknown"
        conf = row.get("confidence_level", "")
        ioc_id = row.get("id", "")
        dp = f"malware={malware}, confidence_level={conf}"
        ref = f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else ""
        authoritative = label == "ThreatFox"
        return CheckResult(
            source=label, endpoint=endpoint, method="POST", status="hit",
            data_point=dp, detail=f"IOC confirmed in ThreatFox ({malware})",
            reference=ref,
            is_authoritative_hit=authoritative,
            is_corroborating=label == "abuse.ch Hunting",
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped(label, endpoint, "POST", "rate limited (HTTP 429)")
        if _auth_failure(e):
            return _check_threatfox_csv(term, label)
        csv_result = _check_threatfox_csv(term, label)
        if csv_result.status == "hit":
            return csv_result
        return CheckResult(
            source=label, endpoint=endpoint, method="POST", status="error",
            data_point="", detail=repr(e),
        )


def _check_urlhaus_url(url: str) -> CheckResult:
    endpoint = "POST https://urlhaus-api.abuse.ch/v1/url/"
    key = _usable_abuse_ch_key()
    if not key:
        return _check_urlhaus_url_csv(url)

    try:
        data = http_post_json(
            "https://urlhaus-api.abuse.ch/v1/url/",
            {"url": url},
            headers={"Auth-Key": key},
        )
        qs = data.get("query_status", "")
        if qs == "no_results":
            csv_result = _check_urlhaus_url_csv(url)
            if csv_result.status == "hit":
                return csv_result
            return CheckResult(
                source="URLhaus", endpoint=endpoint, method="POST", status="refute",
                data_point=f"query_status={qs}", detail="URL not in URLhaus",
                is_refute=True,
            )
        if qs != "ok":
            return _check_urlhaus_url_csv(url)
        status = str(data.get("url_status", "")).lower()
        threat = data.get("threat", "")
        dp = f"url_status={status}, threat={threat}"
        ref = str(data.get("urlhaus_reference") or data.get("urlhaus_link") or "")
        if status == "online":
            return CheckResult(
                source="URLhaus", endpoint=endpoint, method="POST", status="hit",
                data_point=dp, detail="Active malware URL on URLhaus",
                reference=ref or "https://urlhaus.abuse.ch/",
                is_authoritative_hit=True,
            )
        return CheckResult(
            source="URLhaus", endpoint=endpoint, method="POST", status="hit",
            data_point=dp, detail="URL known to URLhaus (not currently online)",
            reference=ref or "https://urlhaus.abuse.ch/",
            is_corroborating=True,
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped("URLhaus", endpoint, "POST", "rate limited (HTTP 429)")
        if _auth_failure(e):
            return _check_urlhaus_url_csv(url)
        csv_result = _check_urlhaus_url_csv(url)
        if csv_result.status in ("hit", "refute"):
            return csv_result
        return CheckResult(
            source="URLhaus", endpoint=endpoint, method="POST", status="error",
            data_point="", detail=repr(e),
        )


def _check_urlhaus_host(host: str) -> CheckResult:
    endpoint = "POST https://urlhaus-api.abuse.ch/v1/host/"
    key = _usable_abuse_ch_key()
    if not key:
        return _check_urlhaus_host_csv(host)

    try:
        data = http_post_json(
            "https://urlhaus-api.abuse.ch/v1/host/",
            {"host": host},
            headers={"Auth-Key": key},
        )
        qs = data.get("query_status", "")
        dp = f"query_status={qs}, url_count={data.get('url_count', 0)}"
        if qs == "ok":
            return CheckResult(
                source="URLhaus", endpoint=endpoint, method="POST", status="hit",
                data_point=dp, detail="Host known to URLhaus",
                reference="https://urlhaus.abuse.ch/",
                is_corroborating=True,
            )
        return CheckResult(
            source="URLhaus", endpoint=endpoint, method="POST", status="miss",
            data_point=dp, detail="Host not in URLhaus",
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped("URLhaus", endpoint, "POST", "rate limited (HTTP 429)")
        if _auth_failure(e):
            return _check_urlhaus_host_csv(host)
        return CheckResult(
            source="URLhaus", endpoint=endpoint, method="POST", status="error",
            data_point="", detail=repr(e),
        )


def _check_urlhaus_host_csv(host: str) -> CheckResult:
    import csv

    csv_endpoint = "GET https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        count = 0
        for line in _urlhaus_csv_text().splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line], quotechar='"'))
            except Exception:
                continue
            if len(row) < 3:
                continue
            row_url = row[2].strip().strip('"')
            if host in row_url:
                count += 1
        if count:
            return CheckResult(
                source="URLhaus", endpoint=csv_endpoint, method="GET", status="hit",
                data_point=f"url_count>={count} in recent CSV",
                detail="Host found in URLhaus recent CSV export",
                reference="https://urlhaus.abuse.ch/",
                is_corroborating=True,
            )
        return CheckResult(
            source="URLhaus", endpoint=csv_endpoint, method="GET", status="miss",
            data_point="host_not_in_csv", detail="Host not in URLhaus recent CSV",
        )
    except Exception as e:
        return CheckResult(
            source="URLhaus", endpoint=csv_endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_malwarebazaar(hash_value: str) -> CheckResult:
    endpoint = "POST https://mb-api.abuse.ch/api/v1/ (get_info)"
    key = _usable_abuse_ch_key()
    h = hash_value.lower().strip()
    if not key:
        return _check_malwarebazaar_csv(h)

    try:
        data = http_post_json(
            "https://mb-api.abuse.ch/api/v1/",
            {"query": "get_info", "hash": h},
            headers={"Auth-Key": key},
        )
        qs = data.get("query_status", "")
        if qs == "hash_not_found":
            csv_result = _check_malwarebazaar_csv(h)
            if csv_result.status == "hit":
                return csv_result
            return CheckResult(
                source="MalwareBazaar", endpoint=endpoint, method="POST", status="refute",
                data_point=f"query_status={qs}", detail="Hash not in MalwareBazaar",
                is_refute=True,
            )
        if qs != "ok":
            return _check_malwarebazaar_csv(h)
        sample = (data.get("data") or [{}])[0]
        sig = sample.get("signature", "")
        ft = sample.get("file_type", "")
        dp = f"signature={sig}, file_type={ft}"
        return CheckResult(
            source="MalwareBazaar", endpoint=endpoint, method="POST", status="hit",
            data_point=dp, detail="Known malware sample",
            reference=f"https://bazaar.abuse.ch/sample/{h}/",
            is_authoritative_hit=True,
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped("MalwareBazaar", endpoint, "POST", "rate limited (HTTP 429)")
        if _auth_failure(e):
            return _check_malwarebazaar_csv(h)
        csv_result = _check_malwarebazaar_csv(h)
        if csv_result.status in ("hit", "refute"):
            return csv_result
        return CheckResult(
            source="MalwareBazaar", endpoint=endpoint, method="POST", status="error",
            data_point="", detail=repr(e),
        )


_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_cisa_kev_cache: tuple[float, dict] | None = None


def _cisa_kev_data() -> dict:
    global _cisa_kev_cache
    now = time.time()
    if _cisa_kev_cache and now - _cisa_kev_cache[0] < 3600:
        return _cisa_kev_cache[1]
    raw = http_get(_CISA_KEV_URL)
    data = json.loads(raw.decode())
    _cisa_kev_cache = (now, data)
    return data


def _check_cisa_kev(cve: str) -> CheckResult:
    endpoint = f"GET {_CISA_KEV_URL}"
    cve_u = cve.upper().strip()
    try:
        data = _cisa_kev_data()
        for v in data.get("vulnerabilities", []):
            if v.get("cveID", "").upper() == cve_u:
                dp = f"cveID={cve_u}, vendor={v.get('vendorProject', '')}"
                return CheckResult(
                    source="CISA KEV", endpoint=endpoint, method="GET", status="hit",
                    data_point=dp,
                    detail="CVE in CISA Known Exploited Vulnerabilities catalog",
                    reference=str(v.get("notes") or f"https://nvd.nist.gov/vuln/detail/{cve_u}"),
                    is_authoritative_hit=True,
                )
        return CheckResult(
            source="CISA KEV", endpoint=endpoint, method="GET", status="miss",
            data_point=f"cveID={cve_u} not in feed",
            detail="CVE not in CISA KEV",
        )
    except Exception as e:
        return CheckResult(
            source="CISA KEV", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def _check_nvd(cve: str) -> CheckResult:
    endpoint = "GET https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_u = cve.upper().strip()
    headers: dict[str, str] = {"Accept": "application/json"}
    key = _nvd_key()
    if key:
        headers["apiKey"] = key
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_u}"
    try:
        raw = _http_get_with_headers(url, headers)
        data = json.loads(raw.decode())
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return CheckResult(
                source="NVD", endpoint=endpoint, method="GET", status="refute",
                data_point="vulnerabilities=[]",
                detail="CVE not found in NVD",
                is_refute=True,
            )
        metrics = (
            vulns[0].get("cve", {}).get("metrics", {}).get("cvssMetricV31")
            or vulns[0].get("cve", {}).get("metrics", {}).get("cvssMetricV30")
            or []
        )
        score, severity = "", ""
        if metrics:
            cvss = metrics[0].get("cvssData", {})
            score = str(cvss.get("baseScore", ""))
            severity = str(cvss.get("baseSeverity", ""))
        dp = f"baseScore={score}, baseSeverity={severity}"
        return CheckResult(
            source="NVD", endpoint=endpoint, method="GET", status="hit",
            data_point=dp, detail="Valid CVE record in NVD",
            reference=f"https://nvd.nist.gov/vuln/detail/{cve_u}",
            is_corroborating=True,
        )
    except Exception as e:
        if _rate_limited(e):
            return _skipped("NVD", endpoint, "GET", "rate limited (HTTP 429)")
        return CheckResult(
            source="NVD", endpoint=endpoint, method="GET", status="error",
            data_point="", detail=repr(e),
        )


def cross_check(parsed: ParsedAlert, routes: list[SourceRoute]) -> list[CheckResult]:
    """Stage 3 — query each routed source."""
    if not parsed.ioc_value:
        return [CheckResult(
            source="—", endpoint="—", method="—", status="error",
            data_point="", detail="No indicator value to verify",
        )]

    results: list[CheckResult] = []
    seen: set[str] = set()

    for route in routes:
        if route.name in seen:
            continue
        seen.add(route.name)

        if route.name == "AbuseIPDB":
            results.append(_check_abuseipdb(parsed.ioc_value))
        elif route.name == "ThreatFox":
            results.append(_check_threatfox_search(parsed.ioc_value, "ThreatFox"))
        elif route.name == "abuse.ch Hunting":
            results.append(_check_threatfox_search(parsed.ioc_value, "abuse.ch Hunting"))
        elif route.name == "URLhaus":
            if parsed.ioc_type == "url":
                results.append(_check_urlhaus_url(parsed.ioc_value))
            elif parsed.ioc_type == "domain":
                results.append(_check_urlhaus_host(parsed.ioc_value))
            else:
                host = parsed.ioc_value.split("/")[2] if "://" in parsed.ioc_value else parsed.ioc_value
                results.append(_check_urlhaus_host(host))
        elif route.name == "MalwareBazaar":
            results.append(_check_malwarebazaar(parsed.ioc_value))
        elif route.name == "OpenPhish":
            results.append(_check_openphish(parsed.ioc_value))
        elif route.name == "CISA KEV":
            results.append(_check_cisa_kev(parsed.ioc_value))
        elif route.name == "NVD":
            results.append(_check_nvd(parsed.ioc_value))
        elif route.name == "Feodo Tracker":
            results.append(_check_feodo_ip(parsed.ioc_value))
        elif route.name == "PhishTank":
            results.append(_check_phishtank(parsed.ioc_value))
        elif route.name == "Spamhaus DROP":
            results.append(_check_spamhaus_drop(parsed.ioc_value))
        elif route.name == "URLhaus-Hosts":
            results.append(_check_urlhaus_hosts(parsed.ioc_value))
        elif route.name == "SSLBL":
            results.append(_check_sslbl(parsed.ioc_value))
        elif route.name == "blocklist.de":
            results.append(_check_blocklist_de(parsed.ioc_value))
        elif route.name == "Tor Exit Nodes":
            results.append(_check_tor_exit(parsed.ioc_value))

    return results


def _checklist_stage3(checks: list[CheckResult]) -> dict[str, Any]:
    hits = [c for c in checks if c.status == "hit"]
    corroborate = sum(1 for c in checks if c.is_authoritative_hit or c.is_corroborating)
    return {
        "10_api_record_returned": [c.source for c in hits],
        "11_key_data_points": {c.source: c.data_point for c in checks if c.data_point},
        "12_confirm_refute_neutral": {
            c.source: (
                "confirm" if c.is_authoritative_hit or c.is_corroborating
                else "refute" if c.is_refute else "neutral"
            )
            for c in checks if c.status in ("hit", "refute", "miss")
        },
        "13_independent_corroboration_count": corroborate,
        "14_staleness_note": "Recency judged from alert timestamp; APIs return current state.",
    }


# ─── Stage 4: Classify ────────────────────────────────────────────────────────

_SOURCE_REFUTE_SCOPE: dict[str, frozenset[str]] = {
    "OpenPhish": frozenset({"OpenPhish"}),
    "PhishTank": frozenset({"PhishTank"}),
    "URLhaus": frozenset({"URLhaus"}),
    "URLhaus-Hosts": frozenset({"URLhaus-Hosts"}),
    "MalwareBazaar": frozenset({"MalwareBazaar"}),
    "ThreatFox": frozenset({"ThreatFox", "abuse.ch Hunting"}),
    "Feodo Tracker": frozenset({"Feodo Tracker"}),
    "Spamhaus DROP": frozenset({"Spamhaus DROP"}),
    "CISA-KEV": frozenset({"CISA KEV"}),
    "SSLBL": frozenset({"SSLBL"}),
    "blocklist.de": frozenset({"blocklist.de"}),
    "Tor Exit Nodes": frozenset({"Tor Exit Nodes"}),
}


def _relevant_refutes(parsed: ParsedAlert, checks: list[CheckResult]) -> list[CheckResult]:
    """Only count refutes from the source that raised the alert (URLhaus ≠ phishing)."""
    refutes = [c for c in checks if c.is_refute]
    allowed = _SOURCE_REFUTE_SCOPE.get(parsed.source_raised)
    if allowed:
        return [c for c in refutes if c.source in allowed]
    return refutes


def classify(parsed: ParsedAlert, checks: list[CheckResult]) -> tuple[str, str, int, str, list[dict[str, str]]]:
    """
    Returns (classification, confidence, corroboration_count, rationale, references).
    """
    skipped = [c.source for c in checks if c.status == "skipped"]
    auth_hits = [c for c in checks if c.is_authoritative_hit]
    corroborating = [c for c in checks if c.is_corroborating]
    refutes = _relevant_refutes(parsed, checks)

    cisa_hit = next((c for c in checks if c.source == "CISA KEV" and c.is_authoritative_hit), None)
    if cisa_hit:
        refs = [_reference_row(cisa_hit)]
        return (
            "GENUINE",
            "Critical",
            1,
            "CVE listed in CISA KEV — actively exploited in the wild (overrides all).",
            refs,
        )

    all_hits = auth_hits + corroborating
    corro_count = len({c.source for c in all_hits})

    if auth_hits:
        refs = [_reference_row(c) for c in auth_hits + corroborating if c.data_point]
        if not refs:
            return (
                "UNVERIFIED",
                "Low",
                0,
                "Authoritative hit without parseable reference — cannot mark GENUINE.",
                [],
            )
        confidence = "High" if corro_count >= 2 else "Medium"
        return (
            "GENUINE",
            confidence,
            corro_count,
            f"{len(auth_hits)} authoritative source(s) met hit threshold; "
            f"{corro_count} total corroboration.",
            refs,
        )

    if corroborating and not refutes:
        refs = [_reference_row(c) for c in corroborating if c.data_point]
        if refs:
            return (
                "GENUINE",
                "Medium",
                corro_count,
                "Corroborating evidence only (no single authoritative threshold).",
                refs,
            )

    if refutes and not all_hits:
        return (
            "FALSE POSITIVE",
            "High",
            0,
            f"Refuted by {', '.join(c.source for c in refutes)} with no corroborating hits.",
            [],
        )

    if skipped and not all_hits and not refutes:
        return (
            "UNVERIFIED",
            "Low",
            0,
            f"No hits; sources skipped: {', '.join(skipped)}.",
            [],
        )

    return (
        "UNVERIFIED",
        "Low",
        0,
        "No authoritative source met hit threshold; no explicit refutation.",
        [],
    )


def _reference_row(check: CheckResult) -> dict[str, str]:
    return {
        "source": check.source,
        "endpoint": check.endpoint,
        "data_point": check.data_point,
        "reference_url": check.reference,
    }


def _checklist_stage4(
    parsed: ParsedAlert,
    checks: list[CheckResult],
    classification: str,
    confidence: str,
    corro_count: int,
    rationale: str,
    references: list[dict[str, str]],
) -> dict[str, Any]:
    cisa = any(c.source == "CISA KEV" and c.is_authoritative_hit for c in checks)
    auth = any(c.is_authoritative_hit for c in checks)
    return {
        "15_cisa_kev": cisa,
        "16_authoritative_hit": auth,
        "17_two_plus_corroborate": corro_count >= 2,
        "18_all_clean": classification == "FALSE POSITIVE",
        "19_confidence_rationale": f"{confidence} — {rationale}",
        "20_genuine_references": references,
        "21_genuine_without_reference": classification == "GENUINE" and not references,
        "22_skipped_sources": [c.source for c in checks if c.status == "skipped"],
        "23_summary_fields_ready": True,
    }


# ─── Stage 5: Pipeline ───────────────────────────────────────────────────────

def _build_row(parsed: ParsedAlert, checks: list[CheckResult],
               classification: str, confidence: str,
               references: list[dict[str, str]]) -> dict[str, str]:
    sources_checked = ", ".join(c.source for c in checks)
    data_points = "; ".join(
        f"{c.source}: {c.data_point}" for c in checks if c.data_point
    ) or "—"
    ref_str = "; ".join(
        f"{r['source']} | {r['endpoint']} | {r['data_point']}"
        for r in references
    ) or "—"
    return {
        "alert": f"{parsed.ioc_value} — {parsed.claim[:80]}",
        "type": parsed.ioc_type,
        "sources_checked": sources_checked,
        "data_point_returned": data_points,
        "classification": classification,
        "confidence": confidence,
        "reference": ref_str,
    }


def verify_alert_dict(alert: dict[str, Any]) -> AlertVerification:
    """Run the full 5-stage pipeline on one dashboard alert."""
    parsed = parse_alert(alert)
    routes = route_sources(parsed)
    checks = cross_check(parsed, routes)
    classification, confidence, corro_count, rationale, references = classify(parsed, checks)

    if classification == "GENUINE" and not references:
        classification = "UNVERIFIED"
        confidence = "Low"
        rationale = "Downgraded: GENUINE requires populated reference (source + endpoint + data point)."

    skipped = [c.skipped_reason for c in checks if c.status == "skipped" and c.skipped_reason]

    checklist: dict[str, Any] = {}
    checklist.update(parsed.checklist_stage1())
    checklist.update(_checklist_stage2(parsed, routes))
    checklist.update(_checklist_stage3(checks))
    checklist.update(_checklist_stage4(
        parsed, checks, classification, confidence, corro_count, rationale, references,
    ))

    row = _build_row(parsed, checks, classification, confidence, references)

    return AlertVerification(
        parsed=parsed,
        routes=routes,
        checks=checks,
        classification=classification,
        confidence=confidence,
        references=references,
        skipped_sources=skipped,
        corroboration_count=corro_count,
        rationale=rationale,
        checklist=checklist,
        row=row,
    )


def verify_alerts(
    alerts: list[dict[str, Any]],
    *,
    progress: Callable[[str], None] | None = None,
) -> VerificationSummary:
    """Stage 5 — verify a batch and emit summary counts."""
    summary = VerificationSummary()
    for alert in alerts:
        if progress:
            progress(str(alert.get("id") or alert.get("title") or "alert"))
        result = verify_alert_dict(alert)
        summary.results.append(result)
        summary.total += 1
        if result.classification == "GENUINE":
            summary.genuine += 1
        elif result.classification == "FALSE POSITIVE":
            summary.false_positive += 1
        else:
            summary.unverified += 1
        summary.skipped_auth_sources.extend(result.skipped_sources)
    return summary
