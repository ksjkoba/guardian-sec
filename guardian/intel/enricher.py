"""
IOC enrichment layer.

Runs every Alert through the TI feed index at ingestion time.
Matches on IPs, domains, URLs, and hashes extracted from alert text
and metadata.  Upgrades alert severity when a confirmed IOC is found.
Also runs the heuristic platform scanner for suspicious-but-legitimate
services (pastebin, ngrok, URL shorteners, etc.).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from guardian.engine.alert import Alert, Severity
from guardian.intel.feeds import IOCMatch
from guardian.intel.heuristics import SuspiciousMatch, check_text

if TYPE_CHECKING:
    from guardian.intel.feeds import FeedIndex

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b",
    re.IGNORECASE,
)

# Severity upgrade: if IOC confidence ≥ this, bump one level
_UPGRADE_CONFIDENCE = 80

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _upgrade_severity(current: Severity, by: int = 1) -> Severity:
    idx = _SEVERITY_ORDER.index(current.value)
    new_idx = min(idx + by, len(_SEVERITY_ORDER) - 1)
    return Severity(_SEVERITY_ORDER[new_idx])


def _extract_iocs_from_alert(alert: Alert) -> dict[str, list[str]]:
    """Extract all potential IOC values from alert fields."""
    text = " ".join([
        alert.title,
        alert.description,
        alert.evidence,
        " ".join(str(v) for v in alert.metadata.values()),
    ])
    return {
        "ip": list(set(_IP_RE.findall(text))),
        "hash": list(set(_SHA256_RE.findall(text))),
        "url": list(set(_URL_RE.findall(text))),
        "domain": list(set(_DOMAIN_RE.findall(text))),
    }


def enrich_alert(alert: Alert, index: "FeedIndex") -> list[IOCMatch]:
    """
    Cross-reference alert against TI feeds and heuristic platform list.
    Mutates alert.metadata in-place to add IOC and suspicious match info.
    Returns list of confirmed IOC matches (TI feed hits).
    """
    all_matches: list[IOCMatch] = []
    iocs = _extract_iocs_from_alert(alert)

    for ip in iocs["ip"]:
        matches = index.lookup_ip(ip)
        all_matches.extend(matches)

    for h in iocs["hash"]:
        matches = index.lookup_hash(h)
        all_matches.extend(matches)

    for url in iocs["url"]:
        matches = index.lookup_url(url)
        all_matches.extend(matches)

    # Domains — deduplicate against IPs already checked
    checked_domains: set[str] = set()
    for domain in iocs["domain"]:
        d = domain.lower()
        if d in checked_domains:
            continue
        checked_domains.add(d)
        matches = index.lookup_domain(d)
        all_matches.extend(matches)

    # ── Heuristic platform scan (pastebin, ngrok, shorteners, etc.) ──────────
    full_text = " ".join([
        alert.title, alert.description, alert.evidence,
        " ".join(str(v) for v in alert.metadata.values() if isinstance(v, str)),
    ])
    suspicious: list[SuspiciousMatch] = check_text(full_text)

    if suspicious:
        alert.metadata["suspicious_platforms"] = [
            {
                "value": s.value,
                "category": s.category,
                "reason": s.reason,
                "confidence": s.confidence,
                "example_abuse": s.example_abuse,
            }
            for s in suspicious
        ]
        categories = sorted({s.category for s in suspicious})
        susp_tag = " | ".join(f"SUSPICIOUS:{c}" for c in categories[:3])

        # Merge into existing ioc_tag or set fresh
        existing = alert.metadata.get("ioc_tag", "")
        alert.metadata["ioc_tag"] = (existing + " | " + susp_tag).strip(" |") if existing else susp_tag

        # Upgrade severity if high-confidence suspicious match
        best_susp = max(s.confidence for s in suspicious)
        if best_susp >= _UPGRADE_CONFIDENCE and alert.severity not in (Severity.HIGH, Severity.CRITICAL):
            alert.severity = _upgrade_severity(alert.severity)
            alert.metadata["severity_upgraded"] = True

    if not all_matches and not suspicious:
        return []

    if all_matches:
        # Annotate confirmed TI matches
        alert.metadata["ioc_matches"] = [
            {
                "ioc": m.ioc,
                "type": m.ioc_type,
                "feed": m.feed,
                "malware_family": m.malware_family,
                "confidence": m.confidence,
            }
            for m in all_matches
        ]

        feed_names = sorted({m.feed for m in all_matches})
        families = sorted({m.malware_family for m in all_matches if m.malware_family})
        tag_parts = [f"IOC:{f}" for f in feed_names[:3]]
        if families:
            tag_parts.append(f"MALWARE:{','.join(families[:2])}")
        ti_tag = " | ".join(tag_parts)

        existing = alert.metadata.get("ioc_tag", "")
        alert.metadata["ioc_tag"] = (ti_tag + " | " + existing).strip(" |") if existing else ti_tag

        best_confidence = max(m.confidence for m in all_matches)
        if best_confidence >= _UPGRADE_CONFIDENCE and alert.severity != Severity.CRITICAL:
            alert.severity = _upgrade_severity(alert.severity)
            alert.metadata["severity_upgraded"] = True

    return all_matches


class AlertEnricher:
    """
    Wraps a FeedIndex and provides a callable that enriches alerts.
    Designed to be inserted into the _store_alert pipeline.
    """

    def __init__(self, index: "FeedIndex"):
        self._index = index

    def __call__(self, alert: Alert) -> list[IOCMatch]:
        return enrich_alert(alert, self._index)

    @property
    def total_iocs(self) -> int:
        return self._index.total_iocs

    @property
    def loaded_feeds(self) -> list[str]:
        return self._index.loaded_feeds
