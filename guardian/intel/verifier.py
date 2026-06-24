"""
Live-source verification for global threat alerts.

Re-checks an IOC against the original provider's feed/API to confirm
the alert is genuine and still listed (or was listed at ingest time).
"""

from __future__ import annotations

import json
import time
from typing import Any

from guardian.intel.global_ticker import (
    SOURCE_REGISTRY,
    _parse_threatfox_recent_rows,
    http_get,
    http_post_json,
    load_blocklist_de_ips,
    load_openphish_urls,
    load_tor_exit_ips,
)


def verify_on_source(
    ioc_value: str,
    ioc_type: str,
    source: str,
) -> dict[str, Any]:
    """
    Check whether ioc_value currently appears on the named source feed.
    Returns a dict suitable for the dashboard verify badge.
    """
    ioc_value = (ioc_value or "").strip()
    ioc_type = (ioc_type or "").strip().lower()
    source = (source or "").strip()
    checked_at = time.time()

    if not ioc_value or not source:
        return {
            "verified": False,
            "found": False,
            "source": source,
            "checked_at": checked_at,
            "detail": "Missing IOC value or source name.",
        }

    try:
        if source == "ThreatFox":
            return _verify_threatfox(ioc_value, ioc_type, checked_at)
        if source == "URLhaus":
            return _verify_urlhaus(ioc_value, checked_at)
        if source == "MalwareBazaar":
            return _verify_malwarebazaar(ioc_value, checked_at)
        if source == "CISA-KEV":
            return _verify_cisa_kev(ioc_value, checked_at)
        if source == "OpenPhish":
            return _verify_openphish(ioc_value, checked_at)
        if source == "PhishTank":
            return _verify_phishtank(ioc_value, checked_at)
        if source == "Feodo Tracker":
            return _verify_feodo(ioc_value, checked_at)
        if source == "Spamhaus DROP":
            return _verify_spamhaus_drop(ioc_value, checked_at)
        if source == "URLhaus-Hosts":
            return _verify_urlhaus_hosts(ioc_value, checked_at)
        if source == "SSLBL":
            return _verify_sslbl(ioc_value, checked_at)
        if source == "blocklist.de":
            return _verify_blocklist_de(ioc_value, checked_at)
        if source == "Tor Exit Nodes":
            return _verify_tor_exit(ioc_value, checked_at)
    except Exception as e:
        return {
            "verified": False,
            "found": False,
            "source": source,
            "checked_at": checked_at,
            "detail": f"Live check failed: {e!r}",
        }

    # Fallback: local TI cache
    try:
        from guardian.intel.feeds import get_index
        matches = get_index().lookup(ioc_value)
        feed_names = {m.feed for m in matches}
        if source.replace("-", " ") in str(feed_names) or any(source.split("-")[0] in f for f in feed_names):
            return {
                "verified": True,
                "found": True,
                "source": source,
                "checked_at": checked_at,
                "detail": f"Confirmed in Guardian TI cache ({len(matches)} match(es)).",
                "method": "ti_cache",
            }
    except Exception:
        pass

    return {
        "verified": False,
        "found": False,
        "source": source,
        "checked_at": checked_at,
        "detail": f"No live verifier for source '{source}'.",
    }


def _ok(source: str, checked_at: float, detail: str, ref: str = "", method: str = "live_feed") -> dict[str, Any]:
    return {
        "verified": True,
        "found": True,
        "source": source,
        "checked_at": checked_at,
        "detail": detail,
        "reference_url": ref,
        "method": method,
    }


def _miss(source: str, checked_at: float, detail: str) -> dict[str, Any]:
    return {
        "verified": True,
        "found": False,
        "source": source,
        "checked_at": checked_at,
        "detail": detail,
        "method": "live_feed",
    }


def _verify_threatfox(ioc_value: str, ioc_type: str, checked_at: float) -> dict[str, Any]:
    raw = http_get("https://threatfox.abuse.ch/export/csv/ip-port/recent/")
    rows = _parse_threatfox_recent_rows(raw)
    for row in rows:
        if row["ioc"] == ioc_value or ioc_value in row.get("ioc", ""):
            return _ok(
                "ThreatFox",
                checked_at,
                f"IP {ioc_value} is listed on ThreatFox right now ({row.get('malware', 'malware')}).",
                ref=row.get("reference", ""),
            )
    # domain export fallback
    if ioc_type == "domain":
        raw2 = http_get("https://threatfox.abuse.ch/export/csv/domains/recent/")
        if ioc_value.lower() in raw2.decode(errors="replace").lower():
            return _ok("ThreatFox", checked_at, f"Domain {ioc_value} found in ThreatFox recent export.")
    return _miss(
        "ThreatFox",
        checked_at,
        f"{ioc_value} not in ThreatFox recent export — may have aged off the feed (was genuine at ingest).",
    )


def _verify_urlhaus(ioc_value: str, checked_at: float) -> dict[str, Any]:
    try:
        data = http_post_json("https://urlhaus-api.abuse.ch/v1/url/", {"url": ioc_value})
        if data.get("query_status") == "ok":
            ref = data.get("urlhaus_reference", data.get("urlhaus_link", ""))
            return _ok(
                "URLhaus",
                checked_at,
                "URLhaus API confirms this URL is in the database.",
                ref=str(ref) if ref else f"https://urlhaus.abuse.ch/",
            )
    except Exception:
        pass
    raw = http_get("https://urlhaus.abuse.ch/downloads/csv_recent/").decode(errors="replace")
    if ioc_value in raw:
        return _ok("URLhaus", checked_at, "URL found in URLhaus recent CSV dump.")
    return _miss("URLhaus", checked_at, "URL not in URLhaus recent feed anymore.")


def _verify_malwarebazaar(ioc_value: str, checked_at: float) -> dict[str, Any]:
    h = ioc_value.lower().strip()
    try:
        data = http_post_json("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": h})
        if data.get("query_status") == "ok":
            sample = (data.get("data") or [{}])[0]
            sig = sample.get("signature", "")
            return _ok(
                "MalwareBazaar",
                checked_at,
                f"MalwareBazaar confirms hash ({sig or 'sample on file'}).",
                ref=f"https://bazaar.abuse.ch/sample/{h}/",
            )
    except Exception:
        pass
    raw = http_get("https://bazaar.abuse.ch/export/csv/recent/").decode(errors="replace")
    if h in raw.lower():
        return _ok("MalwareBazaar", checked_at, "Hash found in MalwareBazaar recent export.")
    return _miss("MalwareBazaar", checked_at, "Hash not in MalwareBazaar recent export.")


def _verify_cisa_kev(ioc_value: str, checked_at: float) -> dict[str, Any]:
    cve = ioc_value.upper()
    raw = http_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    data = json.loads(raw.decode())
    for v in data.get("vulnerabilities", []):
        if v.get("cveID", "").upper() == cve:
            return _ok(
                "CISA-KEV",
                checked_at,
                f"{cve} is in the CISA Known Exploited Vulnerabilities catalog.",
                ref=v.get("notes", f"https://nvd.nist.gov/vuln/detail/{cve}"),
            )
    return _miss("CISA-KEV", checked_at, f"{cve} not found in CISA KEV catalog.")


def _verify_openphish(ioc_value: str, checked_at: float) -> dict[str, Any]:
    urls = load_openphish_urls()
    target = ioc_value.strip().rstrip("/").lower()
    for url in urls:
        if url.strip().rstrip("/").lower() == target:
            return _ok("OpenPhish", checked_at, "URL is on the OpenPhish active phishing feed.", ref=ioc_value)
    return _miss("OpenPhish", checked_at, "URL no longer on OpenPhish active feed.")


def _verify_phishtank(ioc_value: str, checked_at: float) -> dict[str, Any]:
    from guardian.intel.global_ticker import load_phishtank_entries
    entries = load_phishtank_entries()
    for entry in entries:
        if str(entry.get("url", "")).strip() == ioc_value.strip():
            if entry.get("verified") == "yes" and entry.get("online") == "yes":
                ref = entry.get("phish_detail_url", "")
                return _ok(
                    "PhishTank", checked_at,
                    "PhishTank verified-online feed confirms this phishing URL.",
                    ref=str(ref) if ref else ioc_value,
                )
    return _miss("PhishTank", checked_at, "URL not on PhishTank verified-online feed.")


def _verify_feodo(ioc_value: str, checked_at: float) -> dict[str, Any]:
    raw = http_get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv").decode(errors="replace")
    import csv as _csv
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        row = next(_csv.reader([line]))
        if len(row) >= 6 and row[1].strip() == ioc_value.strip():
            return _ok(
                "Feodo Tracker", checked_at,
                f"IP on Feodo Tracker blocklist ({row[5].strip()}, {row[3].strip()}).",
                ref=f"https://feodotracker.abuse.ch/browse/host/{ioc_value.strip()}/",
            )
    return _miss("Feodo Tracker", checked_at, "IP not on Feodo Tracker blocklist.")


def _verify_spamhaus_drop(ioc_value: str, checked_at: float) -> dict[str, Any]:
    raw = http_get("https://www.spamhaus.org/drop/drop.txt").decode(errors="replace")
    for line in raw.splitlines():
        if line.strip().startswith(";") or not line.strip():
            continue
        cidr = line.split(";")[0].strip()
        if cidr == ioc_value.strip():
            return _ok(
                "Spamhaus DROP", checked_at,
                f"Netblock {cidr} listed on Spamhaus DROP.",
                ref="https://www.spamhaus.org/drop/",
            )
    return _miss("Spamhaus DROP", checked_at, "CIDR not on Spamhaus DROP list.")


def _verify_urlhaus_hosts(ioc_value: str, checked_at: float) -> dict[str, Any]:
    raw = http_get("https://urlhaus.abuse.ch/downloads/hostfile/").decode(errors="replace")
    host = ioc_value.strip().lower()
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("	")
        if len(parts) >= 2 and parts[1].strip().lower() == host:
            return _ok(
                "URLhaus-Hosts", checked_at,
                "Domain listed in URLhaus host file.",
                ref=f"https://urlhaus.abuse.ch/host/{host}/",
            )
    return _miss("URLhaus-Hosts", checked_at, "Domain not on URLhaus host file.")


def _verify_sslbl(ioc_value: str, checked_at: float) -> dict[str, Any]:
    from guardian.intel.global_ticker import SSLBL_FEED_URL
    import csv as _csv
    raw = http_get(SSLBL_FEED_URL).decode(errors="replace")
    ip = ioc_value.strip()
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        row = next(_csv.reader([line]))
        if len(row) >= 2 and row[1].strip() == ip:
            reason = row[3].strip() if len(row) > 3 else "malicious SSL"
            return _ok(
                "SSLBL", checked_at,
                f"IP on SSLBL malicious SSL list ({reason}).",
                ref=f"https://sslbl.abuse.ch/sslblip/{ip}/",
            )
    return _miss("SSLBL", checked_at, "IP not on SSLBL feed.")


def _verify_blocklist_de(ioc_value: str, checked_at: float) -> dict[str, Any]:
    ip = ioc_value.strip()
    if ip in load_blocklist_de_ips():
        return _ok(
            "blocklist.de", checked_at,
            "IP listed on blocklist.de abuse reports.",
            ref=f"https://www.blocklist.de/en/view.html?ip={ip}",
        )
    return _miss("blocklist.de", checked_at, "IP not on blocklist.de feed.")


def _verify_tor_exit(ioc_value: str, checked_at: float) -> dict[str, Any]:
    ip = ioc_value.strip()
    if ip in load_tor_exit_ips():
        return _ok(
            "Tor Exit Nodes", checked_at,
            "IP is a current Tor exit node (official Tor Project list).",
            ref="https://check.torproject.org/",
        )
    return _miss("Tor Exit Nodes", checked_at, "IP not on Tor exit node list.")


def source_label(source: str) -> str:
    reg = SOURCE_REGISTRY.get(source, {})
    return reg.get("label", source)
