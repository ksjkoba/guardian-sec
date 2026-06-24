"""
Threat intelligence feed engine.

Fetches, caches, and parses public free TI feeds into in-memory sets
for O(1) IOC lookup.  No API keys required.

Feeds:
  - Feodo Tracker    — known botnet/C2 IPs (abuse.ch)
  - URLhaus          — malicious URLs and domains (abuse.ch)
  - MalwareBazaar    — malware SHA-256 hashes (abuse.ch)
  - Emerging Threats — compromised/scanner IPs (proofpoint)
  - Spamhaus DROP    — hijacked netblocks (spamhaus)
  - ThreatFox        — multi-type IOCs: IPs, domains, URLs (abuse.ch)
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

CACHE_DIR = Path(os.environ.get("GUARDIAN_CACHE_DIR", Path.home() / ".guardian" / "ti_cache"))
DEFAULT_TTL_SECS = 3600  # 1 hour
REQUEST_TIMEOUT = 15


@dataclass(frozen=True)
class IOCMatch:
    ioc: str                   # the matched value (IP, domain, hash)
    ioc_type: str              # "ip", "domain", "hash", "url"
    feed: str                  # feed name
    malware_family: str = ""   # e.g. "Emotet", "QakBot"
    tags: tuple[str, ...] = field(default_factory=tuple)
    confidence: int = 80       # 0-100

    def __str__(self) -> str:
        fam = f" [{self.malware_family}]" if self.malware_family else ""
        return f"{self.feed}{fam} (confidence {self.confidence}%)"


@dataclass
class FeedDefinition:
    name: str
    url: str
    ioc_type: str        # "ip", "domain", "hash", "url"
    ttl_secs: int = DEFAULT_TTL_SECS
    parser: str = "line"  # "line", "csv", "json_abuse", "et_rules"
    parser_kwargs: dict = field(default_factory=dict)


# ─── Feed registry ────────────────────────────────────────────────────────────

FEEDS: list[FeedDefinition] = [
    FeedDefinition(
        name="Feodo-C2-IPs",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        ioc_type="ip",
        parser="line",
        parser_kwargs={"comment": "#"},
    ),
    FeedDefinition(
        name="Feodo-C2-IPs-Recommended",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        ioc_type="ip",
        parser="line",
        parser_kwargs={"comment": "#"},
    ),
    FeedDefinition(
        name="URLhaus-Domains",
        url="https://urlhaus.abuse.ch/downloads/text/",
        ioc_type="url",
        parser="line",
        parser_kwargs={"comment": "#"},
    ),
    FeedDefinition(
        name="MalwareBazaar-Recent",
        url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
        ioc_type="hash",
        parser="line",
        parser_kwargs={"comment": "#"},
    ),
    FeedDefinition(
        name="ThreatFox-IPs",
        url="https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        ioc_type="ip",
        parser="csv_threatfox",
        parser_kwargs={"skip_rows": 9},
    ),
    FeedDefinition(
        name="ThreatFox-Domains",
        url="https://threatfox.abuse.ch/export/csv/domains/recent/",
        ioc_type="domain",
        parser="csv_threatfox",
        parser_kwargs={"skip_rows": 9},
    ),
    FeedDefinition(
        name="Spamhaus-DROP",
        url="https://www.spamhaus.org/drop/drop.txt",
        ioc_type="ip",
        parser="line",
        parser_kwargs={"comment": ";", "cidr": True},
    ),
    FeedDefinition(
        name="Emerging-Threats-Compromised",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        ioc_type="ip",
        parser="line",
        parser_kwargs={"comment": "#"},
    ),
]


# ─── Cache helpers ────────────────────────────────────────────────────────────

def _cache_path(feed: FeedDefinition) -> Path:
    slug = re.sub(r"[^a-z0-9]", "_", feed.name.lower())
    return CACHE_DIR / f"{slug}.cache"


def _is_fresh(path: Path, ttl: int) -> bool:
    if not path.exists():
        return False
    return time.time() - path.stat().st_mtime < ttl


def _fetch_raw(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Guardian-TI/1.0 (security research, https://github.com/guardian-sec)"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return resp.read()


def _load_or_fetch(feed: FeedDefinition) -> bytes:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = _cache_path(feed)
    if _is_fresh(cache, feed.ttl_secs):
        return cache.read_bytes()
    try:
        raw = _fetch_raw(feed.url)
        cache.write_bytes(raw)
        return raw
    except Exception:
        if cache.exists():
            return cache.read_bytes()  # stale cache is better than nothing
        raise


# ─── Parsers ──────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _parse_line(raw: bytes, comment: str = "#", cidr: bool = False) -> Iterator[str]:
    for line in raw.decode(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(comment):
            continue
        # Strip inline comments
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        if cidr:
            # Expand CIDR → keep the network address for matching
            try:
                net = ipaddress.ip_network(line, strict=False)
                yield str(net)
                continue
            except ValueError:
                pass
        yield line


def _parse_csv_threatfox(raw: bytes, skip_rows: int = 9) -> Iterator[tuple[str, str]]:
    """Yields (ioc_value, malware_family) pairs."""
    lines = raw.decode(errors="replace").splitlines()
    for line in lines[skip_rows:]:
        if not line or line.startswith("#"):
            continue
        try:
            reader = csv.reader([line], quotechar='"')
            row = next(reader)
            if len(row) >= 3:
                ioc = row[2].strip().strip('"')
                # ip:port → strip port
                if ":" in ioc and not ioc.startswith("http"):
                    ioc = ioc.rsplit(":", 1)[0]
                # Full export: row[1]=ioc_id, row[7]=malware_printable
                # Short rows (tests/legacy): row[1]=malware family name
                malware = ""
                if len(row) > 7:
                    malware = row[7].strip().strip('"')
                if not malware and len(row) > 5:
                    malware = row[5].strip().strip('"')
                if not malware and len(row) >= 2:
                    candidate = row[1].strip().strip('"')
                    if candidate and not candidate.isdigit():
                        malware = candidate
                yield ioc, malware
        except Exception:
            continue


# ─── In-memory index ─────────────────────────────────────────────────────────

@dataclass
class FeedIndex:
    """Loaded, searchable TI index."""
    # Sets for O(1) exact lookup
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    # CIDR networks for subnet matching
    networks: list[ipaddress.IPv4Network] = field(default_factory=list)
    # ioc_value -> list of IOCMatch (for rich metadata on hit)
    metadata: dict[str, list[IOCMatch]] = field(default_factory=dict)
    loaded_feeds: list[str] = field(default_factory=list)
    load_time: float = field(default_factory=time.time)
    errors: list[str] = field(default_factory=list)

    def _add(self, value: str, match: IOCMatch) -> None:
        self.metadata.setdefault(value, []).append(match)

    def lookup_ip(self, ip: str) -> list[IOCMatch]:
        results = list(self.metadata.get(ip, []))
        # Check CIDR membership
        try:
            addr = ipaddress.ip_address(ip)
            for net in self.networks:
                if addr in net:
                    net_key = str(net)
                    results.extend(self.metadata.get(net_key, []))
        except ValueError:
            pass
        return results

    def lookup_domain(self, domain: str) -> list[IOCMatch]:
        domain = domain.lower().rstrip(".")
        results = list(self.metadata.get(domain, []))
        # Also check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            results.extend(self.metadata.get(parent, []))
        return results

    def lookup_hash(self, h: str) -> list[IOCMatch]:
        return list(self.metadata.get(h.lower(), []))

    def lookup_url(self, url: str) -> list[IOCMatch]:
        results = list(self.metadata.get(url, []))
        # Extract domain from URL and check that too
        m = re.search(r"https?://([^/\?:]+)", url, re.IGNORECASE)
        if m:
            results.extend(self.lookup_domain(m.group(1)))
        return results

    def lookup(self, value: str) -> list[IOCMatch]:
        """Auto-detect IOC type and look it up."""
        v = value.strip()
        if _IP_RE.match(v):
            return self.lookup_ip(v)
        if _SHA256_RE.match(v):
            return self.lookup_hash(v)
        if _URL_RE.match(v):
            return self.lookup_url(v)
        if _DOMAIN_RE.match(v):
            return self.lookup_domain(v)
        return []

    @property
    def total_iocs(self) -> int:
        return len(self.metadata)


# ─── Loader ───────────────────────────────────────────────────────────────────

def load_feeds(
    feeds: list[FeedDefinition] | None = None,
    force_refresh: bool = False,
    progress_cb=None,
) -> FeedIndex:
    """Load (and if needed fetch) all feeds into a FeedIndex."""
    feeds = feeds or FEEDS
    index = FeedIndex()

    for feed in feeds:
        if progress_cb:
            progress_cb(f"Loading {feed.name}...")
        try:
            if force_refresh:
                _cache_path(feed).unlink(missing_ok=True)
            raw = _load_or_fetch(feed)
            _parse_into_index(feed, raw, index)
            index.loaded_feeds.append(feed.name)
        except Exception as e:
            index.errors.append(f"{feed.name}: {e}")

    return index


def _parse_into_index(feed: FeedDefinition, raw: bytes, index: FeedIndex) -> None:
    kwargs = feed.parser_kwargs

    if feed.parser == "line":
        for value in _parse_line(raw, **{k: v for k, v in kwargs.items() if k in ("comment",)}):
            cidr = kwargs.get("cidr", False)
            if cidr:
                try:
                    net = ipaddress.ip_network(value, strict=False)
                    index.networks.append(net)
                    match = IOCMatch(ioc=value, ioc_type="ip", feed=feed.name, confidence=85)
                    index._add(value, match)
                    continue
                except ValueError:
                    pass
            match = IOCMatch(ioc=value, ioc_type=feed.ioc_type, feed=feed.name, confidence=90)
            index._add(value, match)

    elif feed.parser == "csv_threatfox":
        skip = kwargs.get("skip_rows", 9)
        for ioc_val, malware in _parse_csv_threatfox(raw, skip_rows=skip):
            match = IOCMatch(
                ioc=ioc_val,
                ioc_type=feed.ioc_type,
                feed=feed.name,
                malware_family=malware,
                confidence=92,
            )
            index._add(ioc_val, match)


# ─── Global singleton ─────────────────────────────────────────────────────────

_index: FeedIndex | None = None
_index_lock = threading.Lock()
_refresh_thread: threading.Thread | None = None


def get_index(force_refresh: bool = False) -> FeedIndex:
    """Return the global FeedIndex, loading it on first call."""
    global _index
    with _index_lock:
        if _index is None or force_refresh:
            _index = load_feeds(force_refresh=force_refresh)
    return _index


def start_background_refresh(interval_secs: int = DEFAULT_TTL_SECS) -> None:
    """Start a background thread that refreshes feeds on a schedule."""
    global _refresh_thread

    def _loop() -> None:
        while True:
            time.sleep(interval_secs)
            try:
                global _index
                new_index = load_feeds(force_refresh=True)
                with _index_lock:
                    _index = new_index
            except Exception:
                pass

    _refresh_thread = threading.Thread(target=_loop, daemon=True)
    _refresh_thread.start()


def feed_status() -> list[dict]:
    """Return status of all feed cache files."""
    rows = []
    for feed in FEEDS:
        cache = _cache_path(feed)
        if cache.exists():
            age = time.time() - cache.stat().st_mtime
            fresh = age < feed.ttl_secs
            size = cache.stat().st_size
        else:
            age = float("inf")
            fresh = False
            size = 0
        rows.append({
            "feed": feed.name,
            "ioc_type": feed.ioc_type,
            "cached": cache.exists(),
            "fresh": fresh,
            "age_mins": round(age / 60, 1) if cache.exists() else None,
            "size_kb": round(size / 1024, 1),
            "ttl_mins": feed.ttl_secs // 60,
        })
    return rows
