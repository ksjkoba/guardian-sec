"""
Personal breach lookup — mock-first for QA, swappable to live APIs at deploy.

Providers (GUARDIAN_BREACH_PROVIDER):
  mock          — fictional scenarios for QA (default)
  auto          — HIBP if HIBP_API_KEY set, else multi (free dual-source)
  multi         — XposedOrNot + HackMyIP (free, no keys; exposed if any source hits)
  xposedornot   — single free source
  hibp          — Have I Been Pwned (requires HIBP_API_KEY)

Set GUARDIAN_BREACH_LIVE=1 as shorthand for auto when no provider is set.

Enrichment (XposedOrNot):
  GUARDIAN_BREACH_FAST=1   — check-email only (sparse dates/classes on hits)
  GUARDIAN_BREACH_RICH=1   — always use breach-analytics (slowest, most detail)
  default                  — check-email first, then analytics when exposed
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime
from email.utils import parsedate_to_datetime
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

IdentifierType = Literal["email", "phone", "username"]
CheckStatus = Literal["clean", "exposed", "invalid", "error"]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,20}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")

# Fictional personas for mock QA — realistic format, not real individuals.
MOCK_EMAIL_CLEAN = "marcus.hale47@gmail.com"
MOCK_EMAIL_BREACHED = "dana.porter1988@outlook.com"
MOCK_EMAIL_PASTE = "kevin.lawson.trading@gmail.com"
MOCK_EMAIL_LINKED = "rachel.mitchell.home@yahoo.com"

XON_API_BASE = os.environ.get("GUARDIAN_XON_API_BASE", "https://api.xposedornot.com")
HACKMYIP_API_BASE = os.environ.get("GUARDIAN_HACKMYIP_API_BASE", "https://hackmyip.com")
HIBP_API_BASE = os.environ.get("GUARDIAN_HIBP_API_BASE", "https://haveibeenpwned.com/api/v3")
HIBP_USER_AGENT = os.environ.get(
    "GUARDIAN_HIBP_USER_AGENT",
    "Guardian-Personal-Check/1.0 (security-dashboard; breach-lookup)",
)
BREACH_REQUEST_TIMEOUT = float(os.environ.get("GUARDIAN_BREACH_TIMEOUT", "8"))
BREACH_CACHE_SECS = int(os.environ.get("GUARDIAN_BREACH_CACHE_SECS", "600"))
BREACH_USER_AGENT = "Guardian-Personal-Check/1.0"

# Recent lookup cache — AES-256-GCM sealed blobs keyed by identifier hash
_breach_cache: dict[str, tuple[float, str]] = {}  # key -> (stored_at, sealed_json)
_breach_cache_lock = threading.Lock()

# Daily API call counters (in-memory; resets at UTC midnight)
_usage_lock = threading.Lock()
_usage_day: str = ""
_usage_counts: dict[str, int] = {}


@dataclass
class BreachIncident:
    name: str
    breach_date: str
    added_date: str
    data_classes: list[str]
    description: str
    pwn_count: int = 0
    is_verified: bool = True
    domain: str = ""
    source_provider: str = ""
    breach_date_precision: str = "unknown"  # day | year | unknown
    # Demo-only fields for UI testing — not available from real HIBP
    demo_ip: str = ""
    demo_location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PasteExposure:
    source: str
    paste_id: str
    title: str
    exposed_date: str
    email_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LinkedAccount:
    service: str
    username: str
    linked_via: str
    first_seen: str
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BreachCheckResult:
    status: CheckStatus
    identifier_type: IdentifierType
    identifier_masked: str
    identifier_hash: str
    breach_count: int = 0
    paste_count: int = 0
    linked_account_count: int = 0
    breaches: list[BreachIncident] = field(default_factory=list)
    pastes: list[PasteExposure] = field(default_factory=list)
    linked_accounts: list[LinkedAccount] = field(default_factory=list)
    timeline: list[dict[str, str]] = field(default_factory=list)
    plain_summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    checked_at: float = 0.0
    provider: str = "mock"
    scenario_id: str = ""
    notes: list[str] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)
    risk_level: str = "low"  # low | medium | high
    risk_summary: str = ""
    data_classes_summary: list[str] = field(default_factory=list)
    from_cache: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "identifier_type": self.identifier_type,
            "identifier_masked": self.identifier_masked,
            "identifier_hash": self.identifier_hash,
            "breach_count": self.breach_count,
            "paste_count": self.paste_count,
            "linked_account_count": self.linked_account_count,
            "breaches": [
                {**b.to_dict(), "severity": _breach_card_severity(b)} for b in self.breaches
            ],
            "pastes": [p.to_dict() for p in self.pastes],
            "linked_accounts": [a.to_dict() for a in self.linked_accounts],
            "timeline": self.timeline,
            "plain_summary": self.plain_summary,
            "recommendations": self.recommendations,
            "checked_at": self.checked_at,
            "provider": self.provider,
            "scenario_id": self.scenario_id,
            "notes": self.notes,
            "sources_checked": self.sources_checked,
            "risk_level": self.risk_level,
            "risk_summary": self.risk_summary,
            "data_classes_summary": self.data_classes_summary,
            "from_cache": self.from_cache,
        }


@dataclass
class PasswordCheckResult:
    status: Literal["safe", "pwned", "invalid", "error"]
    count: int = 0
    plain_summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    checked_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Mock scenario catalog (for QA / demos) ───────────────────────────────────

MOCK_SCENARIOS: list[dict[str, str]] = [
    {
        "id": "clean_email",
        "type": "email",
        "sample": MOCK_EMAIL_CLEAN,
        "expected": "clean",
        "description": "No known breaches — green 'all clear' path",
    },
    {
        "id": "multi_breach_email",
        "type": "email",
        "sample": MOCK_EMAIL_BREACHED,
        "expected": "exposed",
        "description": "Multiple breaches with timeline and data classes",
    },
    {
        "id": "paste_only_email",
        "type": "email",
        "sample": MOCK_EMAIL_PASTE,
        "expected": "exposed",
        "description": "Public paste exposure without formal breach record",
    },
    {
        "id": "linked_accounts_email",
        "type": "email",
        "sample": MOCK_EMAIL_LINKED,
        "expected": "exposed",
        "description": "Same email reused across multiple services",
    },
    {
        "id": "breached_phone",
        "type": "phone",
        "sample": "+15559876543",
        "expected": "exposed",
        "description": "Phone number found in telecom/marketing leak",
    },
    {
        "id": "clean_phone",
        "type": "phone",
        "sample": "+15550001111",
        "expected": "clean",
        "description": "Phone not in mock breach database",
    },
    {
        "id": "breached_username",
        "type": "username",
        "sample": "leaked_user",
        "expected": "exposed",
        "description": "Username tied to gaming/social breaches",
    },
    {
        "id": "clean_username",
        "type": "username",
        "sample": "safe_handle_99",
        "expected": "clean",
        "description": "Username not found in mock data",
    },
    {
        "id": "invalid_email",
        "type": "email",
        "sample": "not-an-email",
        "expected": "invalid",
        "description": "Validation error — malformed email",
    },
]


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text).replace("&nbsp;", " ").strip()


def _today_utc() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _quota_limit(provider: str) -> int | None:
    if provider in ("xposedornot", "multi"):
        if provider == "multi":
            return int(os.environ.get("GUARDIAN_MULTI_DAILY_LIMIT", os.environ.get("GUARDIAN_XON_DAILY_LIMIT", "100")))
        return int(os.environ.get("GUARDIAN_XON_DAILY_LIMIT", "100"))
    if provider == "hibp":
        raw = os.environ.get("GUARDIAN_HIBP_DAILY_LIMIT", "").strip()
        if raw:
            return int(raw)
        return None
    return None


def _reset_usage_if_needed() -> None:
    global _usage_day
    today = _today_utc()
    if _usage_day != today:
        _usage_day = today
        _usage_counts.clear()


def _record_api_call(provider: str, count: int = 1) -> None:
    if provider not in ("xposedornot", "hibp", "multi"):
        return
    with _usage_lock:
        _reset_usage_if_needed()
        _usage_counts[provider] = _usage_counts.get(provider, 0) + count


def quota_status(provider: str | None = None) -> dict[str, Any]:
    """Return daily usage for a live provider."""
    provider = provider or _provider_name()
    with _usage_lock:
        _reset_usage_if_needed()
        used = _usage_counts.get(provider, 0)
    limit = _quota_limit(provider)
    if limit is None:
        return {
            "provider": provider,
            "used": used,
            "limit": None,
            "remaining": None,
            "tracked": provider in ("xposedornot", "hibp", "multi"),
            "resets_utc": f"{_today_utc()} 00:00 UTC",
        }
    return {
        "provider": provider,
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
        "tracked": True,
        "resets_utc": f"{_today_utc()} 00:00 UTC",
    }


def _quota_exceeded(provider: str) -> bool:
    q = quota_status(provider)
    remaining = q.get("remaining")
    return remaining is not None and remaining <= 0


def _hibp_api_key() -> str:
    return os.environ.get("HIBP_API_KEY", "").strip()


def _is_hibp_test_key(key: str) -> bool:
    return key == "00000000000000000000000000000000"


def _hash_identifier(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:16]


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def mask_username(username: str) -> str:
    if len(username) <= 3:
        return username[0] + "**"
    return username[:2] + "*" * (len(username) - 3) + username[-1]


def validate_identifier(identifier_type: IdentifierType, value: str) -> str | None:
    v = (value or "").strip()
    if not v:
        return "Please enter a value to check."
    if identifier_type == "email":
        if not _EMAIL_RE.match(v):
            return "That doesn't look like a valid email address."
    elif identifier_type == "phone":
        if not _PHONE_RE.match(v):
            return "Enter a phone number with at least 7 digits (e.g. +1 555 123 4567)."
    elif identifier_type == "username":
        if not _USERNAME_RE.match(v):
            return "Username must be 3–32 characters (letters, numbers, _, ., -)."
    return None


def _timeline_sort_key(date: str) -> tuple[int, str]:
    d = (date or "").strip().lower()
    if not d or d == "unknown":
        return (0, "")
    return (1, d)


def _format_timeline_date(date: str, *, precision: str = "unknown") -> str:
    d = (date or "").strip()
    if not d or d.lower() == "unknown":
        return "Date unknown"
    if precision == "year" or re.fullmatch(r"\d{4}", d):
        year = d[:4] if len(d) >= 4 else d
        return f"{year} (year only)"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
        try:
            dt = datetime.strptime(d, "%Y-%m-%d")
            return dt.strftime("%d %b %Y")
        except ValueError:
            return d
    return d


def _build_timeline(breaches: list[BreachIncident], pastes: list[PasteExposure]) -> list[dict[str, str]]:
    events: list[tuple[str, str, str, str]] = []
    for b in breaches:
        classes = b.data_classes[:4]
        if classes:
            detail = ", ".join(classes)
            if len(b.data_classes) > 4:
                detail += f" (+{len(b.data_classes) - 4} more)"
            label = f"{b.name} — {detail}"
        else:
            label = b.name
        events.append(
            (
                b.breach_date,
                "breach",
                label,
                _format_timeline_date(b.breach_date, precision=b.breach_date_precision),
            )
        )
    for p in pastes:
        events.append(
            (p.exposed_date, "paste", f"{p.source}: {p.title}", _format_timeline_date(p.exposed_date))
        )
    events.sort(key=lambda x: _timeline_sort_key(x[0]), reverse=True)
    return [{"date": disp, "kind": k, "label": lbl} for _, k, lbl, disp in events]


def _recommendations(status: CheckStatus, breaches: list[BreachIncident], *, live: bool = False) -> list[str]:
    if status == "clean":
        if live:
            return [
                "No known public breaches for this identifier in the checked database.",
                "Keep using unique passwords and enable two-factor authentication.",
                "Add this email to your watchlist — we'll re-check automatically and alert you if anything changes.",
            ]
        return [
            "No known public breaches for this identifier in our test database.",
            "Keep using unique passwords and enable two-factor authentication.",
            "Add this email to your watchlist to simulate ongoing monitoring.",
        ]
    recs = [
        "Change passwords on any account that used this identifier.",
        "Enable two-factor authentication wherever possible.",
        "Watch for phishing emails referencing the breached services.",
    ]
    if any("Password" in c or "password" in c.lower() for b in breaches for c in b.data_classes):
        recs.insert(0, "Passwords were exposed — assume this password is compromised everywhere it was reused.")
    if any("Phone" in c for b in breaches for c in b.data_classes):
        recs.append("Phone numbers were exposed — expect more spam calls and SMS phishing.")
    return recs


def _aggregate_data_classes(breaches: list[BreachIncident]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for breach in breaches:
        for dc in breach.data_classes:
            if dc not in seen:
                seen.add(dc)
                out.append(dc)
    return out


def _compute_risk(
    status: CheckStatus,
    breaches: list[BreachIncident],
    pastes: list[PasteExposure],
) -> tuple[str, str]:
    if status == "clean":
        return "low", "No known public exposure in the databases we checked."
    if status == "invalid":
        return "low", ""
    score = 0
    classes = _aggregate_data_classes(breaches)
    if any("password" in c.lower() for c in classes):
        score += 4
    if pastes:
        score += 2
    if len(breaches) >= 3:
        score += 2
    elif breaches:
        score += 1
    if score >= 5:
        return "high", "Serious exposure — passwords or multiple breaches found. Take action today."
    if score >= 2:
        return "medium", "Some personal data may be public — update passwords and turn on 2FA."
    return "low", "Limited exposure reported — review the timeline and follow the steps below."


def _breach_card_severity(breach: BreachIncident) -> str:
    classes = " ".join(breach.data_classes).lower()
    if "password" in classes:
        return "high"
    if breach.pwn_count > 10_000_000:
        return "medium"
    return "low"


def _finalize_result(result: BreachCheckResult) -> BreachCheckResult:
    risk_level, risk_summary = _compute_risk(result.status, result.breaches, result.pastes)
    result.risk_level = risk_level
    result.risk_summary = risk_summary
    result.data_classes_summary = _aggregate_data_classes(result.breaches)
    if result.status in ("clean", "exposed") and not result.recommendations:
        result.recommendations = _recommendations(
            result.status, result.breaches, live=result.provider != "mock"
        )
    return result


def _mock_lookup_email(email: str) -> BreachCheckResult:
    key = email.strip().lower()
    masked = mask_email(key)
    h = _hash_identifier(key)
    now = time.time()

    if key == MOCK_EMAIL_CLEAN:
        return BreachCheckResult(
            status="clean",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="Good news — we found no public breach records for this email in our test database.",
            recommendations=_recommendations("clean", []),
            checked_at=now,
            scenario_id="clean_email",
            notes=["Mock mode — swap to HIBP API key for production."],
        )

    if key == MOCK_EMAIL_BREACHED:
        breaches = [
            BreachIncident(
                name="LinkedIn",
                breach_date="2012-05-05",
                added_date="2016-08-18",
                data_classes=["Email addresses", "Passwords", "Names"],
                description="Professional network breach affecting millions of accounts.",
                pwn_count=164_611_595,
                domain="linkedin.com",
                demo_ip="203.0.113.45",
                demo_location="San Francisco, US (demo)",
            ),
            BreachIncident(
                name="Adobe",
                breach_date="2013-10-04",
                added_date="2013-12-04",
                data_classes=["Email addresses", "Password hints", "Passwords", "Usernames"],
                description="Creative software vendor breach with encrypted passwords.",
                pwn_count=152_445_165,
                domain="adobe.com",
                demo_ip="198.51.100.22",
                demo_location="London, UK (demo)",
            ),
            BreachIncident(
                name="Collection #1",
                breach_date="2019-01-07",
                added_date="2019-01-16",
                data_classes=["Email addresses", "Passwords"],
                description="Large combo-list aggregation of many prior breaches.",
                pwn_count=772_904_991,
                domain="",
            ),
        ]
        timeline = _build_timeline(breaches, [])
        return BreachCheckResult(
            status="exposed",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            breach_count=len(breaches),
            breaches=breaches,
            timeline=timeline,
            plain_summary=(
                f"This email appears in {len(breaches)} known public breaches. "
                "Passwords and personal details may be circulating."
            ),
            recommendations=_recommendations("exposed", breaches),
            checked_at=now,
            scenario_id="multi_breach_email",
            notes=[
                "IP and location shown are demo placeholders for UI testing only.",
                "Real HIBP API does not return MAC addresses or victim IPs.",
            ],
        )

    if key == MOCK_EMAIL_PASTE:
        pastes = [
            PasteExposure(
                source="Pastebin",
                paste_id="abc123",
                title="combo_list_jan2024.txt",
                exposed_date="2024-01-15",
                email_count=1,
            ),
        ]
        timeline = _build_timeline([], pastes)
        return BreachCheckResult(
            status="exposed",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            paste_count=len(pastes),
            pastes=pastes,
            timeline=timeline,
            plain_summary="This email was found in a public paste — it may not be a formal breach but still risky.",
            recommendations=_recommendations("exposed", []),
            checked_at=now,
            scenario_id="paste_only_email",
            notes=["Paste hits are separate from breach catalog entries."],
        )

    if key == MOCK_EMAIL_LINKED:
        breaches = [
            BreachIncident(
                name="Canva",
                breach_date="2019-05-24",
                added_date="2019-08-05",
                data_classes=["Email addresses", "Names", "Passwords", "Usernames"],
                description="Design platform breach.",
                pwn_count=137_272_116,
                domain="canva.com",
            ),
        ]
        linked = [
            LinkedAccount(service="GitHub", username="rmitchell-dev", linked_via="email", first_seen="2018-03-01"),
            LinkedAccount(service="Spotify", username="rachel.m.home", linked_via="email", first_seen="2019-11-20"),
            LinkedAccount(service="Twitter/X", username="rachelmitchell", linked_via="email", first_seen="2020-06-15"),
        ]
        timeline = _build_timeline(breaches, [])
        return BreachCheckResult(
            status="exposed",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            breach_count=len(breaches),
            linked_account_count=len(linked),
            breaches=breaches,
            linked_accounts=linked,
            timeline=timeline,
            plain_summary=(
                f"This email is in {len(breaches)} breach(es) and linked to "
                f"{len(linked)} accounts in our mock correlation view."
            ),
            recommendations=_recommendations("exposed", breaches),
            checked_at=now,
            scenario_id="linked_accounts_email",
            notes=["Account linking is simulated — production may use breach domain correlation."],
        )

    # Default: treat unknown emails as clean in mock mode
    return BreachCheckResult(
        status="clean",
        identifier_type="email",
        identifier_masked=masked,
        identifier_hash=h,
        plain_summary=(
            f"No matches in mock database. Try {MOCK_EMAIL_BREACHED} or "
            f"{MOCK_EMAIL_CLEAN} for demo cases."
        ),
        recommendations=_recommendations("clean", []),
        checked_at=now,
        scenario_id="unknown_clean",
        notes=["Unknown emails default to clean in mock mode."],
    )


def _mock_lookup_phone(phone: str) -> BreachCheckResult:
    digits = re.sub(r"\D", "", phone)
    masked = mask_phone(phone)
    h = _hash_identifier(digits)
    now = time.time()

    if digits.endswith("9876543") or digits == "15559876543":
        breaches = [
            BreachIncident(
                name="Telecom Marketing Leak",
                breach_date="2022-08-12",
                added_date="2023-01-05",
                data_classes=["Phone numbers", "Names", "Locations"],
                description="Mock telecom marketing database exposure.",
                pwn_count=2_400_000,
                demo_location="Chicago, US (demo)",
            ),
        ]
        timeline = _build_timeline(breaches, [])
        return BreachCheckResult(
            status="exposed",
            identifier_type="phone",
            identifier_masked=masked,
            identifier_hash=h,
            breach_count=len(breaches),
            breaches=breaches,
            timeline=timeline,
            plain_summary="This phone number appears in a mock breach record.",
            recommendations=_recommendations("exposed", breaches),
            checked_at=now,
            scenario_id="breached_phone",
            notes=["Phone breach coverage is limited in real APIs; mock for UI testing."],
        )

    if digits.endswith("0001111") or digits == "15550001111":
        return BreachCheckResult(
            status="clean",
            identifier_type="phone",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="No mock breach records for this phone number.",
            recommendations=_recommendations("clean", []),
            checked_at=now,
            scenario_id="clean_phone",
        )

    return BreachCheckResult(
        status="clean",
        identifier_type="phone",
        identifier_masked=masked,
        identifier_hash=h,
        plain_summary="No matches. Try +15559876543 (exposed) or +15550001111 (clean).",
        recommendations=_recommendations("clean", []),
        checked_at=now,
        scenario_id="unknown_clean",
    )


def _mock_lookup_username(username: str) -> BreachCheckResult:
    key = username.strip().lower()
    masked = mask_username(username)
    h = _hash_identifier(key)
    now = time.time()

    if key == "leaked_user":
        breaches = [
            BreachIncident(
                name="Epic Games",
                breach_date="2018-12-01",
                added_date="2019-03-27",
                data_classes=["Email addresses", "Passwords", "Usernames"],
                description="Gaming platform credential exposure.",
                pwn_count=252_000_000,
                domain="epicgames.com",
            ),
            BreachIncident(
                name="MySpace",
                breach_date="2008-06-01",
                added_date="2016-05-31",
                data_classes=["Email addresses", "Passwords", "Usernames"],
                description="Legacy social network breach (old passwords).",
                pwn_count=360_000_000,
                domain="myspace.com",
            ),
        ]
        linked = [
            LinkedAccount(service="Epic Games", username="leaked_user", linked_via="username", first_seen="2017-04-01"),
            LinkedAccount(service="MySpace", username="leaked_user", linked_via="username", first_seen="2007-09-10"),
        ]
        timeline = _build_timeline(breaches, [])
        return BreachCheckResult(
            status="exposed",
            identifier_type="username",
            identifier_masked=masked,
            identifier_hash=h,
            breach_count=len(breaches),
            linked_account_count=len(linked),
            breaches=breaches,
            linked_accounts=linked,
            timeline=timeline,
            plain_summary=f"Username '{masked}' found in {len(breaches)} mock breaches.",
            recommendations=_recommendations("exposed", breaches),
            checked_at=now,
            scenario_id="breached_username",
        )

    if key == "safe_handle_99":
        return BreachCheckResult(
            status="clean",
            identifier_type="username",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="No mock breach records for this username.",
            recommendations=_recommendations("clean", []),
            checked_at=now,
            scenario_id="clean_username",
        )

    return BreachCheckResult(
        status="clean",
        identifier_type="username",
        identifier_masked=masked,
        identifier_hash=h,
        plain_summary="No matches. Try leaked_user (exposed) or safe_handle_99 (clean).",
        recommendations=_recommendations("clean", []),
        checked_at=now,
        scenario_id="unknown_clean",
    )


def check_breach(identifier_type: IdentifierType, value: str) -> BreachCheckResult:
    """Run breach lookup — mock provider by default."""
    err = validate_identifier(identifier_type, value)
    if err:
        return _finalize_result(BreachCheckResult(
            status="invalid",
            identifier_type=identifier_type,
            identifier_masked="",
            identifier_hash="",
            plain_summary=err,
            checked_at=time.time(),
            provider=_provider_name(),
        ))

    provider = _provider_name()
    cached = _breach_cache_get(provider, identifier_type, value)
    if cached is not None:
        return cached

    if provider == "hibp":
        result = _finalize_result(_hibp_lookup(identifier_type, value))
    elif provider == "multi":
        result = _finalize_result(_multi_lookup(identifier_type, value))
    elif provider == "xposedornot":
        result = _finalize_result(_xposedornot_lookup(identifier_type, value))
    elif identifier_type == "email":
        result = _finalize_result(_mock_lookup_email(value.strip().lower()))
    elif identifier_type == "phone":
        result = _finalize_result(_mock_lookup_phone(value))
    else:
        result = _finalize_result(_mock_lookup_username(value.strip()))

    if result.status in ("clean", "exposed"):
        _breach_cache_set(provider, identifier_type, value, result)
    return result


def _provider_name() -> str:
    explicit = os.environ.get("GUARDIAN_BREACH_PROVIDER", "").lower().strip()
    has_hibp = bool(_hibp_api_key())
    live_flag = os.environ.get("GUARDIAN_BREACH_LIVE", "").lower() in ("1", "true", "yes")

    if explicit == "mock":
        return "mock"
    if explicit in ("xposedornot", "xon", "free"):
        return "xposedornot"
    if explicit == "multi":
        return "multi"
    if explicit == "hibp":
        return "hibp"
    if explicit in ("auto", "live") or (not explicit and live_flag):
        allow_hibp = os.environ.get("GUARDIAN_ALLOW_HIBP", "").lower() in ("1", "true", "yes")
        if has_hibp and allow_hibp and explicit != "multi":
            return "hibp"
        return "multi"
    if not explicit:
        return "mock"
    return explicit


def provider_info() -> dict[str, Any]:
    """Metadata for dashboard banner / ops."""
    name = _provider_name()
    has_hibp = bool(_hibp_api_key())
    meta: dict[str, dict[str, Any]] = {
        "mock": {
            "label": "Mock (QA)",
            "live": False,
            "email": True,
            "phone": True,
            "username": True,
            "note": "Fictional scenarios for UI testing.",
            "sources": ["Demo dataset"],
        },
        "xposedornot": {
            "label": "XposedOrNot (free)",
            "live": True,
            "email": True,
            "phone": False,
            "username": True,
            "note": "Single free source — email and username.",
            "sources": ["XposedOrNot"],
        },
        "multi": {
            "label": "Guardian Free Stack",
            "live": True,
            "email": True,
            "phone": False,
            "username": True,
            "note": "XposedOrNot + HackMyIP — parallel free sources; no HIBP required.",
            "sources": ["XposedOrNot", "HackMyIP"],
        },
        "hibp": {
            "label": "Have I Been Pwned",
            "live": True,
            "email": True,
            "phone": False,
            "username": False,
            "note": "Production email + paste lookup via HIBP API.",
            "sources": ["Have I Been Pwned"],
        },
    }
    info = meta.get(name, {"label": name, "live": True, "email": True, "phone": False, "username": False, "sources": [name]})
    sources = list(info.get("sources") or [])
    exposed_demos = sum(1 for s in MOCK_SCENARIOS if s.get("expected") == "exposed")
    return {
        "provider": name,
        **info,
        "sources": sources,
        "source_count": len(sources),
        "demo_stats": {
            "scenarios": len(MOCK_SCENARIOS),
            "exposed_demos": exposed_demos,
        } if name == "mock" else None,
        "quota": quota_status(name),
        "hibp_configured": has_hibp,
        "hibp_active": name == "hibp",
        "available_providers": {
            "mock": True,
            "xposedornot": True,
            "multi": True,
            "hibp": has_hibp,
        },
        "upgrade_hint": (
            "Optional: set GUARDIAN_ALLOW_HIBP=1 + HIBP_API_KEY for HIBP lookups."
            if not os.environ.get("GUARDIAN_ALLOW_HIBP", "").lower() in ("1", "true", "yes")
            and has_hibp and name == "multi"
            else (
                "Optional: set HIBP_API_KEY + GUARDIAN_BREACH_PROVIDER=hibp for paid production lookups."
                if not has_hibp and name in ("xposedornot", "multi")
                else ""
            )
        ),
    }


def _http_get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    try:
        raw = _breach_http_get(url, headers=headers)
        return 200, json.loads(raw.decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(body) if body else None
        except json.JSONDecodeError:
            return exc.code, {"raw": body}
    except Exception as exc:
        return 0, {"error": str(exc)}


def _breach_http_get(url: str, headers: dict[str, str] | None = None) -> bytes:
    """Fast HTTP for breach APIs — short timeout, minimal SSL retries."""
    import ssl
    import urllib.request

    hdrs = {"User-Agent": BREACH_USER_AGENT, **(headers or {})}
    contexts: list[ssl.SSLContext] = []
    if os.environ.get("GUARDIAN_INSECURE_SSL", "").lower() in ("1", "true", "yes"):
        contexts.append(ssl._create_unverified_context())
    else:
        try:
            contexts.append(ssl.create_default_context())
        except ssl.SSLError:
            contexts.append(ssl._create_unverified_context())

    last_err: Exception | None = None
    for ctx in contexts:
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=BREACH_REQUEST_TIMEOUT, context=ctx) as resp:
                return resp.read()
        except Exception as e:
            last_err = e
    raise last_err or RuntimeError(f"GET failed: {url}")


def _breach_cache_key(provider: str, identifier_type: str, value: str) -> str:
    return f"v4:{provider}:{identifier_type}:{_hash_identifier(value)}"


def _result_from_dict(d: dict[str, Any]) -> BreachCheckResult:
    breaches = [BreachIncident(**{k: v for k, v in b.items() if k in BreachIncident.__dataclass_fields__}) for b in d.get("breaches", [])]
    pastes = [PasteExposure(**p) for p in d.get("pastes", [])]
    linked = [LinkedAccount(**a) for a in d.get("linked_accounts", [])]
    return BreachCheckResult(
        status=d["status"],
        identifier_type=d["identifier_type"],
        identifier_masked=d["identifier_masked"],
        identifier_hash=d["identifier_hash"],
        breach_count=d.get("breach_count", 0),
        paste_count=d.get("paste_count", 0),
        linked_account_count=d.get("linked_account_count", 0),
        breaches=breaches,
        pastes=pastes,
        linked_accounts=linked,
        timeline=list(d.get("timeline", [])),
        plain_summary=d.get("plain_summary", ""),
        recommendations=list(d.get("recommendations", [])),
        checked_at=d.get("checked_at", 0.0),
        provider=d.get("provider", "mock"),
        scenario_id=d.get("scenario_id", ""),
        notes=list(d.get("notes", [])),
        sources_checked=list(d.get("sources_checked", [])),
        risk_level=d.get("risk_level", "low"),
        risk_summary=d.get("risk_summary", ""),
        data_classes_summary=list(d.get("data_classes_summary", [])),
        from_cache=d.get("from_cache", False),
    )


def _breach_cache_get(
    provider: str, identifier_type: IdentifierType, value: str
) -> BreachCheckResult | None:
    key = _breach_cache_key(provider, identifier_type, value)
    now = time.time()
    with _breach_cache_lock:
        hit = _breach_cache.get(key)
        if not hit:
            return None
        stored_at, sealed = hit
        if now - stored_at > BREACH_CACHE_SECS:
            _breach_cache.pop(key, None)
            return None
    try:
        from guardian.security.vault import unseal_json

        d = unseal_json(sealed, aad=f"breach-cache:{key}")
        result = _result_from_dict(d)
    except Exception:
        with _breach_cache_lock:
            _breach_cache.pop(key, None)
        return None
    cached = BreachCheckResult(
        status=result.status,
        identifier_type=result.identifier_type,
        identifier_masked=result.identifier_masked,
        identifier_hash=result.identifier_hash,
        breach_count=result.breach_count,
        paste_count=result.paste_count,
        linked_account_count=result.linked_account_count,
        breaches=list(result.breaches),
        pastes=list(result.pastes),
        linked_accounts=list(result.linked_accounts),
        timeline=list(result.timeline),
        plain_summary=result.plain_summary,
        recommendations=list(result.recommendations),
        checked_at=result.checked_at,
        provider=result.provider,
        scenario_id=result.scenario_id,
        notes=[*result.notes, f"Cached result ({int(now - stored_at)}s ago)."],
        sources_checked=list(result.sources_checked),
        risk_level=result.risk_level,
        risk_summary=result.risk_summary,
        data_classes_summary=list(result.data_classes_summary),
        from_cache=True,
    )
    return cached


def _breach_cache_set(
    provider: str, identifier_type: IdentifierType, value: str, result: BreachCheckResult
) -> None:
    key = _breach_cache_key(provider, identifier_type, value)
    try:
        from guardian.security.vault import seal_json

        sealed = seal_json(result.to_dict(), aad=f"breach-cache:{key}")
    except Exception:
        return
    with _breach_cache_lock:
        _breach_cache[key] = (time.time(), sealed)
        if len(_breach_cache) > 500:
            oldest = min(_breach_cache.items(), key=lambda x: x[1][0])[0]
            _breach_cache.pop(oldest, None)


def _parse_xon_data_classes(raw: str | list[Any]) -> list[str]:
    if isinstance(raw, list):
        return [str(p).strip() for p in raw if str(p).strip()]
    if not raw:
        return []
    parts = re.split(r"[;,]", str(raw))
    return [p.strip() for p in parts if p.strip()]


def _parse_breach_date(raw: Any) -> tuple[str, str]:
    """Normalize a provider date to (iso_date, precision). precision: day | year | unknown."""
    if raw is None:
        return "unknown", "unknown"
    text = str(raw).strip()
    if not text or text.lower() == "unknown":
        return "unknown", "unknown"
    if re.fullmatch(r"\d{4}", text):
        return f"{text}-01-01", "year"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text, "day"
    if "T" in text:
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return dt.date().isoformat(), "day"
        except ValueError:
            pass
    try:
        dt = parsedate_to_datetime(text)
        return dt.date().isoformat(), "day"
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    return text, "unknown"


_xon_catalog_cache: dict[str, dict[str, Any] | None] = {}
_xon_catalog_index: dict[str, dict[str, Any]] | None = None
_xon_catalog_index_loaded_at: float = 0.0
_xon_catalog_index_failed_at: float = 0.0
_XON_CATALOG_INDEX_TTL = int(os.environ.get("GUARDIAN_XON_CATALOG_TTL", "86400"))
_XON_CATALOG_RETRY_SECS = 120
_xon_catalog_lock = threading.Lock()


def _xon_load_catalog_index(*, force: bool = False) -> dict[str, dict[str, Any]]:
    """Load all known breaches once (single API call) and index by normalized breach ID."""
    global _xon_catalog_index, _xon_catalog_index_loaded_at, _xon_catalog_index_failed_at
    now = time.time()
    with _xon_catalog_lock:
        if (
            not force
            and _xon_catalog_index is not None
            and _xon_catalog_index
            and now - _xon_catalog_index_loaded_at < _XON_CATALOG_INDEX_TTL
        ):
            return _xon_catalog_index
        if (
            not force
            and _xon_catalog_index_failed_at
            and now - _xon_catalog_index_failed_at < _XON_CATALOG_RETRY_SECS
        ):
            return _xon_catalog_index or {}

    status, data = _http_get_json(f"{XON_API_BASE}/v1/breaches")
    index: dict[str, dict[str, Any]] = {}
    if status == 200 and isinstance(data, dict):
        for item in data.get("exposedBreaches") or []:
            if not isinstance(item, dict):
                continue
            breach_id = str(item.get("breachID") or item.get("breach") or "")
            key = _normalize_breach_name(breach_id)
            if key:
                index[key] = item

    with _xon_catalog_lock:
        if index:
            _xon_catalog_index = index
            _xon_catalog_index_loaded_at = now
            _xon_catalog_index_failed_at = 0.0
            _xon_catalog_cache.clear()
            return index
        _xon_catalog_index_failed_at = now
        return _xon_catalog_index or {}


def _xon_fetch_breach_catalog(breach_name: str) -> dict[str, Any] | None:
    cache_key = _normalize_breach_name(breach_name)
    if not cache_key:
        return None
    with _xon_catalog_lock:
        if cache_key in _xon_catalog_cache:
            return _xon_catalog_cache[cache_key]
    entry = _xon_load_catalog_index().get(cache_key)
    if entry is None:
        q = urllib.parse.quote(breach_name, safe="")
        status, data = _http_get_json(f"{XON_API_BASE}/v1/breaches?breach_id={q}")
        if status == 200 and isinstance(data, dict):
            for item in data.get("exposedBreaches") or []:
                if not isinstance(item, dict):
                    continue
                if _normalize_breach_name(str(item.get("breachID") or "")) == cache_key:
                    entry = item
                    break
    with _xon_catalog_lock:
        _xon_catalog_cache[cache_key] = entry
    return entry


def _xon_catalog_fields(entry: dict[str, Any]) -> dict[str, Any]:
    breach_date, precision = _parse_breach_date(entry.get("breachedDate"))
    added_date, _ = _parse_breach_date(entry.get("addedDate"))
    records = entry.get("exposedRecords") or 0
    try:
        pwn_count = int(records)
    except (TypeError, ValueError):
        pwn_count = 0
    return {
        "breach_date": breach_date,
        "breach_date_precision": precision,
        "added_date": added_date,
        "data_classes": _parse_xon_data_classes(entry.get("exposedData") or []),
        "description": str(entry.get("exposureDescription") or ""),
        "pwn_count": pwn_count,
        "domain": str(entry.get("domain") or ""),
        "is_verified": bool(entry.get("verified", True)),
    }


def _prefer_date(existing: str, existing_precision: str, new: str, new_precision: str) -> tuple[str, str]:
    rank = {"unknown": 0, "year": 1, "day": 2}
    if rank.get(new_precision, 0) > rank.get(existing_precision, 0):
        return new, new_precision
    if existing and existing != "unknown":
        return existing, existing_precision
    return new, new_precision


def _xon_enrich_breach(incident: BreachIncident) -> BreachIncident:
    if os.environ.get("GUARDIAN_BREACH_NO_CATALOG", "").lower() in ("1", "true", "yes"):
        return incident
    if (
        incident.breach_date_precision == "day"
        and incident.data_classes
        and incident.pwn_count > 0
        and not incident.description.startswith("Listed in")
    ):
        return incident
    catalog = _xon_fetch_breach_catalog(incident.name)
    if not catalog:
        return incident
    info = _xon_catalog_fields(catalog)
    breach_date, precision = _prefer_date(
        incident.breach_date,
        incident.breach_date_precision,
        info["breach_date"],
        info["breach_date_precision"],
    )
    added_date = info["added_date"] if info["added_date"] != "unknown" else incident.added_date
    data_classes = info["data_classes"] or incident.data_classes
    description = info["description"] or incident.description
    pwn_count = info["pwn_count"] or incident.pwn_count
    domain = info["domain"] or incident.domain
    return BreachIncident(
        name=incident.name,
        breach_date=breach_date,
        added_date=added_date,
        data_classes=data_classes,
        description=description,
        pwn_count=pwn_count,
        is_verified=info["is_verified"] if info["is_verified"] is not None else incident.is_verified,
        domain=domain,
        source_provider=incident.source_provider or "XposedOrNot",
        breach_date_precision=precision,
        demo_ip=incident.demo_ip,
        demo_location=incident.demo_location,
    )


def _xon_enrich_breaches(breaches: list[BreachIncident]) -> list[BreachIncident]:
    return [_xon_enrich_breach(b) for b in breaches]


def _xon_breach_from_detail(item: dict[str, Any]) -> BreachIncident:
    name = str(item.get("breach") or item.get("name") or "Unknown")
    raw_date = item.get("xposed_date") or item.get("breach_date") or item.get("breachedDate") or ""
    breach_date, precision = _parse_breach_date(raw_date)
    records = item.get("xposed_records") or item.get("pwn_count") or item.get("exposedRecords") or 0
    try:
        pwn_count = int(records)
    except (TypeError, ValueError):
        pwn_count = 0
    return BreachIncident(
        name=name,
        breach_date=breach_date,
        added_date=breach_date,
        data_classes=_parse_xon_data_classes(item.get("xposed_data") or item.get("exposedData") or ""),
        description=str(item.get("details") or item.get("exposureDescription") or f"Data breach involving {name}."),
        pwn_count=pwn_count,
        is_verified=str(item.get("verified", "Yes")).lower() in ("yes", "true", "1"),
        domain=str(item.get("domain") or ""),
        source_provider="XposedOrNot",
        breach_date_precision=precision,
    )


def _normalize_breach_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _breach_detail_score(breach: BreachIncident) -> int:
    score = 0
    if breach.breach_date and breach.breach_date != "unknown":
        score += 4
    if breach.data_classes:
        score += 2 + min(len(breach.data_classes), 5)
    if breach.pwn_count > 0:
        score += 2
    if breach.domain:
        score += 1
    if breach.description and not breach.description.startswith("Listed in"):
        score += 1
    return score


def _merge_breach_lists(lists: list[list[BreachIncident]]) -> list[BreachIncident]:
    best: dict[str, BreachIncident] = {}
    order: list[str] = []
    for blist in lists:
        for breach in blist:
            key = _normalize_breach_name(breach.name)
            if not key:
                continue
            if key not in best:
                best[key] = breach
                order.append(key)
            elif _breach_detail_score(breach) > _breach_detail_score(best[key]):
                best[key] = breach
    return [best[k] for k in order]


def _xon_names_from_check_email(data: dict[str, Any]) -> list[str]:
    raw_names = data.get("breaches")
    names: list[str] = []
    if isinstance(raw_names, list):
        for entry in raw_names:
            if isinstance(entry, list):
                names.extend(str(n) for n in entry)
            elif isinstance(entry, str):
                names.append(entry)
    return names


def _query_xon_analytics(email: str) -> dict[str, Any]:
    """Full XposedOrNot analytics (slower, richer paste + data-class detail)."""
    key = email.strip().lower()
    q = urllib.parse.quote(key, safe="")
    status, data = _http_get_json(f"{XON_API_BASE}/v1/breach-analytics?email={q}")
    if status == 429:
        return {"ok": False, "error": "rate_limit", "breaches": [], "pastes": [], "exposed": False}
    if status == 0 or not isinstance(data, dict):
        msg = data.get("error", "Could not reach XposedOrNot") if isinstance(data, dict) else "Network error"
        return {"ok": False, "error": msg, "breaches": [], "pastes": [], "exposed": False}

    exposed_block = data.get("ExposedBreaches") or {}
    details = exposed_block.get("breaches_details") if isinstance(exposed_block, dict) else None
    breaches: list[BreachIncident] = []
    if isinstance(details, list):
        for item in details:
            if isinstance(item, dict):
                breaches.append(_xon_breach_from_detail(item))

    if not breaches:
        names = _xon_names_from_check_email(data)
        for name in names:
            breaches.append(
                BreachIncident(
                    name=name,
                    breach_date="unknown",
                    added_date="unknown",
                    data_classes=[],
                    description=f"Listed in XposedOrNot breach index as {name}.",
                    source_provider="XposedOrNot",
                )
            )

    pastes: list[PasteExposure] = []
    exposed_pastes = data.get("ExposedPastes")
    if isinstance(exposed_pastes, dict):
        paste_items = exposed_pastes.get("pastes_details") or exposed_pastes.get("details") or []
        if isinstance(paste_items, list):
            for p in paste_items:
                if not isinstance(p, dict):
                    continue
                pastes.append(
                    PasteExposure(
                        source=str(p.get("source") or p.get("site") or "Paste"),
                        paste_id=str(p.get("id") or p.get("paste_id") or ""),
                        title=str(p.get("title") or p.get("name") or "Public paste"),
                        exposed_date=str(p.get("date") or p.get("exposed_date") or "unknown"),
                        email_count=int(p.get("email_count") or 0),
                    )
                )
    paste_summary = data.get("PastesSummary") or {}
    if not pastes and isinstance(paste_summary, dict) and int(paste_summary.get("cnt") or 0) > 0:
        pastes.append(
            PasteExposure(
                source=str(paste_summary.get("domain") or "Paste"),
                paste_id="",
                title="Public paste exposure",
                exposed_date=str(paste_summary.get("tmpstmp") or "unknown"),
            )
        )

    has_signal = bool(breaches or pastes)
    if not has_signal and data.get("BreachMetrics") is None:
        return {"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}
    if not has_signal and str(data.get("Error") or "").lower() == "not found":
        return {"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}
    breaches = _xon_enrich_breaches(breaches)
    return {"ok": True, "breaches": breaches, "pastes": pastes, "exposed": has_signal, "error": None}


def _xon_stubs_from_names(names: list[str]) -> list[BreachIncident]:
    return [
        BreachIncident(
            name=name,
            breach_date="unknown",
            added_date="unknown",
            data_classes=[],
            description=f"Listed in XposedOrNot breach index as {name}.",
            source_provider="XposedOrNot",
        )
        for name in names
    ]


def _query_xon_raw(email: str) -> dict[str, Any]:
    """Query XposedOrNot — fast check-email; enrich with analytics on positive hits."""
    if os.environ.get("GUARDIAN_BREACH_RICH", "").lower() in ("1", "true", "yes"):
        return _query_xon_analytics(email)

    key = email.strip().lower()
    q = urllib.parse.quote(key, safe="")
    status, data = _http_get_json(
        f"{XON_API_BASE}/v1/check-email/{q}?include_details=true"
    )
    if status == 429:
        return {"ok": False, "error": "rate_limit", "breaches": [], "pastes": [], "exposed": False}
    if status == 0 or not isinstance(data, dict):
        msg = data.get("error", "Could not reach XposedOrNot") if isinstance(data, dict) else "Network error"
        return {"ok": False, "error": msg, "breaches": [], "pastes": [], "exposed": False}
    if status == 404:
        return {"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}

    names = _xon_names_from_check_email(data) if status == 200 else []
    if not names:
        if str(data.get("Error") or "").lower() == "not found":
            return {"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}", "breaches": [], "pastes": [], "exposed": False}
        return {"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}

    fast_only = os.environ.get("GUARDIAN_BREACH_FAST", "").lower() in ("1", "true", "yes")
    breaches = _xon_enrich_breaches(_xon_stubs_from_names(names))
    pastes: list[PasteExposure] = []

    if not fast_only:
        enriched = _query_xon_analytics(key)
        pastes = enriched.get("pastes") or []
        if enriched.get("ok") and enriched.get("breaches"):
            breaches = _merge_breach_lists([breaches, enriched["breaches"]])

    return {
        "ok": True,
        "breaches": breaches,
        "pastes": pastes,
        "exposed": True,
        "error": None,
    }


def _query_xon_username_raw(username: str) -> dict[str, Any]:
    """XposedOrNot free username breach check."""
    key = username.strip().lower()
    q = urllib.parse.quote(key, safe="")
    status, data = _http_get_json(f"{XON_API_BASE}/v1/check-username/{q}")
    if status == 429:
        return {"ok": False, "error": "rate_limit", "breaches": [], "exposed": False}
    if status == 0 or not isinstance(data, dict):
        msg = data.get("error", "Could not reach XposedOrNot") if isinstance(data, dict) else "Network error"
        return {"ok": False, "error": msg, "breaches": [], "exposed": False}
    if status == 404 or str(data.get("Error") or "").lower() == "not found":
        return {"ok": True, "breaches": [], "exposed": False, "error": None}
    names = data.get("breaches") or data.get("Breaches") or []
    if isinstance(names, dict):
        names = list(names.keys())
    if not isinstance(names, list):
        names = []
    breaches = [
        BreachIncident(
            name=str(name),
            breach_date="unknown",
            added_date="unknown",
            data_classes=[],
            description=f"Username found in {name} breach index (XposedOrNot).",
            source_provider="XposedOrNot",
        )
        for name in names
        if name
    ]
    exposed = bool(breaches) or bool(data.get("exposed"))
    return {"ok": True, "breaches": breaches, "exposed": exposed, "error": None}


def _query_hackmyip_raw(email: str) -> dict[str, Any]:
    """Query HackMyIP free breach API (no key)."""
    key = email.strip().lower()
    q = urllib.parse.quote(key, safe="")
    status, data = _http_get_json(f"{HACKMYIP_API_BASE}/api/breach?email={q}")
    if status == 0 or not isinstance(data, dict):
        msg = data.get("error", "Could not reach HackMyIP") if isinstance(data, dict) else "Network error"
        return {"ok": False, "error": msg, "breaches": [], "exposed": False}
    if not data.get("success"):
        return {"ok": False, "error": str(data.get("error", "HackMyIP lookup failed")), "breaches": [], "exposed": False}

    payload = data.get("data") if isinstance(data.get("data"), dict) else {}
    breaches: list[BreachIncident] = []
    for svc in payload.get("services") or []:
        name = str(svc)
        breaches.append(
            BreachIncident(
                name=name,
                breach_date="unknown",
                added_date="unknown",
                data_classes=[],
                description=f"Listed in HackMyIP breach index as {name}.",
                source_provider="HackMyIP",
            )
        )
    count = int(payload.get("breaches") or 0)
    exposed = count > 0 or bool(breaches)
    breaches = _xon_enrich_breaches(breaches)
    return {"ok": True, "breaches": breaches, "pastes": [], "exposed": exposed, "error": None}


def _build_email_result(
    *,
    email: str,
    status: CheckStatus,
    breaches: list[BreachIncident],
    pastes: list[PasteExposure],
    plain_summary: str,
    provider: str,
    notes: list[str],
    sources_checked: list[str] | None = None,
) -> BreachCheckResult:
    key = email.strip().lower()
    timeline = _build_timeline(breaches, pastes)
    return BreachCheckResult(
        status=status,
        identifier_type="email",
        identifier_masked=mask_email(key),
        identifier_hash=_hash_identifier(key),
        breach_count=len(breaches),
        paste_count=len(pastes),
        breaches=breaches,
        pastes=pastes,
        timeline=timeline,
        plain_summary=plain_summary,
        recommendations=_recommendations(status, breaches, live=True),
        checked_at=time.time(),
        provider=provider,
        notes=notes,
        sources_checked=sources_checked or [],
    )


def _multi_lookup_email(email: str) -> BreachCheckResult:
    key = email.strip().lower()
    masked = mask_email(key)
    h = _hash_identifier(key)
    now = time.time()

    if _quota_exceeded("multi"):
        q = quota_status("multi")
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=f"Daily limit reached ({q['used']}/{q['limit']} multi checks). Resets at UTC midnight.",
            checked_at=now,
            provider="multi",
            notes=["Free multi-source mode — XposedOrNot + HackMyIP."],
        )

    _record_api_call("multi")
    poll_secs = BREACH_REQUEST_TIMEOUT + 2
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        fut_xon = pool.submit(_query_xon_raw, key)
        fut_hmi = pool.submit(_query_hackmyip_raw, key)
        try:
            xon = fut_xon.result(timeout=poll_secs)
        except FuturesTimeoutError:
            xon = {"ok": False, "error": "timeout", "breaches": [], "pastes": [], "exposed": False}
        try:
            hmi = fut_hmi.result(timeout=poll_secs)
        except FuturesTimeoutError:
            hmi = {"ok": False, "error": "timeout", "breaches": [], "pastes": [], "exposed": False}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    sources_ok: list[str] = []
    sources_fail: list[str] = []
    if xon.get("ok"):
        sources_ok.append("XposedOrNot")
    else:
        sources_fail.append("XposedOrNot")
    if hmi.get("ok"):
        sources_ok.append("HackMyIP")
    else:
        sources_fail.append("HackMyIP")

    if not sources_ok:
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="All free breach sources unreachable. Try again later.",
            checked_at=now,
            provider="multi",
            notes=[f"Failed: {', '.join(sources_fail)}"],
        )

    breaches = _merge_breach_lists([xon.get("breaches") or [], hmi.get("breaches") or []])
    breaches = _xon_enrich_breaches(breaches)
    pastes = xon.get("pastes") or []
    exposed = bool(breaches or pastes) or bool(xon.get("exposed")) or bool(hmi.get("exposed"))

    notes = [
        "Free multi-source mode — exposed if any source reports a hit.",
        f"Checked: {', '.join(sources_ok)}.",
    ]
    if sources_fail:
        notes.append(f"Unavailable: {', '.join(sources_fail)}.")

    if not exposed:
        return _build_email_result(
            email=key,
            status="clean",
            breaches=[],
            pastes=[],
            plain_summary=(
                f"No breaches found in {len(sources_ok)} free database(s) "
                f"({', '.join(sources_ok)})."
            ),
            provider="multi",
            notes=notes,
            sources_checked=sources_ok,
        )

    xon_hit = bool(xon.get("exposed"))
    hmi_hit = bool(hmi.get("exposed"))
    if xon_hit and hmi_hit:
        agree = " Both sources report exposure."
    elif xon_hit != hmi_hit:
        agree = " Sources disagree — treating as at-risk."
    else:
        agree = ""

    parts = []
    if breaches:
        parts.append(f"{len(breaches)} breach(es)")
    if pastes:
        parts.append(f"{len(pastes)} paste(s)")
    summary = f"Found {' and '.join(parts) or 'exposure'} across {', '.join(sources_ok)}.{agree}"

    return _build_email_result(
        email=key,
        status="exposed",
        breaches=breaches,
        pastes=pastes,
        plain_summary=summary,
        provider="multi",
        notes=notes,
        sources_checked=sources_ok,
    )


def _multi_lookup(identifier_type: IdentifierType, value: str) -> BreachCheckResult:
    if identifier_type == "phone":
        return BreachCheckResult(
            status="invalid",
            identifier_type="phone",
            identifier_masked=mask_phone(value),
            identifier_hash=_hash_identifier(value),
            plain_summary="Phone checks are not available on the free stack yet.",
            checked_at=time.time(),
            provider="multi",
            notes=["Use mock mode for phone demos."],
        )
    if identifier_type == "username":
        return _xon_lookup_username(value.strip())
    return _multi_lookup_email(value.strip().lower())


def _xon_lookup_username(username: str) -> BreachCheckResult:
    key = username.strip().lower()
    masked = mask_username(username)
    h = _hash_identifier(key)
    now = time.time()
    if _quota_exceeded("multi"):
        q = quota_status("multi")
        return BreachCheckResult(
            status="error",
            identifier_type="username",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=f"Daily limit reached ({q['used']}/{q['limit']}).",
            checked_at=now,
            provider="multi",
        )
    _record_api_call("multi")
    raw = _query_xon_username_raw(key)
    if not raw.get("ok"):
        return BreachCheckResult(
            status="error",
            identifier_type="username",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=str(raw.get("error", "Username lookup failed")),
            checked_at=now,
            provider="multi",
            notes=["Source: XposedOrNot username API."],
        )
    breaches = raw.get("breaches") or []
    if not raw.get("exposed"):
        return BreachCheckResult(
            status="clean",
            identifier_type="username",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="No breaches found for username via XposedOrNot.",
            checked_at=now,
            provider="multi",
            sources_checked=["XposedOrNot"],
        )
    return BreachCheckResult(
        status="exposed",
        identifier_type="username",
        identifier_masked=masked,
        identifier_hash=h,
        breach_count=len(breaches),
        breaches=breaches,
        plain_summary=f"Username found in {len(breaches)} breach record(s) via XposedOrNot.",
        recommendations=_recommendations("exposed", breaches, live=True),
        checked_at=now,
        provider="multi",
        sources_checked=["XposedOrNot"],
    )


def _xon_lookup_email(email: str) -> BreachCheckResult:
    key = email.strip().lower()
    masked = mask_email(key)
    h = _hash_identifier(key)
    now = time.time()
    notes = ["Source: XposedOrNot free API — email lookup only."]

    if _quota_exceeded("xposedornot"):
        q = quota_status("xposedornot")
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=(
                f"Daily limit reached ({q['used']}/{q['limit']} checks). "
                "Resets at UTC midnight, or use GUARDIAN_BREACH_PROVIDER=multi."
            ),
            checked_at=now,
            provider="xposedornot",
            notes=notes,
        )

    _record_api_call("xposedornot")
    raw = _query_xon_raw(key)
    if not raw.get("ok"):
        if raw.get("error") == "rate_limit":
            msg = "Rate limit reached (XposedOrNot). Try again later."
        else:
            msg = f"Breach lookup failed: {raw.get('error', 'unknown error')}"
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=msg,
            checked_at=now,
            provider="xposedornot",
            notes=notes,
        )

    breaches = raw.get("breaches") or []
    pastes = raw.get("pastes") or []
    if not raw.get("exposed"):
        return _build_email_result(
            email=key,
            status="clean",
            breaches=[],
            pastes=[],
            plain_summary="Good news — no public breach records found for this email in XposedOrNot.",
            provider="xposedornot",
            notes=notes,
            sources_checked=["XposedOrNot"],
        )

    parts = []
    if breaches:
        parts.append(f"{len(breaches)} breach(es)")
    if pastes:
        parts.append(f"{len(pastes)} paste(s)")
    return _build_email_result(
        email=key,
        status="exposed",
        breaches=breaches,
        pastes=pastes,
        plain_summary=f"This email appears in {' and '.join(parts)} in XposedOrNot's database.",
        provider="xposedornot",
        notes=notes,
        sources_checked=["XposedOrNot"],
    )


def _xposedornot_lookup(identifier_type: IdentifierType, value: str) -> BreachCheckResult:
    if identifier_type != "email":
        masked = (
            mask_phone(value) if identifier_type == "phone" else mask_username(value.strip())
        )
        return BreachCheckResult(
            status="invalid",
            identifier_type=identifier_type,
            identifier_masked=masked,
            identifier_hash=_hash_identifier(value),
            plain_summary=(
                "XposedOrNot supports email lookup only. "
                "Use HIBP for paid email checks, or switch to mock mode for phone/username demos."
            ),
            checked_at=time.time(),
            provider="xposedornot",
            notes=["Phone and username checks are not available on the free tier."],
        )
    return _xon_lookup_email(value.strip().lower())


def _hibp_breach_from_api(item: dict[str, Any]) -> BreachIncident:
    data_classes = item.get("DataClasses") or []
    breach_date, precision = _parse_breach_date(item.get("BreachDate"))
    added_date, _ = _parse_breach_date(item.get("AddedDate"))
    if added_date == "unknown":
        added_date = breach_date
    if not isinstance(data_classes, list):
        data_classes = []
    desc = _strip_html(str(item.get("Description") or ""))
    return BreachIncident(
        name=str(item.get("Title") or item.get("Name") or "Unknown"),
        breach_date=breach_date,
        added_date=added_date,
        data_classes=[str(d) for d in data_classes],
        description=desc,
        pwn_count=int(item.get("PwnCount") or 0),
        is_verified=bool(item.get("IsVerified", True)),
        domain=str(item.get("Domain") or ""),
        source_provider="HIBP",
        breach_date_precision=precision,
    )


def _hibp_lookup_email(email: str, api_key: str) -> BreachCheckResult:
    key = email.strip().lower()
    masked = mask_email(key)
    h = _hash_identifier(key)
    now = time.time()
    notes = ["Source: Have I Been Pwned API."]
    if _is_hibp_test_key(api_key):
        notes.append("HIBP test key — only @hibp-integration-tests.com addresses return live data.")
        if not key.endswith("@hibp-integration-tests.com"):
            return BreachCheckResult(
                status="error",
                identifier_type="email",
                identifier_masked=masked,
                identifier_hash=h,
                plain_summary=(
                    "HIBP test key only works with @hibp-integration-tests.com addresses. "
                    "Use a paid key for real emails."
                ),
                checked_at=now,
                provider="hibp",
                notes=notes,
            )

    if _quota_exceeded("hibp"):
        q = quota_status("hibp")
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=f"Daily HIBP limit reached ({q['used']}/{q['limit']} checks). Resets at UTC midnight.",
            checked_at=now,
            provider="hibp",
            notes=notes,
        )

    headers = {"hibp-api-key": api_key, "User-Agent": HIBP_USER_AGENT}

    q = urllib.parse.quote(key, safe="")
    _record_api_call("hibp", 2)
    breach_status, breach_data = _http_get_json(
        f"{HIBP_API_BASE}/breachedaccount/{q}?truncateResponse=false", headers
    )
    paste_status, paste_data = _http_get_json(f"{HIBP_API_BASE}/pasteaccount/{q}", headers)

    breaches: list[BreachIncident] = []
    if breach_status == 200 and isinstance(breach_data, list):
        for item in breach_data:
            if isinstance(item, dict):
                breaches.append(_hibp_breach_from_api(item))
    elif breach_status not in (200, 404):
        if breach_status == 401:
            return BreachCheckResult(
                status="error",
                identifier_type="email",
                identifier_masked=masked,
                identifier_hash=h,
                plain_summary="HIBP API key rejected — check HIBP_API_KEY.",
                checked_at=now,
                provider="hibp",
                notes=notes,
            )
        if breach_status == 403:
            return BreachCheckResult(
                status="error",
                identifier_type="email",
                identifier_masked=masked,
                identifier_hash=h,
                plain_summary="HIBP rejected the request (403) — check User-Agent and API key permissions.",
                checked_at=now,
                provider="hibp",
                notes=notes,
            )
        if breach_status == 429:
            return BreachCheckResult(
                status="error",
                identifier_type="email",
                identifier_masked=masked,
                identifier_hash=h,
                plain_summary="HIBP rate limit reached — retry in a few seconds.",
                checked_at=now,
                provider="hibp",
                notes=notes,
            )
        err = breach_data.get("message", f"HTTP {breach_status}") if isinstance(breach_data, dict) else f"HTTP {breach_status}"
        return BreachCheckResult(
            status="error",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary=f"HIBP lookup failed: {err}",
            checked_at=now,
            provider="hibp",
            notes=notes,
        )

    pastes: list[PasteExposure] = []
    if paste_status == 200 and isinstance(paste_data, list):
        for p in paste_data:
            if not isinstance(p, dict):
                continue
            pastes.append(
                PasteExposure(
                    source=str(p.get("Source") or "Paste"),
                    paste_id=str(p.get("Id") or ""),
                    title=str(p.get("Title") or "Public paste"),
                    exposed_date=str(p.get("Date") or "unknown"),
                    email_count=int(p.get("EmailCount") or 0),
                )
            )

    if not breaches and not pastes:
        return BreachCheckResult(
            status="clean",
            identifier_type="email",
            identifier_masked=masked,
            identifier_hash=h,
            plain_summary="Good news — no public breach or paste records found for this email in HIBP.",
            recommendations=_recommendations("clean", [], live=True),
            checked_at=now,
            provider="hibp",
            notes=notes,
        )

    timeline = _build_timeline(breaches, pastes)
    parts = []
    if breaches:
        parts.append(f"{len(breaches)} breach(es)")
    if pastes:
        parts.append(f"{len(pastes)} paste(s)")
    return BreachCheckResult(
        status="exposed",
        identifier_type="email",
        identifier_masked=masked,
        identifier_hash=h,
        breach_count=len(breaches),
        paste_count=len(pastes),
        breaches=breaches,
        pastes=pastes,
        timeline=timeline,
        plain_summary=f"This email appears in {' and '.join(parts)} according to Have I Been Pwned.",
        recommendations=_recommendations("exposed", breaches, live=True),
        checked_at=now,
        provider="hibp",
        notes=notes,
    )


def _hibp_lookup(identifier_type: IdentifierType, value: str) -> BreachCheckResult:
    api_key = _hibp_api_key()
    if not api_key:
        if identifier_type == "email":
            result = _mock_lookup_email(value.strip().lower())
        elif identifier_type == "phone":
            result = _mock_lookup_phone(value)
        else:
            result = _mock_lookup_username(value.strip())
        result.provider = "hibp"
        result.notes.append("HIBP_API_KEY not set — showing mock data.")
        return result

    if identifier_type != "email":
        masked = mask_phone(value) if identifier_type == "phone" else mask_username(value.strip())
        return BreachCheckResult(
            status="invalid",
            identifier_type=identifier_type,
            identifier_masked=masked,
            identifier_hash=_hash_identifier(value),
            plain_summary="HIBP supports email breach lookup only.",
            checked_at=time.time(),
            provider="hibp",
            notes=["Use email type for live HIBP checks."],
        )
    return _hibp_lookup_email(value, api_key)


def list_scenarios() -> list[dict[str, str]]:
    return list(MOCK_SCENARIOS)


# ─── Pwned Passwords (HIBP k-anonymity — free, no API key) ─────────────────────

PWNED_PASSWORDS_API = os.environ.get(
    "GUARDIAN_PWNED_PASSWORDS_API", "https://api.pwnedpasswords.com/range/"
)
_MOCK_PWNED_PASSWORDS = frozenset({"password", "password123", "123456", "qwerty", "letmein"})


def check_pwned_password(password: str) -> PasswordCheckResult:
    """Check if a password appears in breach dumps (never sends full password)."""
    now = time.time()
    if not password:
        return PasswordCheckResult(
            status="invalid",
            plain_summary="Enter a password to check.",
            checked_at=now,
        )
    if len(password) > 256:
        return PasswordCheckResult(
            status="invalid",
            plain_summary="Password is too long to check.",
            checked_at=now,
        )

    if _provider_name() == "mock":
        if password.lower() in _MOCK_PWNED_PASSWORDS:
            return PasswordCheckResult(
                status="pwned",
                count=120_694,
                plain_summary="This password appears in known breach lists (mock demo). Do not use it.",
                recommendations=[
                    "Choose a unique password you have never used elsewhere.",
                    "Use a password manager to generate and store strong passwords.",
                    "Enable two-factor authentication on important accounts.",
                ],
                checked_at=now,
            )
        return PasswordCheckResult(
            status="safe",
            count=0,
            plain_summary="This password was not found in our mock breach list. Try 'password123' to see a hit.",
            recommendations=[
                "No match in this demo — in live mode we query Have I Been Pwned's Pwned Passwords API.",
                "Still use a long, unique password — absence from breach lists is not a guarantee.",
            ],
            checked_at=now,
        )

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    url = f"{PWNED_PASSWORDS_API}{prefix}"
    try:
        raw = _breach_http_get(url, headers={"Add-Padding": "true"}).decode(errors="replace")
    except Exception as e:
        return PasswordCheckResult(
            status="error",
            plain_summary=f"Could not reach Pwned Passwords API: {e}",
            checked_at=now,
        )

    count = 0
    for line in raw.splitlines():
        part, _, tally = line.partition(":")
        if part.strip() == suffix:
            count = int(tally.strip())
            break

    if count:
        return PasswordCheckResult(
            status="pwned",
            count=count,
            plain_summary=(
                f"This password has been seen {count:,} times in data breaches. "
                "Anyone could guess it — change it immediately."
            ),
            recommendations=[
                "Stop using this password everywhere immediately.",
                "Use a password manager to generate a unique replacement.",
                "Turn on two-factor authentication on email and banking.",
            ],
            checked_at=now,
        )
    return PasswordCheckResult(
        status="safe",
        count=0,
        plain_summary="Good news — this password was not found in known breach databases.",
        recommendations=[
            "Keep using unique passwords for every site.",
            "A password manager makes this much easier.",
        ],
        checked_at=now,
    )


def check_pwned_password_range(prefix: str, suffix: str) -> PasswordCheckResult:
    """Check Pwned Passwords by SHA-1 prefix + suffix only (k-anonymity — no full password)."""
    now = time.time()
    prefix = prefix.upper().strip()
    suffix = suffix.upper().strip()
    if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
        return PasswordCheckResult(
            status="invalid",
            plain_summary="Invalid hash prefix (need 5 hex characters).",
            checked_at=now,
        )
    if len(suffix) != 35 or not all(c in "0123456789ABCDEF" for c in suffix):
        return PasswordCheckResult(
            status="invalid",
            plain_summary="Invalid hash suffix (need 35 hex characters).",
            checked_at=now,
        )

    if _provider_name() == "mock":
        mock_suffixes = {
            "5BAA6": "1E4C9B793F3F0D68A277AE3FD59EA43CD140EB23",
        }
        if prefix == "5BAA6" and suffix == mock_suffixes["5BAA6"]:
            return PasswordCheckResult(
                status="pwned",
                count=120_694,
                plain_summary="This password appears in known breach lists (mock demo). Do not use it.",
                recommendations=[
                    "Choose a unique password you have never used elsewhere.",
                    "Use a password manager to generate and store strong passwords.",
                ],
                checked_at=now,
            )
        return PasswordCheckResult(
            status="safe",
            count=0,
            plain_summary="This password was not found in our mock breach list.",
            checked_at=now,
        )

    url = f"{PWNED_PASSWORDS_API}{prefix}"
    try:
        raw = _breach_http_get(url, headers={"Add-Padding": "true"}).decode(errors="replace")
    except Exception as e:
        return PasswordCheckResult(
            status="error",
            plain_summary=f"Could not reach Pwned Passwords API: {e}",
            checked_at=now,
        )

    count = 0
    for line in raw.splitlines():
        part, _, tally = line.partition(":")
        if part.strip() == suffix:
            count = int(tally.strip())
            break

    if count:
        return PasswordCheckResult(
            status="pwned",
            count=count,
            plain_summary=(
                f"This password has been seen {count:,} times in data breaches. "
                "Anyone could guess it — change it immediately."
            ),
            recommendations=[
                "Stop using this password everywhere immediately.",
                "Use a password manager to generate a unique replacement.",
                "Turn on two-factor authentication on email and banking.",
            ],
            checked_at=now,
        )
    return PasswordCheckResult(
        status="safe",
        count=0,
        plain_summary="Good news — this password was not found in known breach databases.",
        recommendations=[
            "Keep using unique passwords for every site.",
            "A password manager makes this much easier.",
        ],
        checked_at=now,
    )


# ─── Watchlist + monitoring alerts ─────────────────────────────────────────────

_watchlist: dict[str, dict[str, Any]] = {}
_watchlist_values: dict[str, str] = {}  # AES-256-GCM sealed values (base64url)
_watchlist_alerts: list[dict[str, Any]] = []
_watchlist_lock = threading.Lock()
_watchlist_scheduler_started = False


_WATCHLIST_ENC_PREFIX = "enc:v1:"
_WATCHLIST_FILE = "watchlist.v1.enc"
_watchlist_loaded = False


def _watchlist_persist() -> None:
    try:
        from guardian.security.vault import seal_file

        with _watchlist_lock:
            payload = {"entries": dict(_watchlist), "values": dict(_watchlist_values)}
        seal_file(_WATCHLIST_FILE, payload, aad="guardian-watchlist-v1")
    except Exception:
        pass


def _watchlist_load_once() -> None:
    global _watchlist_loaded
    if _watchlist_loaded:
        return
    _watchlist_loaded = True
    try:
        from guardian.security.vault import unseal_file

        data = unseal_file(_WATCHLIST_FILE, aad="guardian-watchlist-v1")
        if not data:
            return
        with _watchlist_lock:
            _watchlist.update(data.get("entries", {}))
            _watchlist_values.update(data.get("values", {}))
    except Exception:
        pass


def _watchlist_seal(value: str, entry_id: str) -> str:
    """Encrypt a watchlist identifier at rest (AES-256-GCM)."""
    try:
        from guardian.security.crypto import encrypt_text, has_crypto
        from guardian.security.keys import get_master_key

        if not has_crypto():
            return value.strip()
        token = encrypt_text(get_master_key(), value.strip(), aad=f"watchlist:{entry_id}")
        return _WATCHLIST_ENC_PREFIX + token
    except Exception:
        return value.strip()


def _watchlist_unseal(stored: str, entry_id: str) -> str:
    """Decrypt a sealed watchlist value; legacy plaintext entries pass through."""
    if not stored.startswith(_WATCHLIST_ENC_PREFIX):
        return stored
    token = stored[len(_WATCHLIST_ENC_PREFIX):]
    try:
        from guardian.security.crypto import decrypt_text, has_crypto
        from guardian.security.keys import get_master_key

        if not has_crypto():
            return stored
        return decrypt_text(get_master_key(), token, aad=f"watchlist:{entry_id}")
    except Exception:
        return stored


def _watchlist_apply_check(entry_id: str, entry: dict[str, Any], result: BreachCheckResult) -> None:
    entry["last_checked"] = time.time()
    entry["last_status"] = result.status
    entry["last_breach_count"] = result.breach_count
    entry["last_paste_count"] = result.paste_count
    entry["risk_level"] = result.risk_level


def _watchlist_maybe_alert(
    entry: dict[str, Any],
    *,
    prev_status: str,
    prev_breach_count: int,
    result: BreachCheckResult,
) -> None:
    changed = False
    message = ""
    if prev_status == "clean" and result.status == "exposed":
        changed = True
        message = f"New exposure detected for {entry['identifier_masked']}."
    elif result.breach_count > prev_breach_count:
        changed = True
        delta = result.breach_count - prev_breach_count
        message = (
            f"{entry['identifier_masked']}: breach count increased by {delta} "
            f"({prev_breach_count} → {result.breach_count})."
        )
    if not changed:
        return
    alert = {
        "id": f"alert-{int(time.time() * 1000)}-{entry['id'][:8]}",
        "entry_id": entry["id"],
        "identifier_masked": entry["identifier_masked"],
        "message": message,
        "status": result.status,
        "breach_count": result.breach_count,
        "risk_level": result.risk_level,
        "created_at": time.time(),
        "read": False,
    }
    with _watchlist_lock:
        _watchlist_alerts.insert(0, alert)
        _watchlist_alerts[:] = _watchlist_alerts[:50]


def watchlist_add(identifier_type: IdentifierType, value: str, label: str = "") -> dict[str, Any]:
    _watchlist_load_once()
    err = validate_identifier(identifier_type, value)
    if err:
        return {"error": err}
    key = f"{identifier_type}:{_hash_identifier(value)}"
    result = check_breach(identifier_type, value)
    entry = {
        "id": key,
        "identifier_type": identifier_type,
        "identifier_masked": (
            mask_email(value) if identifier_type == "email"
            else mask_phone(value) if identifier_type == "phone"
            else mask_username(value)
        ),
        "label": label or identifier_type,
        "added_at": time.time(),
        "last_status": result.status,
        "last_breach_count": result.breach_count,
        "last_paste_count": result.paste_count,
        "last_checked": time.time(),
        "risk_level": result.risk_level,
        "monitoring": True,
    }
    with _watchlist_lock:
        _watchlist[key] = entry
        _watchlist_values[key] = _watchlist_seal(value, key)
    _watchlist_persist()
    return {"ok": True, "entry": entry, "initial_check": result.to_dict()}


def watchlist_remove(entry_id: str) -> dict[str, Any]:
    _watchlist_load_once()
    removed = False
    with _watchlist_lock:
        if entry_id in _watchlist:
            del _watchlist[entry_id]
            _watchlist_values.pop(entry_id, None)
            removed = True
    if removed:
        _watchlist_persist()
        return {"ok": True}
    return {"error": "not found"}


def watchlist_list() -> list[dict[str, Any]]:
    _watchlist_load_once()
    with _watchlist_lock:
        return [dict(e) for e in _watchlist.values()]


def watchlist_recheck_all() -> dict[str, Any]:
    """Re-check all watchlist entries; emit alerts when status worsens."""
    _watchlist_load_once()
    with _watchlist_lock:
        snapshot = [
            (eid, dict(entry), _watchlist_unseal(_watchlist_values.get(eid, ""), eid))
            for eid, entry in _watchlist.items()
        ]

    alerts_new = 0
    checked = 0
    for entry_id, entry, value in snapshot:
        if not value:
            continue
        prev_status = entry.get("last_status", "unknown")
        prev_count = int(entry.get("last_breach_count") or 0)
        result = check_breach(entry["identifier_type"], value)  # type: ignore[arg-type]
        checked += 1
        with _watchlist_lock:
            stored = _watchlist.get(entry_id)
            if not stored:
                continue
            before_alerts = len(_watchlist_alerts)
            _watchlist_maybe_alert(
                stored,
                prev_status=prev_status,
                prev_breach_count=prev_count,
                result=result,
            )
            if len(_watchlist_alerts) > before_alerts:
                alerts_new += 1
            _watchlist_apply_check(entry_id, stored, result)

    return {
        "checked": checked,
        "alerts_new": alerts_new,
        "entries": watchlist_list(),
        "alerts": watchlist_alerts(unread_only=False),
    }


def watchlist_alerts(*, unread_only: bool = True) -> list[dict[str, Any]]:
    with _watchlist_lock:
        items = list(_watchlist_alerts)
    if unread_only:
        items = [a for a in items if not a.get("read")]
    return items


def watchlist_alerts_mark_read(alert_id: str | None = None) -> dict[str, Any]:
    with _watchlist_lock:
        if alert_id:
            for alert in _watchlist_alerts:
                if alert["id"] == alert_id:
                    alert["read"] = True
            return {"ok": True}
        for alert in _watchlist_alerts:
            alert["read"] = True
    return {"ok": True, "marked": "all"}


def start_watchlist_scheduler(interval_secs: int | None = None) -> None:
    """Background re-check for watchlist entries (default 1 hour, override via env)."""
    global _watchlist_scheduler_started
    if _watchlist_scheduler_started:
        return
    interval = interval_secs or int(os.environ.get("GUARDIAN_WATCHLIST_INTERVAL", "3600"))
    interval = max(60, interval)

    def _loop() -> None:
        while True:
            time.sleep(interval)
            try:
                summary = watchlist_recheck_all()
                if summary["alerts_new"]:
                    print(
                        f"[watchlist] {summary['alerts_new']} new alert(s) "
                        f"after re-checking {summary['checked']} entries"
                    )
            except Exception as e:
                print(f"[watchlist] scheduled recheck error: {e!r}")

    threading.Thread(target=_loop, name="watchlist-scheduler", daemon=True).start()
    _watchlist_scheduler_started = True
    print(f"[watchlist] monitoring scheduler started (every {interval}s)")


# Back-compat alias used by older scripts
def watchlist_check_all() -> list[dict[str, Any]]:
    summary = watchlist_recheck_all()
    return summary["entries"]
