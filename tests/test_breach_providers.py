"""Tests for live breach providers (XposedOrNot, HIBP)."""

import os
from unittest.mock import patch

from guardian.intel import breach_lookup as bl


class _Env:
    KEYS = (
        "GUARDIAN_BREACH_PROVIDER",
        "GUARDIAN_BREACH_LIVE",
        "HIBP_API_KEY",
        "GUARDIAN_XON_DAILY_LIMIT",
        "GUARDIAN_MULTI_DAILY_LIMIT",
        "GUARDIAN_HIBP_DAILY_LIMIT",
    )

    def __init__(self, **overrides: str):
        self._overrides = overrides
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        for key in self.KEYS:
            self._saved[key] = os.environ.get(key)
            os.environ.pop(key, None)
        for key, val in self._overrides.items():
            os.environ[key] = val
        return self

    def __exit__(self, *args):
        for key in self.KEYS:
            os.environ.pop(key, None)
        for key, val in self._saved.items():
            if val is not None:
                os.environ[key] = val


def test_provider_defaults_mock():
    with _Env():
        assert bl._provider_name() == "mock"
        assert bl.provider_info()["live"] is False


def test_provider_xposedornot_explicit():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        assert bl._provider_name() == "xposedornot"
        assert bl.provider_info()["live"] is True


def test_provider_live_flag():
    with _Env(GUARDIAN_BREACH_LIVE="1"):
        assert bl._provider_name() == "multi"


def test_auto_prefers_hibp_when_key_set():
    with _Env(GUARDIAN_BREACH_PROVIDER="auto", HIBP_API_KEY="test-key"):
        assert bl._provider_name() == "hibp"


def test_auto_falls_back_to_multi_without_key():
    with _Env(GUARDIAN_BREACH_PROVIDER="auto"):
        assert bl._provider_name() == "multi"


def test_quota_increments():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        with bl._usage_lock:
            bl._usage_counts.clear()
            bl._usage_day = bl._today_utc()
        bl._record_api_call("xposedornot")
        q = bl.quota_status("xposedornot")
        assert q["used"] == 1
        assert q["limit"] == 100
        assert q["remaining"] == q["limit"] - q["used"]


def test_quota_blocks_xon_when_exhausted():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot", GUARDIAN_XON_DAILY_LIMIT="1"):
        bl._usage_counts.clear()
        bl._usage_day = bl._today_utc()
        bl._record_api_call("xposedornot")
        r = bl.check_breach("email", "marcus.hale47@gmail.com")
        assert r.status == "error"
        assert "limit" in r.plain_summary.lower()


def test_hibp_test_key_rejects_real_email():
    with _Env(GUARDIAN_BREACH_PROVIDER="hibp", HIBP_API_KEY="00000000000000000000000000000000"):
        r = bl.check_breach("email", "marcus.hale47@gmail.com")
        assert r.status == "error"
        assert r.provider == "hibp"


def test_hibp_strips_html():
    item = {"Title": "Test", "Description": "<p>Hello <b>world</b></p>", "DataClasses": []}
    b = bl._hibp_breach_from_api(item)
    assert "<" not in b.description
    assert "Hello" in b.description


def test_multi_merges_sources():
    with _Env(GUARDIAN_BREACH_PROVIDER="multi"):
        def fake_xon(email):
            return {
                "ok": True,
                "breaches": [
                    bl.BreachIncident(
                        name="LinkedIn",
                        breach_date="2012-01-01",
                        added_date="2012-01-01",
                        data_classes=["Email addresses"],
                        description="From XON",
                        source_provider="XposedOrNot",
                    )
                ],
                "pastes": [],
                "exposed": True,
                "error": None,
            }

        def fake_hmi(email):
            return {
                "ok": True,
                "breaches": [
                    bl.BreachIncident(
                        name="Adobe",
                        breach_date="unknown",
                        added_date="unknown",
                        data_classes=[],
                        description="From HMI",
                        source_provider="HackMyIP",
                    )
                ],
                "pastes": [],
                "exposed": True,
                "error": None,
            }

        with patch.object(bl, "_query_xon_raw", side_effect=fake_xon), patch.object(
            bl, "_query_hackmyip_raw", side_effect=fake_hmi
        ):
            r = bl.check_breach("email", "dana.porter1988@outlook.com")
        assert r.provider == "multi"
        assert r.status == "exposed"
        assert r.breach_count == 2
        assert set(r.sources_checked) == {"XposedOrNot", "HackMyIP"}


def test_multi_clean_when_both_clean():
    with _Env(GUARDIAN_BREACH_PROVIDER="multi"):
        with patch.object(bl, "_query_xon_raw", return_value={"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}), patch.object(
            bl, "_query_hackmyip_raw", return_value={"ok": True, "breaches": [], "pastes": [], "exposed": False, "error": None}
        ):
            r = bl.check_breach("email", "marcus.hale47@gmail.com")
        assert r.status == "clean"
        assert "2 free database" in r.plain_summary


def test_multi_dedup_same_breach_name():
    with _Env(GUARDIAN_BREACH_PROVIDER="multi"):
        dup = bl.BreachIncident(
            name="LinkedIn",
            breach_date="2012-01-01",
            added_date="2012-01-01",
            data_classes=[],
            description="a",
            source_provider="XposedOrNot",
        )
        dup2 = bl.BreachIncident(
            name="linkedin",
            breach_date="unknown",
            added_date="unknown",
            data_classes=[],
            description="b",
            source_provider="HackMyIP",
        )
        with patch.object(bl, "_query_xon_raw", return_value={"ok": True, "breaches": [dup], "pastes": [], "exposed": True, "error": None}), patch.object(
            bl, "_query_hackmyip_raw", return_value={"ok": True, "breaches": [dup2], "pastes": [], "exposed": True, "error": None}
        ):
            r = bl.check_breach("email", "test@example.com")
        assert r.breach_count == 1


def test_xon_clean_response():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        def fake_http(url, headers=None):
            return 200, {
                "BreachMetrics": None,
                "BreachesSummary": {"site": ""},
                "ExposedBreaches": None,
                "ExposedPastes": None,
                "PastesSummary": {"cnt": 0},
            }

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "marcus.hale47@gmail.com")
        assert r.provider == "xposedornot"
        assert r.status == "clean"


def test_xon_exposed_response():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        def fake_http(url, headers=None):
            if "check-email" in url:
                return 200, {"breaches": [["LinkedIn"]]}
            return 404, {"Error": "Not found"}

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "dana.porter1988@outlook.com")
        assert r.status == "exposed"
        assert r.breach_count == 1
        assert r.breaches[0].name == "LinkedIn"


def test_xon_phone_not_supported():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        r = bl.check_breach("phone", "+15559876543")
        assert r.status == "invalid"
        assert "email lookup only" in r.plain_summary.lower()


def test_hibp_exposed_response():
    with _Env(GUARDIAN_BREACH_PROVIDER="hibp", HIBP_API_KEY="test-key"):
        def fake_http(url, headers=None):
            if "breachedaccount" in url:
                return 200, [
                    {
                        "Name": "Adobe",
                        "Title": "Adobe",
                        "Domain": "adobe.com",
                        "BreachDate": "2013-10-04",
                        "AddedDate": "2013-12-04",
                        "PwnCount": 152000000,
                        "Description": "Adobe breach",
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified": True,
                    }
                ]
            return 404, None

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "dana.porter1988@outlook.com")
        assert r.provider == "hibp"
        assert r.status == "exposed"
        assert r.breach_count == 1


def test_hibp_clean_404():
    with _Env(GUARDIAN_BREACH_PROVIDER="hibp", HIBP_API_KEY="test-key"):
        with patch.object(bl, "_http_get_json", return_value=(404, None)):
            r = bl.check_breach("email", "marcus.hale47@gmail.com")
        assert r.status == "clean"
        assert r.provider == "hibp"
