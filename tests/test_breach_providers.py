"""Tests for live breach providers (XposedOrNot, HIBP)."""

import os
from unittest.mock import patch

from guardian.intel import breach_lookup as bl


class _Env:
    KEYS = (
        "GUARDIAN_BREACH_PROVIDER",
        "GUARDIAN_BREACH_LIVE",
        "GUARDIAN_BREACH_FAST",
        "GUARDIAN_BREACH_NO_CATALOG",
        "GUARDIAN_ALLOW_HIBP",
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


def test_auto_prefers_hibp_when_key_set_and_allowed():
    with _Env(GUARDIAN_BREACH_PROVIDER="auto", HIBP_API_KEY="test-key", GUARDIAN_ALLOW_HIBP="1"):
        assert bl._provider_name() == "hibp"


def test_auto_ignores_hibp_without_allow_flag():
    with _Env(GUARDIAN_BREACH_PROVIDER="auto", HIBP_API_KEY="test-key"):
        assert bl._provider_name() == "multi"


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


def test_merge_prefers_richer_breach():
    sparse = bl.BreachIncident(
        name="LinkedIn",
        breach_date="unknown",
        added_date="unknown",
        data_classes=[],
        description="Listed in HackMyIP breach index as LinkedIn.",
        source_provider="HackMyIP",
    )
    rich = bl.BreachIncident(
        name="linkedin",
        breach_date="2012-05-05",
        added_date="2012-05-05",
        data_classes=["Email addresses", "Passwords"],
        description="LinkedIn breach with full detail.",
        pwn_count=164_611_595,
        domain="linkedin.com",
        source_provider="XposedOrNot",
    )
    merged = bl._merge_breach_lists([[sparse], [rich]])
    assert len(merged) == 1
    assert merged[0].pwn_count == 164_611_595
    assert merged[0].data_classes


def test_parse_breach_date_iso_and_year():
    assert bl._parse_breach_date("2020") == ("2020-01-01", "year")
    assert bl._parse_breach_date("2020-06-01T00:00:00+00:00") == ("2020-06-01", "day")
    assert bl._parse_breach_date("unknown") == ("unknown", "unknown")


def test_xon_catalog_enriches_exact_date():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        bl._xon_catalog_cache.clear()
        incident = bl.BreachIncident(
            name="Wattpad",
            breach_date="2020-01-01",
            added_date="unknown",
            data_classes=[],
            description="stub",
            breach_date_precision="year",
            source_provider="XposedOrNot",
        )

        bl._xon_catalog_cache.clear()
        bl._xon_catalog_index = None
        bl._xon_catalog_index_loaded_at = 0.0

        def fake_http(url, headers=None):
            if url.rstrip("/").endswith("/v1/breaches"):
                return 200, {
                    "exposedBreaches": [
                        {
                            "breachID": "Wattpad",
                            "breachedDate": "2020-06-01T00:00:00+00:00",
                            "addedDate": "2023-11-08T06:30:32+00:00",
                            "exposedData": ["Email addresses", "IP addresses"],
                            "exposedRecords": 268113400,
                            "exposureDescription": "Wattpad breach",
                            "domain": "wattpad.com",
                            "verified": True,
                        }
                    ]
                }
            return 404, {}

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            enriched = bl._xon_enrich_breach(incident)
        assert enriched.breach_date == "2020-06-01"
        assert enriched.breach_date_precision == "day"
        assert enriched.added_date == "2023-11-08"
        assert any("IP addresses" in c for c in enriched.data_classes)


def test_xon_stubs_enriched_via_catalog_when_analytics_empty():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot"):
        bl._xon_catalog_cache.clear()
        bl._xon_catalog_index = None
        bl._xon_catalog_index_loaded_at = 0.0

        def fake_http(url, headers=None):
            if "check-email" in url:
                return 200, {"breaches": [["Wattpad", "Dunzo"]]}
            if "breach-analytics" in url:
                return 200, {
                    "BreachMetrics": None,
                    "ExposedBreaches": None,
                    "PastesSummary": {"cnt": 0},
                }
            if url.rstrip("/").endswith("/v1/breaches"):
                return 200, {
                    "exposedBreaches": [
                        {
                            "breachID": "Wattpad",
                            "breachedDate": "2020-06-01T00:00:00+00:00",
                            "addedDate": "2023-11-08T06:30:32+00:00",
                            "exposedData": ["Email addresses", "IP addresses"],
                            "exposedRecords": 268113400,
                            "exposureDescription": "Wattpad breach",
                            "domain": "wattpad.com",
                            "verified": True,
                        },
                        {
                            "breachID": "Dunzo",
                            "breachedDate": "2019-07-01T00:00:00+00:00",
                            "addedDate": "2021-01-01T00:00:00+00:00",
                            "exposedData": ["Email addresses", "Phone numbers"],
                            "exposedRecords": 3500000,
                            "exposureDescription": "Dunzo breach",
                            "domain": "dunzo.com",
                            "verified": True,
                        },
                    ]
                }
            return 404, {}

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "user@example.com")
        assert r.status == "exposed"
        assert r.breach_count == 2
        by_name = {b.name: b for b in r.breaches}
        assert by_name["Wattpad"].breach_date == "2020-06-01"
        assert by_name["Wattpad"].breach_date_precision == "day"
        assert any("IP addresses" in c for c in by_name["Wattpad"].data_classes)
        assert by_name["Dunzo"].breach_date_precision == "day"


def test_xon_exposed_response():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot", GUARDIAN_BREACH_NO_CATALOG="1"):
        def fake_http(url, headers=None):
            if "check-email" in url:
                return 200, {"breaches": [["LinkedIn"]]}
            if "breach-analytics" in url:
                return 200, {
                    "ExposedBreaches": {
                        "breaches_details": [
                            {
                                "breach": "LinkedIn",
                                "xposed_date": "2012",
                                "xposed_records": 164611595,
                                "xposed_data": "Email addresses;Passwords",
                                "details": "LinkedIn breach affecting millions of accounts.",
                                "domain": "linkedin.com",
                                "verified": "Yes",
                            }
                        ]
                    }
                }
            return 404, {"Error": "Not found"}

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "dana.porter1988@outlook.com")
        assert r.status == "exposed"
        assert r.breach_count == 1
        assert r.breaches[0].name == "LinkedIn"
        assert r.breaches[0].pwn_count == 164611595
        assert "Email addresses" in r.breaches[0].data_classes
        assert r.timeline
        assert "2012" in r.timeline[0]["date"]


def test_xon_fast_skips_analytics_enrichment():
    with _Env(GUARDIAN_BREACH_PROVIDER="xposedornot", GUARDIAN_BREACH_FAST="1"):
        bl._xon_catalog_cache.clear()
        bl._xon_catalog_index = None
        calls: list[str] = []

        def fake_http(url, headers=None):
            calls.append(url)
            if "check-email" in url:
                return 200, {"breaches": [["Wattpad"]]}
            if url.rstrip("/").endswith("/v1/breaches"):
                return 200, {"exposedBreaches": []}
            if "breach_id=Wattpad" in url:
                return 200, {"exposedBreaches": []}
            raise AssertionError("analytics should not be called in fast mode")

        with patch.object(bl, "_http_get_json", side_effect=fake_http):
            r = bl.check_breach("email", "test@example.com")
        assert r.status == "exposed"
        assert not any("breach-analytics" in u for u in calls)
        assert any("check-email" in u for u in calls)


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
