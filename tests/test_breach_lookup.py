"""Tests for personal breach lookup (mock scenarios)."""

from guardian.intel.breach_lookup import (
    MOCK_EMAIL_BREACHED,
    MOCK_EMAIL_CLEAN,
    MOCK_EMAIL_LINKED,
    MOCK_EMAIL_PASTE,
    MOCK_SCENARIOS,
    check_breach,
    list_scenarios,
    mask_email,
    mask_phone,
    validate_identifier,
    watchlist_add,
    watchlist_list,
    watchlist_remove,
)


def test_list_scenarios():
    scenarios = list_scenarios()
    assert len(scenarios) >= 8
    ids = {s["id"] for s in scenarios}
    assert "clean_email" in ids
    assert "multi_breach_email" in ids


def test_mask_email():
    assert "@" in mask_email("dana.porter1988@outlook.com")
    assert "dana" not in mask_email("dana.porter1988@outlook.com")


def test_clean_email():
    r = check_breach("email", MOCK_EMAIL_CLEAN)
    assert r.status == "clean"
    assert r.breach_count == 0
    assert r.scenario_id == "clean_email"


def test_multi_breach_email():
    r = check_breach("email", MOCK_EMAIL_BREACHED)
    assert r.status == "exposed"
    assert r.breach_count == 3
    assert len(r.timeline) == 3
    assert any("Passwords" in b.data_classes for b in r.breaches)


def test_paste_email():
    r = check_breach("email", MOCK_EMAIL_PASTE)
    assert r.status == "exposed"
    assert r.paste_count == 1
    assert r.breach_count == 0


def test_linked_accounts_email():
    r = check_breach("email", MOCK_EMAIL_LINKED)
    assert r.status == "exposed"
    assert r.linked_account_count == 3
    assert r.breach_count == 1


def test_breached_phone():
    r = check_breach("phone", "+15559876543")
    assert r.status == "exposed"
    assert r.breach_count == 1


def test_clean_phone():
    r = check_breach("phone", "+15550001111")
    assert r.status == "clean"


def test_breached_username():
    r = check_breach("username", "leaked_user")
    assert r.status == "exposed"
    assert r.breach_count == 2
    assert r.linked_account_count == 2


def test_clean_username():
    r = check_breach("username", "safe_handle_99")
    assert r.status == "clean"


def test_invalid_email():
    r = check_breach("email", "not-an-email")
    assert r.status == "invalid"
    assert "valid" in r.plain_summary.lower()


def test_invalid_empty():
    assert validate_identifier("email", "") is not None
    assert validate_identifier("phone", "abc") is not None
    assert validate_identifier("username", "x") is not None


def test_unknown_defaults_clean():
    r = check_breach("email", "jordan.ellis.work@proton.me")
    assert r.status == "clean"
    assert r.scenario_id == "unknown_clean"


def test_watchlist_flow():
    watchlist_remove("email:deadbeef")
    out = watchlist_add("email", MOCK_EMAIL_CLEAN, "my test")
    assert out.get("ok")
    assert out["entry"]["last_status"] == "clean"
    entries = watchlist_list()
    assert any(e["identifier_masked"] for e in entries)
    entry_id = entries[-1]["id"]
    assert watchlist_remove(entry_id).get("ok")


def test_risk_level_exposed():
    r = check_breach("email", MOCK_EMAIL_BREACHED)
    assert r.risk_level in ("medium", "high")
    assert r.data_classes_summary


def test_risk_level_clean():
    r = check_breach("email", MOCK_EMAIL_CLEAN)
    assert r.risk_level == "low"


def test_pwned_password_mock():
    from guardian.intel.breach_lookup import check_pwned_password

    bad = check_pwned_password("password123")
    assert bad.status == "pwned"
    assert bad.count > 0
    good = check_pwned_password("unique-guardian-test-xyzzy-99")
    assert good.status == "safe"


def test_breach_cache():
    from guardian.intel import breach_lookup as bl

    with bl._breach_cache_lock:
        bl._breach_cache.clear()
    email = "cache-test-user@example.org"
    r1 = check_breach("email", email)
    r2 = check_breach("email", email)
    assert r2.from_cache is True
    assert r1.status == r2.status


def test_watchlist_recheck_flow():
    from guardian.intel.breach_lookup import watchlist_recheck_all, watchlist_remove

    watchlist_add("email", MOCK_EMAIL_CLEAN, "recheck-test")
    summary = watchlist_recheck_all()
    assert summary["checked"] >= 1
    for e in summary["entries"]:
        if e.get("label") == "recheck-test":
            watchlist_remove(e["id"])


def test_all_documented_scenarios():
    for s in MOCK_SCENARIOS:
        r = check_breach(s["type"], s["sample"])  # type: ignore[arg-type]
        assert r.status == s["expected"], f"scenario {s['id']} expected {s['expected']} got {r.status}"
