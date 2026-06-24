#!/usr/bin/env python3
"""QA runner: all mock breach scenarios + live API checks."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8765"


def main() -> int:
    failures: list[tuple[str, str]] = []
    passed = 0

    def ok(name: str) -> None:
        nonlocal passed
        passed += 1
        print(f"  PASS  {name}")

    def fail(name: str, detail: str = "") -> None:
        failures.append((name, detail))
        print(f"  FAIL  {name}: {detail}")

    def get(path: str) -> tuple[int, object]:
        with urllib.request.urlopen(BASE + path) as r:
            return r.status, json.loads(r.read())

    def post(path: str, body: dict) -> tuple[int, object]:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            BASE + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())

    def delete(path: str) -> tuple[int, object]:
        req = urllib.request.Request(BASE + path, method="DELETE")
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())

    print("=== Module tests (breach_lookup) ===")
    from guardian.intel.breach_lookup import (
        MOCK_EMAIL_BREACHED,
        MOCK_EMAIL_CLEAN,
        MOCK_EMAIL_LINKED,
        MOCK_EMAIL_PASTE,
        MOCK_SCENARIOS,
        check_breach,
        list_scenarios,
        mask_email,
        validate_identifier,
        watchlist_add,
        watchlist_list,
        watchlist_remove,
    )

    if len(list_scenarios()) >= 8:
        ok("list_scenarios count")
    else:
        fail("list_scenarios count", str(len(list_scenarios())))

    if "dana" not in mask_email("dana.porter1988@outlook.com"):
        ok("mask_email")
    else:
        fail("mask_email")

    for s in MOCK_SCENARIOS:
        r = check_breach(s["type"], s["sample"])  # type: ignore[arg-type]
        sid = s["id"]
        if r.status == s["expected"]:
            ok(f"scenario {sid}")
        else:
            fail(f"scenario {sid}", f"expected {s['expected']} got {r.status}")

    r = check_breach("email", "random.person@unknown.test")
    if r.status == "clean" and r.scenario_id == "unknown_clean":
        ok("unknown_defaults_clean")
    else:
        fail("unknown_defaults_clean", r.status)

    if validate_identifier("email", "") and validate_identifier("phone", "abc"):
        ok("invalid_empty validation")
    else:
        fail("invalid_empty validation")

    watchlist_remove("email:deadbeef")
    if watchlist_add("email", MOCK_EMAIL_CLEAN, "qa").get("ok"):
        ok("watchlist_add")
    else:
        fail("watchlist_add")
    entries = watchlist_list()
    if entries:
        ok("watchlist_list")
        if watchlist_remove(entries[-1]["id"]).get("ok"):
            ok("watchlist_remove")
        else:
            fail("watchlist_remove")
    else:
        fail("watchlist_list", "empty")

    print("\n=== Live API tests ===")
    try:
        st, data = get("/api/breach/scenarios")
        if st == 200 and isinstance(data, dict) and data.get("provider") == "mock":
            if len(data.get("scenarios", [])) >= 8:
                ok("GET /api/breach/scenarios")
            else:
                fail("GET /api/breach/scenarios", "too few scenarios")
        else:
            fail("GET /api/breach/scenarios", str(data)[:200])
    except Exception as exc:
        fail("GET /api/breach/scenarios", str(exc))

    api_cases = [
        ("clean_email", "email", MOCK_EMAIL_CLEAN, "clean", {"breach_count": 0}),
        ("multi_breach", "email", MOCK_EMAIL_BREACHED, "exposed", {"breach_count": 3}),
        ("paste_only", "email", MOCK_EMAIL_PASTE, "exposed", {"paste_count": 1, "breach_count": 0}),
        ("linked", "email", MOCK_EMAIL_LINKED, "exposed", {"linked_account_count": 3}),
        ("phone_exposed", "phone", "+15559876543", "exposed", {"breach_count": 1}),
        ("phone_clean", "phone", "+15550001111", "clean", {}),
        ("user_exposed", "username", "leaked_user", "exposed", {"breach_count": 2}),
        ("user_clean", "username", "safe_handle_99", "clean", {}),
        ("invalid", "email", "not-an-email", "invalid", {}),
    ]
    for name, typ, val, exp_status, extra in api_cases:
        try:
            st, d = post("/api/breach/check", {"type": typ, "value": val})
            if st == 200 and isinstance(d, dict) and d.get("status") == exp_status:
                if all(d.get(k) == v for k, v in extra.items()):
                    ok(f"POST check {name}")
                else:
                    fail(f"POST check {name}", f"extra mismatch {d}")
            else:
                fail(f"POST check {name}", f"got {d}")
        except Exception as exc:
            fail(f"POST check {name}", str(exc))

    try:
        st, d = post(
            "/api/breach/watchlist",
            {"type": "email", "value": MOCK_EMAIL_BREACHED, "label": "qa"},
        )
        if st == 200 and isinstance(d, dict) and d.get("ok"):
            ok("POST watchlist")
            st2, entries = get("/api/breach/watchlist")
            if st2 == 200 and entries:
                ok("GET watchlist")
                eid = entries[-1]["id"]
                st3, rem = delete(f"/api/breach/watchlist/{eid}")
                if st3 == 200 and isinstance(rem, dict) and rem.get("ok"):
                    ok("DELETE watchlist")
                else:
                    fail("DELETE watchlist", str(rem))
            else:
                fail("GET watchlist", str(entries))
        else:
            fail("POST watchlist", str(d))
    except Exception as exc:
        fail("watchlist API", str(exc))

    print("\n=== Global feed API ===")
    try:
        st, data = get("/api/global-feed/status")
        if st == 200 and isinstance(data, dict) and "sources_ok" in data:
            ok(f"GET global-feed/status ({data.get('sources_ok', 0)} ok)")
        else:
            fail("GET global-feed/status", str(data)[:200])
    except Exception as exc:
        fail("GET global-feed/status", str(exc))

    print("\n=== Dashboard HTML ===")
    try:
        with urllib.request.urlopen(BASE + "/") as r:
            html = r.read().decode()
        for needle in ["Personal Check", "Live Threat Feed", "breach-form"]:
            if needle in html:
                ok(f"HTML contains {needle}")
            else:
                fail(f"HTML contains {needle}", "missing")
    except Exception as exc:
        fail("dashboard HTML", str(exc))

    print(f"\n=== SUMMARY: {passed} passed, {len(failures)} failed ===")
    for name, detail in failures:
        print(f"  - {name}: {detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
