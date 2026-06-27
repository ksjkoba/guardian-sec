"""Tests for the dashboard access-control layer (password gate)."""

import hashlib
import time

import pytest

from guardian.security import access


# ─── Unit: password config + verification ─────────────────────────────────────

def test_login_not_required_when_unset(monkeypatch):
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD_HASH", raising=False)
    assert access.login_required() is False
    assert access.verify_password("anything") is False


def test_login_required_with_plaintext_password(monkeypatch):
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD", "hunter2")
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD_HASH", raising=False)
    assert access.login_required() is True
    assert access.verify_password("hunter2") is True
    assert access.verify_password("wrong") is False
    assert access.verify_password("") is False


def test_login_required_with_password_hash(monkeypatch):
    digest = hashlib.sha256(b"s3cret").hexdigest()
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD_HASH", digest)
    assert access.login_required() is True
    assert access.verify_password("s3cret") is True
    assert access.verify_password("nope") is False


def test_hash_takes_precedence_over_plaintext(monkeypatch):
    digest = hashlib.sha256(b"fromhash").hexdigest()
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD", "fromplain")
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD_HASH", digest)
    assert access.verify_password("fromhash") is True
    assert access.verify_password("fromplain") is False


# ─── Unit: AccessManager token lifecycle ──────────────────────────────────────

def test_issue_and_verify_token():
    mgr = access.AccessManager()
    token, expires = mgr.issue()
    assert token
    assert expires > time.time()
    assert mgr.verify(token) is True
    assert mgr.verify("not-the-token") is False
    assert mgr.verify("") is False


def test_revoke_token():
    mgr = access.AccessManager()
    token, _ = mgr.issue()
    assert mgr.verify(token) is True
    mgr.revoke(token)
    assert mgr.verify(token) is False


def test_expired_token_is_rejected():
    mgr = access.AccessManager(ttl_secs=-1)  # already expired on issue
    token, _ = mgr.issue()
    assert mgr.verify(token) is False
    assert mgr.active_count() == 0


def test_token_cap_evicts_oldest():
    mgr = access.AccessManager()
    # Drop the cap low for the test.
    import guardian.security.access as mod
    original = mod.MAX_ACCESS_TOKENS
    mod.MAX_ACCESS_TOKENS = 3
    try:
        tokens = [mgr.issue()[0] for _ in range(5)]
        assert mgr.active_count() <= 3
        # The most recent tokens should still be valid.
        assert mgr.verify(tokens[-1]) is True
    finally:
        mod.MAX_ACCESS_TOKENS = original


# ─── Integration: server enforcement ──────────────────────────────────────────

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from guardian.web.server import create_app, DashboardState  # noqa: E402


@pytest.fixture
def gated_client(monkeypatch, tmp_path):
    """A dashboard with a password configured."""
    monkeypatch.setenv("GUARDIAN_API_AUTH", "0")
    monkeypatch.setenv("GUARDIAN_ALLOW_PLAINTEXT", "1")
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "guardian"))
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD", "letmein")
    import guardian.web.persistence as persist
    persist._initialized = False
    app = create_app(dashboard_state=DashboardState())
    with TestClient(app) as tc:
        yield tc


def test_status_reports_login_required(gated_client):
    r = gated_client.get("/api/security/status")
    assert r.status_code == 200
    assert r.json()["login_required"] is True


def test_protected_route_blocked_without_token(gated_client):
    r = gated_client.get("/api/alerts")
    assert r.status_code == 401
    assert r.json().get("login_required") is True


def test_login_wrong_password_rejected(gated_client):
    r = gated_client.post("/api/security/login", json={"password": "nope"})
    assert r.status_code == 401


def test_login_then_access_granted(gated_client):
    r = gated_client.post("/api/security/login", json={"password": "letmein"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    assert token

    # Without the token: blocked.
    assert gated_client.get("/api/alerts").status_code == 401
    # With the token: allowed.
    ok = gated_client.get("/api/alerts", headers={"X-Guardian-Access": token})
    assert ok.status_code == 200


def test_handshake_blocked_until_login(gated_client):
    """No E2E session is issued to an unauthenticated client."""
    r = gated_client.post(
        "/api/security/handshake", json={"client_public_key": "x"}
    )
    assert r.status_code == 401  # gated before reaching the handshake logic


def test_logout_revokes_token(gated_client):
    token = gated_client.post(
        "/api/security/login", json={"password": "letmein"}
    ).json()["access_token"]
    hdr = {"X-Guardian-Access": token}
    assert gated_client.get("/api/alerts", headers=hdr).status_code == 200
    gated_client.post("/api/security/logout", headers=hdr)
    assert gated_client.get("/api/alerts", headers=hdr).status_code == 401


# ─── Unit: LoginThrottle ──────────────────────────────────────────────────────

def test_throttle_locks_after_max_failures():
    t = access.LoginThrottle(max_failures=3, lockout_secs=60, window_secs=900)
    client = "8.8.8.8"
    assert t.is_locked(client) is False
    assert t.record_failure(client) == 0.0  # 1
    assert t.record_failure(client) == 0.0  # 2
    locked = t.record_failure(client)        # 3 -> lockout
    assert locked == 60
    assert t.is_locked(client) is True
    assert 0 < t.locked_for(client) <= 60


def test_throttle_success_clears_failures():
    t = access.LoginThrottle(max_failures=3, lockout_secs=60)
    client = "8.8.8.8"
    t.record_failure(client)
    t.record_failure(client)
    t.record_success(client)
    # Counter reset — a single failure shouldn't lock now.
    assert t.record_failure(client) == 0.0
    assert t.is_locked(client) is False


def test_throttle_lockout_expires():
    t = access.LoginThrottle(max_failures=1, lockout_secs=-1)  # expires immediately
    client = "8.8.8.8"
    t.record_failure(client)
    assert t.is_locked(client) is False  # already expired


def test_throttle_exempts_loopback_by_default(monkeypatch):
    monkeypatch.delenv("GUARDIAN_LOGIN_THROTTLE_LOCAL", raising=False)
    t = access.LoginThrottle(max_failures=1, lockout_secs=60)
    for _ in range(5):
        assert t.record_failure("127.0.0.1") == 0.0
    assert t.is_locked("127.0.0.1") is False


def test_throttle_can_include_loopback(monkeypatch):
    monkeypatch.setenv("GUARDIAN_LOGIN_THROTTLE_LOCAL", "1")
    t = access.LoginThrottle(max_failures=2, lockout_secs=60)
    t.record_failure("127.0.0.1")
    assert t.record_failure("127.0.0.1") == 60
    assert t.is_locked("127.0.0.1") is True


def test_throttle_window_drops_old_failures():
    # window=0 means every prior failure is immediately stale, so the count
    # never accumulates toward a lockout.
    t = access.LoginThrottle(max_failures=3, lockout_secs=60, window_secs=0)
    client = "8.8.8.8"
    for _ in range(10):
        assert t.record_failure(client) == 0.0
    assert t.is_locked(client) is False


# ─── Unit: audit log ──────────────────────────────────────────────────────────

def test_audit_log_writes_jsonl(monkeypatch, tmp_path):
    import json as _json
    import guardian.security.vault as vault
    monkeypatch.setattr(vault, "data_dir", lambda: tmp_path)

    access.log_login_event("login_failure", "8.8.8.8")
    access.log_login_event("login_success", "8.8.8.8", detail="ok")

    log = tmp_path / "audit.log"
    assert log.exists()
    lines = [l for l in log.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    first = _json.loads(lines[0])
    assert first["event"] == "login_failure"
    assert first["client"] == "8.8.8.8"
    assert "ts" in first and "iso" in first
    assert _json.loads(lines[1])["detail"] == "ok"


def test_audit_log_never_raises(monkeypatch):
    import guardian.security.vault as vault

    def _boom():
        raise OSError("no data dir")

    monkeypatch.setattr(vault, "data_dir", _boom)
    # Must not propagate — auditing is best-effort.
    access.log_login_event("login_failure", "1.2.3.4")


# ─── Integration: throttle + audit via the login endpoint ─────────────────────

def test_login_lockout_via_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_API_AUTH", "0")
    monkeypatch.setenv("GUARDIAN_ALLOW_PLAINTEXT", "1")
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "guardian"))
    monkeypatch.setenv("GUARDIAN_DASHBOARD_PASSWORD", "letmein")
    monkeypatch.setenv("GUARDIAN_LOGIN_MAX_FAILURES", "3")
    monkeypatch.setenv("GUARDIAN_LOGIN_LOCKOUT_SECS", "300")
    # TestClient reports client as "testclient" (not loopback), so throttling applies.
    import guardian.web.persistence as persist
    persist._initialized = False
    app = create_app(dashboard_state=DashboardState())
    with TestClient(app) as c:
        for _ in range(2):
            assert c.post("/api/security/login", json={"password": "wrong"}).status_code == 401
        # 3rd failure triggers lockout (429), not a plain 401.
        r = c.post("/api/security/login", json={"password": "wrong"})
        assert r.status_code == 429
        assert r.json().get("locked") is True
        assert "Retry-After" in r.headers
        # Even the correct password is refused while locked out.
        assert c.post("/api/security/login", json={"password": "letmein"}).status_code == 429


def test_no_password_means_open(monkeypatch, tmp_path):
    """Without a configured password, the gate is inactive (local-use default)."""
    monkeypatch.setenv("GUARDIAN_API_AUTH", "0")
    monkeypatch.setenv("GUARDIAN_ALLOW_PLAINTEXT", "1")
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "guardian"))
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("GUARDIAN_DASHBOARD_PASSWORD_HASH", raising=False)
    import guardian.web.persistence as persist
    persist._initialized = False
    app = create_app(dashboard_state=DashboardState())
    with TestClient(app) as tc:
        assert tc.get("/api/security/status").json()["login_required"] is False
        assert tc.get("/api/alerts").status_code == 200
        # login is a no-op when not required
        assert tc.post("/api/security/login", json={}).json()["login_required"] is False
