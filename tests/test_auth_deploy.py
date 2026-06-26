"""Auth path rules for local vs VPS deployment."""

import os

from guardian.security import auth


class _Env:
    def __init__(self, **kwargs: str):
        self._kwargs = kwargs
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        for key in (
            "GUARDIAN_DEPLOY_MODE",
            "GUARDIAN_DISABLE_TEST_ALERT",
            "GUARDIAN_ALLOW_TEST_ALERT",
        ):
            self._saved[key] = os.environ.get(key)
            os.environ.pop(key, None)
        for key, val in self._kwargs.items():
            os.environ[key] = val
        return self

    def __exit__(self, *args):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val


def test_test_alert_allowed_local_loopback():
    with _Env():
        assert auth.test_alert_allowed("127.0.0.1") is True
        assert "/api/test-alert" in auth.public_api_paths("127.0.0.1")


def test_test_alert_blocked_on_vps():
    with _Env(GUARDIAN_DEPLOY_MODE="vps"):
        assert auth.test_alert_allowed("127.0.0.1") is False
        assert "/api/test-alert" not in auth.public_api_paths("127.0.0.1")


def test_test_alert_blocked_remote_on_local_mode():
    with _Env():
        assert auth.test_alert_allowed("203.0.113.50") is False


def test_test_alert_explicit_allow():
    with _Env(GUARDIAN_DEPLOY_MODE="vps", GUARDIAN_ALLOW_TEST_ALERT="1"):
        assert auth.test_alert_allowed("203.0.113.50") is True


def test_verify_persist_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path))
    from guardian.web.persistence import init_db, load_alerts, save_alert

    init_db()
    alert = {
        "id": "alert-verify-1",
        "title": "Test",
        "verified": False,
        "timestamp": 1.0,
        "metadata": {"verified": False},
    }
    save_alert(alert)
    alert["verified"] = True
    alert["verified_detail"] = "confirmed"
    alert["metadata"]["verified"] = True
    save_alert(alert)
    loaded = load_alerts()
    assert loaded[0]["verified"] is True
    assert loaded[0]["verified_detail"] == "confirmed"
