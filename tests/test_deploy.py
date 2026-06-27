"""Deployment profile tests."""

import os

from guardian.web import deploy


class _Env:
    KEYS = (
        "GUARDIAN_DEPLOY_MODE",
        "GUARDIAN_PUBLIC_HOST",
        "GUARDIAN_PUBLIC_PORT",
        "GUARDIAN_PUBLIC_URL",
        "GUARDIAN_TLS_CERT",
        "GUARDIAN_TLS_AUTO",
        "GUARDIAN_BIND_HOST",
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


def test_local_dashboard_url():
    with _Env():
        assert deploy.deploy_mode() == "local"
        assert deploy.dashboard_base_url() == "http://127.0.0.1:8765/"


def test_vps_public_url_https():
    with _Env(
        GUARDIAN_DEPLOY_MODE="vps",
        GUARDIAN_PUBLIC_HOST="guardian.example.com",
        GUARDIAN_PUBLIC_PORT="443",
        GUARDIAN_TLS_CERT="/etc/letsencrypt/live/guardian.example.com/fullchain.pem",
    ):
        assert deploy.dashboard_base_url() == "https://guardian.example.com/"


def test_vps_bind_host_default():
    with _Env(GUARDIAN_DEPLOY_MODE="vps"):
        assert deploy.default_bind_host() == "0.0.0.0"
