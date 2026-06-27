"""Tests for the optional local TLS certificate helper."""

import os

import pytest

from guardian.security import tls


class _Env:
    """Context manager to set/restore environment variables."""

    def __init__(self, **kwargs):
        self._new = kwargs
        self._old: dict[str, str | None] = {}

    def __enter__(self):
        for k, v in self._new.items():
            self._old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_explicit_cert_and_key_passthrough():
    with _Env(GUARDIAN_TLS_CERT="/tmp/a.crt", GUARDIAN_TLS_KEY="/tmp/a.key"):
        assert tls.ensure_local_tls_cert() == ("/tmp/a.crt", "/tmp/a.key")


def test_disabled_when_no_auto_and_no_explicit():
    with _Env(GUARDIAN_TLS_CERT=None, GUARDIAN_TLS_KEY=None, GUARDIAN_TLS_AUTO=None):
        assert tls.ensure_local_tls_cert() is None


def test_reuses_existing_generated_cert(tmp_path, monkeypatch):
    # Point data_dir() at a temp dir and pre-create the cert/key pair so the
    # helper returns the existing files without invoking openssl.
    import guardian.security.vault as vault
    monkeypatch.setattr(vault, "data_dir", lambda: tmp_path)
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    (tls_dir / "guardian-local.crt").write_text("cert")
    (tls_dir / "guardian-local.key").write_text("key")

    with _Env(GUARDIAN_TLS_CERT=None, GUARDIAN_TLS_KEY=None, GUARDIAN_TLS_AUTO="1"):
        cert, key = tls.ensure_local_tls_cert()
    assert cert.endswith("guardian-local.crt")
    assert key.endswith("guardian-local.key")


def test_missing_openssl_raises_friendly_error(tmp_path, monkeypatch):
    import guardian.security.vault as vault
    monkeypatch.setattr(vault, "data_dir", lambda: tmp_path)

    def _boom(*a, **k):
        raise FileNotFoundError("openssl")

    monkeypatch.setattr(tls.subprocess, "run", _boom)
    with _Env(GUARDIAN_TLS_CERT=None, GUARDIAN_TLS_KEY=None, GUARDIAN_TLS_AUTO="1"):
        with pytest.raises(RuntimeError) as exc:
            tls.ensure_local_tls_cert()
    assert "openssl" in str(exc.value).lower()


def test_cert_subject_has_no_personal_domain():
    """The self-signed cert subject must not embed any personal/operator domain."""
    import inspect

    src = inspect.getsource(tls.ensure_local_tls_cert)
    assert "learniam" not in src.lower()
