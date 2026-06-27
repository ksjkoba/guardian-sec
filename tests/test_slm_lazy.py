"""Tests for lazy SLM loading.

`guardian serve` must NOT load the 2.4 GB Phi-3 model into RAM at startup —
the dashboard should come up light and fast, and the model should only be
materialized on the first analysis that actually needs it. These tests lock in
that contract at the `slm` module boundary and the `serve` wiring.
"""

from __future__ import annotations

import pytest

import guardian.engine.slm as slm


@pytest.fixture(autouse=True)
def _reset_slm_singleton():
    """Ensure each test starts and ends with a clean SLM singleton."""
    slm._instance = None
    slm._configured_model_path = None
    yield
    slm._instance = None
    slm._configured_model_path = None


def test_is_loaded_false_before_use():
    assert slm.is_loaded() is False


def test_set_model_path_records_path_without_loading():
    slm.set_model_path("/some/custom/model.gguf")
    assert slm._configured_model_path == "/some/custom/model.gguf"
    # Registering a path must not construct the engine.
    assert slm.is_loaded() is False


def test_get_engine_uses_configured_path(monkeypatch):
    captured = {}

    class _FakeEngine:
        def __init__(self, model_path=None):
            captured["model_path"] = model_path

    monkeypatch.setattr(slm, "SLMEngine", _FakeEngine)

    slm.set_model_path("/configured/model.gguf")
    engine = slm.get_engine()

    assert isinstance(engine, _FakeEngine)
    assert captured["model_path"] == "/configured/model.gguf"
    assert slm.is_loaded() is True


def test_explicit_path_overrides_configured(monkeypatch):
    captured = {}

    class _FakeEngine:
        def __init__(self, model_path=None):
            captured["model_path"] = model_path

    monkeypatch.setattr(slm, "SLMEngine", _FakeEngine)

    slm.set_model_path("/configured/model.gguf")
    slm.get_engine(model_path="/explicit/model.gguf")

    assert captured["model_path"] == "/explicit/model.gguf"


def test_get_engine_is_singleton(monkeypatch):
    calls = {"n": 0}

    class _FakeEngine:
        def __init__(self, model_path=None):
            calls["n"] += 1

    monkeypatch.setattr(slm, "SLMEngine", _FakeEngine)

    first = slm.get_engine()
    second = slm.get_engine()

    assert first is second
    assert calls["n"] == 1


def test_prepare_engine_lazy_does_not_load(monkeypatch):
    """`serve`'s lazy prep registers the path but never builds the engine."""
    from guardian import cli

    def _boom(*a, **k):
        raise AssertionError("SLMEngine must not be constructed during serve startup")

    monkeypatch.setattr(slm, "SLMEngine", _boom)

    cli._prepare_engine_lazy(None)

    assert slm.is_loaded() is False
