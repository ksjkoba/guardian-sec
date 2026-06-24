"""Tests for code scanner pre-filter logic (no SLM required)."""

import re
import pytest
from guardian.modules.code_scanner import _detect_language, _LANG_EXTS, _BAD_PATTERNS
from pathlib import Path


def _is_suspicious_line(line: str) -> bool:
    return any(p.search(line) for p, _ in _BAD_PATTERNS)


def test_detects_hardcoded_password():
    assert _is_suspicious_line('password = "mysecret123"')


def test_detects_eval():
    assert _is_suspicious_line("eval(user_input)")


def test_detects_sql_concat():
    assert _is_suspicious_line("query = 'SELECT * FROM users WHERE id = ' + user_id")


def test_detects_private_key():
    assert _is_suspicious_line("-----BEGIN RSA PRIVATE KEY-----")


def test_clean_line_not_flagged():
    assert not _is_suspicious_line("x = 1 + 2")
    assert not _is_suspicious_line("def my_function(a, b):")


def test_language_detection():
    assert _detect_language(Path("app.py")) == "Python"
    assert _detect_language(Path("main.go")) == "Go"
    assert _detect_language(Path("Dockerfile")) == "Dockerfile"
    assert _detect_language(Path("config.yaml")) == "YAML"
    assert _detect_language(Path("mystery.xyz")) == "Unknown"
