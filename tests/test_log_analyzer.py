"""Tests for log analyzer pre-filter (no SLM required)."""

from guardian.modules.log_analyzer import _is_suspicious


def test_detects_failed_auth():
    assert _is_suspicious("Jun 14 10:01:32 server sshd[1234]: Failed password for root from 192.168.1.1 port 22")


def test_detects_sudo():
    assert _is_suspicious("sudo: jhak : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash")


def test_detects_nmap():
    assert _is_suspicious("user ran nmap scan on network")


def test_detects_sensitive_paths():
    assert _is_suspicious("read /etc/shadow attempt detected")


def test_normal_line_not_flagged():
    assert not _is_suspicious("Jun 14 10:00:01 server CRON[1234]: pam_unix(cron:session): session opened for user www-data")
