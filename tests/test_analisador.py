"""Testes do analisador principal e emissão de JSON."""

import json

from analisador_ssh_mitre.analisador import analyze, to_json
from analisador_ssh_mitre.models import AnalisadorResult

SAMPLE_LOG = """Oct 10 10:23:45 host sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22000 ssh2
Oct 10 10:23:46 host sshd[1234]: Failed password for root from 10.0.0.5 port 51234 ssh2
Oct 10 10:23:47 host sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 51235 ssh2
"""


def test_analyze_returns_result_with_counts():
    result = analyze(SAMPLE_LOG.splitlines(), source="auth.log")
    assert isinstance(result, AnalisadorResult)
    assert result.source == "auth.log"
    assert result.total_events == 3


def test_analyze_events_have_expected_fields():
    result = analyze(SAMPLE_LOG.splitlines(), source="auth.log")
    assert len(result.events) == 3
    assert result.events[0]["user"] == "admin"
    assert result.events[0]["ip"] == "192.168.1.10"
    assert result.events[0]["port"] == 22000
    assert result.events[0]["event_type"] == "invalid_user"
    assert result.events[2]["event_type"] == "accepted_password"


def test_analyze_techniques_match_events():
    result = analyze(SAMPLE_LOG.splitlines(), source="auth.log")
    assert len(result.techniques) == 3
    assert result.techniques[0]["technique_id"] == "T1110"
    assert result.techniques[1]["technique_id"] == "T1110"
    assert result.techniques[2]["technique_id"] == "T1078"


def test_output_is_deterministic():
    output_a = to_json(analyze(SAMPLE_LOG.splitlines(), source="auth.log"))
    output_b = to_json(analyze(SAMPLE_LOG.splitlines(), source="auth.log"))
    assert output_a == output_b
    json.loads(output_a)  # deve ser JSON válido


def test_empty_log_produces_empty_result():
    result = analyze([], source="vazio")
    assert result.total_events == 0
    assert result.events == []
    assert result.techniques == []


def test_events_are_sorted_by_timestamp():
    log = """Oct 10 10:23:47 host sshd[1]: Accepted password for z from 1.1.1.1 port 1 ssh2
Oct 10 10:23:45 host sshd[1]: Failed password for a from 2.2.2.2 port 2 ssh2
Oct 10 10:23:46 host sshd[1]: Failed password for b from 3.3.3.3 port 3 ssh2
"""
    result = analyze(log.splitlines(), source="x")
    assert [e["user"] for e in result.events] == ["a", "b", "z"]
