"""Testes do parser de linhas de log SSH."""

from analisador_ssh_mitre.parser import parse_line, parse_log


def test_parse_failed_password_invalid_user():
    line = "Oct 10 10:23:45 host sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22000 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.timestamp == "Oct 10 10:23:45"
    assert event.user == "admin"
    assert event.ip == "192.168.1.10"
    assert event.port == 22000
    assert event.event_type == "invalid_user"


def test_parse_failed_password_valid_user():
    line = "Oct 10 10:23:46 host sshd[1234]: Failed password for root from 10.0.0.5 port 51234 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.user == "root"
    assert event.ip == "10.0.0.5"
    assert event.port == 51234
    assert event.event_type == "failed_password"


def test_parse_accepted_password():
    line = "Oct 10 10:23:47 host sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 51235 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.user == "ubuntu"
    assert event.ip == "10.0.0.5"
    assert event.port == 51235
    assert event.event_type == "accepted_password"


def test_parse_ignores_non_password_lines():
    assert parse_line("Oct 10 10:23:48 host sshd[1234]: Accepted publickey for ubuntu from 10.0.0.5 port 51236 ssh2") is None
    assert parse_line("Oct 10 10:23:49 host sshd[1234]: Connection closed by 10.0.0.5 port 51235 [preauth]") is None


def test_parse_returns_none_for_empty_line():
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_parse_log_extracts_all_events(sample_log):
    events = parse_log(sample_log)
    assert len(events) == 3
    assert events[0].event_type == "invalid_user"
    assert events[1].event_type == "failed_password"
    assert events[2].event_type == "accepted_password"


def test_parse_log_ignores_unrecognized_lines(sample_log):
    events = parse_log(sample_log)
    ips = {e.ip for e in events}
    assert ips == {"192.168.1.10", "10.0.0.5"}
    users = {e.user for e in events}
    assert users == {"admin", "root", "ubuntu"}
