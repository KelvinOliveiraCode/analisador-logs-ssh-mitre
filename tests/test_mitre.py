"""Testes do mapeamento MITRE ATT&CK."""

from analisador_ssh_mitre.mitre import MITRE_MAP, map_event
from analisador_ssh_mitre.models import SshEvent


def _event(event_type: str, user: str = "teste") -> SshEvent:
    return SshEvent(
        timestamp="Oct 10 10:23:45",
        user=user,
        ip="10.0.0.5",
        port=51234,
        event_type=event_type,
        raw_line="x",
    )


def test_map_failed_password_to_t1110():
    mapping = map_event(_event("failed_password", "root"))
    assert mapping.technique_id == "T1110"
    assert mapping.technique_name == "Brute Force"
    assert mapping.sub_technique_id == "T1110.001"
    assert mapping.sub_technique_name == "Password Guessing"
    assert mapping.tactic == "Credential Access"


def test_map_invalid_user_to_t1110():
    mapping = map_event(_event("invalid_user", "admin"))
    assert mapping.technique_id == "T1110"
    assert mapping.technique_name == "Brute Force"
    assert mapping.sub_technique_id == "T1110.001"
    assert mapping.tactic == "Credential Access"


def test_map_accepted_password_to_t1078():
    mapping = map_event(_event("accepted_password", "ubuntu"))
    assert mapping.technique_id == "T1078"
    assert mapping.technique_name == "Valid Accounts"
    assert mapping.sub_technique_id is None
    assert mapping.sub_technique_name is None
    assert "Defense Evasion" in mapping.tactic


def test_mitre_map_covers_all_event_types():
    assert set(MITRE_MAP) == {"failed_password", "invalid_user", "accepted_password"}
