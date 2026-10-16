"""Mapeamento de eventos SSH para técnicas MITRE ATT&CK.

Cada tipo de evento SSH é associado a uma técnica (e, quando aplicável,
sub-técnica) do framework MITRE ATT&CK, na matriz Enterprise.
"""

from __future__ import annotations

from .models import MitreMapping, SshEvent

MITRE_MAP: dict[str, MitreMapping] = {
    "failed_password": MitreMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique_id="T1110.001",
        sub_technique_name="Password Guessing",
        tactic="Credential Access",
    ),
    "invalid_user": MitreMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique_id="T1110.001",
        sub_technique_name="Password Guessing",
        tactic="Credential Access",
    ),
    "accepted_password": MitreMapping(
        technique_id="T1078",
        technique_name="Valid Accounts",
        sub_technique_id=None,
        sub_technique_name=None,
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    ),
}


def map_event(event: SshEvent) -> MitreMapping:
    """Retorna o mapeamento MITRE ATT&CK para um evento SSH.

    Args:
        event: evento SSH parseado.

    Returns:
        O :class:`MitreMapping` correspondente ao ``event.event_type``.

    Raises:
        KeyError: se o tipo de evento não tiver mapeamento definido.
    """
    return MITRE_MAP[event.event_type]
