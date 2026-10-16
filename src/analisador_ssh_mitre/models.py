"""Modelos de dados do analisador de logs SSH."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SshEvent:
    """Evento SSH extraído de uma linha de log.

    Attributes:
        timestamp: carimbo de data/hora tal como aparece no log (sem ano).
        user: nome de utilizador envolvido no evento.
        ip: endereço IPv4 de origem.
        port: porta de origem da ligação.
        event_type: tipo do evento ("failed_password", "accepted_password",
            "invalid_user").
        raw_line: linha original do log, para rastreabilidade.
    """

    timestamp: str
    user: str
    ip: str
    port: int
    event_type: str
    raw_line: str


@dataclass(frozen=True)
class MitreMapping:
    """Mapeamento de um evento SSH para uma técnica MITRE ATT&CK.

    Attributes:
        technique_id: identificador da técnica (ex: "T1110").
        technique_name: nome da técnica (ex: "Brute Force").
        sub_technique_id: identificador da sub-técnica, quando aplicável.
        sub_technique_name: nome da sub-técnica, quando aplicável.
        tactic: tática(s) ATT&CK associada(s).
    """

    technique_id: str
    technique_name: str
    sub_technique_id: Optional[str]
    sub_technique_name: Optional[str]
    tactic: str


@dataclass(frozen=True)
class AnalisadorResult:
    """Resultado completo da análise de um ficheiro de log.

    Attributes:
        source: identificador da fonte de dados (caminho do ficheiro ou "stdin").
        total_events: número total de eventos SSH parseados.
        events: lista de eventos serializados, ordenada por carimbo de hora.
        techniques: lista de mapeamentos MITRE, um por evento, mesma ordem.
    """

    source: str
    total_events: int
    events: list[dict]
    techniques: list[dict]
