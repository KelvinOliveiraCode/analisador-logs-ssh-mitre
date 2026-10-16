"""Análise principal: parseia, mapeia para MITRE e emite JSON determinístico.

O resultado é totalmente determinístico: mesmo input produz sempre o mesmo
output (ordenação estável por carimbo de hora, chaves JSON ordenadas, sem
datas de execução nem valores aleatórios).
"""

from __future__ import annotations

import json
from typing import Iterable

from .mitre import map_event
from .models import AnalisadorResult, SshEvent
from .parser import parse_log

_MONTHS = {
    name: number
    for number, name in enumerate(
        [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ],
        start=1,
    )
}


def _sort_key(event: SshEvent) -> tuple[int, int, str]:
    """Chave de ordenação estável para eventos (mês, dia, hora)."""
    month, day, time = event.timestamp.split(" ", 2)
    return (_MONTHS.get(month, 0), int(day), time)


def _event_to_dict(event: SshEvent) -> dict:
    """Serializa um :class:`SshEvent` para dicionário."""
    return {
        "timestamp": event.timestamp,
        "user": event.user,
        "ip": event.ip,
        "port": event.port,
        "event_type": event.event_type,
    }


def _mapping_to_dict(mapping) -> dict:
    """Serializa um mapeamento MITRE para dicionário."""
    return {
        "technique_id": mapping.technique_id,
        "technique_name": mapping.technique_name,
        "sub_technique_id": mapping.sub_technique_id,
        "sub_technique_name": mapping.sub_technique_name,
        "tactic": mapping.tactic,
    }


def analyze(lines: Iterable[str], source: str = "stdin") -> AnalisadorResult:
    """Analisa linhas de log SSH e devolve o resultado estruturado.

    Args:
        lines: linhas de texto do ficheiro de log.
        source: identificador da fonte (caminho do ficheiro ou "stdin").

    Returns:
        :class:`AnalisadorResult` com eventos e mapeamentos, ordenado por
        carimbo de hora.
    """
    events = parse_log(lines)
    events.sort(key=_sort_key)

    event_dicts = [_event_to_dict(event) for event in events]
    technique_dicts = [_mapping_to_dict(map_event(event)) for event in events]

    return AnalisadorResult(
        source=source,
        total_events=len(events),
        events=event_dicts,
        techniques=technique_dicts,
    )


def to_json(result: AnalisadorResult) -> str:
    """Serializa o resultado em JSON determinístico (ordenado, sem NaN).

    Args:
        result: resultado da análise.

    Returns:
        String JSON com as chaves ordenadas e terminada por nova linha.
    """
    payload = {
        "source": result.source,
        "total_events": result.total_events,
        "events": result.events,
        "techniques": result.techniques,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
