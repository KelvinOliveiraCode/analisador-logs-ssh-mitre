"""Parser de linhas de log SSH (auth.log / secure).

Extrai carimbo de hora, utilizador, endereço IP e porta de linhas
típicas do syslog geradas pelo ``sshd``.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .models import SshEvent

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

_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
_PORT = r"(?P<port>\d+)"
_USER = r"(?P<user>\S+)"

_HEADER_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[(?P<pid>\d+)\]:"
)

_FAILED_INVALID_RE = re.compile(
    r"Failed password for invalid user " + _USER + r" from " + _IP + r" port " + _PORT + r" ssh2"
)

_FAILED_RE = re.compile(
    r"Failed password for " + _USER + r" from " + _IP + r" port " + _PORT + r" ssh2"
)

_ACCEPTED_RE = re.compile(
    r"Accepted password for " + _USER + r" from " + _IP + r" port " + _PORT + r" ssh2"
)

# Ordem intencional: "invalid user" é um subcontexto de "failed password";
# o padrão mais específico deve ser testado primeiro.
_PATTERNS = (
    (_FAILED_INVALID_RE, "invalid_user"),
    (_FAILED_RE, "failed_password"),
    (_ACCEPTED_RE, "accepted_password"),
)


def _timestamp_key(month: str, day: str, time: str) -> tuple[int, int, str]:
    """Chave de ordenação determinística para um carimbo de hora do syslog."""
    return (_MONTHS.get(month, 0), int(day), time)


def parse_line(line: str) -> Optional[SshEvent]:
    """Parseia uma única linha de log SSH.

    Args:
        line: linha de texto do ficheiro de log.

    Returns:
        Um :class:`SshEvent` quando a linha corresponde a um padrão
        reconhecido, ``None`` caso contrário.
    """
    header = _HEADER_RE.match(line)
    if header is None:
        return None

    timestamp = f"{header.group('month')} {header.group('day')} {header.group('time')}"

    for pattern, event_type in _PATTERNS:
        match = pattern.search(line)
        if match is None:
            continue
        return SshEvent(
            timestamp=timestamp,
            user=match.group("user"),
            ip=match.group("ip"),
            port=int(match.group("port")),
            event_type=event_type,
            raw_line=line.rstrip("\n"),
        )

    return None


def parse_log(lines: Iterable[str]) -> list[SshEvent]:
    """Parseia um iterável de linhas de log.

    Args:
        lines: linhas de texto do ficheiro de log.

    Returns:
        Lista de eventos SSH extraídos, na ordem em que aparecem no ficheiro.
        Linhas irreconhecíveis são ignoradas silenciosamente.
    """
    events: list[SshEvent] = []
    for line in lines:
        event = parse_line(line)
        if event is not None:
            events.append(event)
    return events
