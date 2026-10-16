"""Analisador de logs SSH com mapeamento MITRE ATT&CK."""

from .analisador import AnalisadorResult, analyze, to_json
from .mitre import MITRE_MAP, map_event
from .models import MitreMapping, SshEvent
from .parser import parse_log, parse_line

__all__ = [
    "AnalisadorResult",
    "MitreMapping",
    "SshEvent",
    "MITRE_MAP",
    "analyze",
    "map_event",
    "parse_line",
    "parse_log",
    "to_json",
]
