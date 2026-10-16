"""Interface de linha de comando do analisador de logs SSH."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analisador import analyze, to_json


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada da CLI.

    Args:
        argv: argumentos da linha de comando (padrão: ``sys.argv[1:]``).

    Returns:
        Código de saída do processo (0 em caso de sucesso).
    """
    parser = argparse.ArgumentParser(
        description="Analisa logs SSH e mapeia eventos para técnicas MITRE ATT&CK."
    )
    parser.add_argument(
        "arquivo",
        nargs="?",
        type=Path,
        help="Caminho do ficheiro de log (padrão: leitura do stdin).",
    )
    parser.add_argument(
        "--fonte",
        default="stdin",
        help="Nome da fonte reportado no JSON de saída (padrão: stdin).",
    )
    args = parser.parse_args(argv)

    if args.arquivo is None:
        text = sys.stdin.read()
        source = args.fonte
    else:
        text = args.arquivo.read_text(encoding="utf-8")
        source = str(args.arquivo)

    result = analyze(text.splitlines(), source=source)
    print(to_json(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
