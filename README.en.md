# analisador-logs-ssh-mitre

**English** · [Português (Brasil)](README.md)

[![Python 3](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#) [![pytest](https://img.shields.io/badge/pytest-17%20tests-0A9EDC?style=flat-square&logo=pytest)](#) [![MIT License](https://img.shields.io/badge/License-MIT-f4c430?style=flat-square)](LICENSE)

## What it is

**SSH log analyser with MITRE ATT&CK mapping**: it parses SSH authentication logs, extracts **events** (failed login, success, disconnect) and maps each one to **MITRE ATT&CK techniques**. Output is JSON. It is an educational offensive/defensive security lab.

## ⚠️ Ethical and legal use warning

Use only on your own logs or with the owner's express authorisation. The MITRE mapping is educational — it does not replace a professional forensic analysis.

## Status

An educational lab, working and tested (17 tests).

## Features

- **SSH log parsing** (`parser.py`): `parse_line` → `SshEvent` with timestamp, source, destination, status (Failed/Accepted/Disconnected/Other).
- **MITRE mapping** (`mitre.py`): `map_event` → `MitreMapping` with technique, tactic and associated ID (e.g. T1110 Brute Force, T1078 Valid Accounts).
- **Analysis** (`analisador.py`): aggregate events by IP, count attempts, produce JSON output.
- **CLI**: `analisador-ssh-mitre <logfile>` or piped via stdin.

## Architecture

An `analisador_ssh_mitre` package with modules: `parser` (log parsing), `models` (SshEvent/MitreMapping dataclasses), `mitre` (mapping), `analisador` (aggregation/JSON).

## Stack

- Python ≥ 3.10, stdlib only
- pytest (dev)

## Repository layout

```
analisador-logs-ssh-mitre/
├── pyproject.toml · BRIEF.md
├── src/analisador_ssh_mitre/
│   ├── parser.py     # SSH log parsing
│   ├── models.py     # dataclasses
│   ├── mitre.py      # MITRE ATT&CK mapping
│   ├── analisador.py # aggregation/JSON
│   └── __main__.py   # CLI
├── tests/            # 17 tests
└── LICENSE           # MIT
```

## Prerequisites and installation

```bash
pip install -e .
```

## How to run

```bash
analisador-ssh-mitre /var/log/auth.log
cat /var/log/auth.log | analisador-ssh-mitre
```

## Tests and quality

```bash
PYTHONPATH=src python -m pytest tests/
# 17 passed
```

## Technical decisions and trade-offs

- SSH-specific log parser: simple and direct; does not cover generic syslog or non-standard formats.
- Stdlib: zero dependencies; in exchange, no advanced regex or machine learning support.

## Known limitations

- Parser is specific to syslog-style SSH authentication logs; other log formats will not work.
- The MITRE mapping is an educational approximation — real attribution depends on additional context.

## Development process

An individual project by Kelvin Oliveira, built with orchestrated AI agents and reviewed by the author.

## License and author

MIT — Copyright (c) 2026 Kelvin Rebelo de Oliveira. Author: [Kelvin Oliveira](https://github.com/KelvinOliveiraCode) · [Portfolio](https://kelvinoliveiracode.github.io/portfolio/)
