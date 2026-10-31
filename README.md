# analisador-logs-ssh-mitre

[English](README.en.md) · **Português (Brasil)**

[![Python 3](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#) [![pytest](https://img.shields.io/badge/pytest-17%20testes-0A9EDC?style=flat-square&logo=pytest)](#) [![MIT License](https://img.shields.io/badge/License-MIT-f4c430?style=flat-square)](LICENSE)

## O que é

**Analisador de logs SSH com mapeamento MITRE ATT&CK**: parseia logs de autenticação SSH, extrai **eventos** (login falho, sucesso, desconexão) e mapeia cada um para **técnicas MITRE ATT&CK**. Saída em JSON. É um laboratório educacional de segurança ofensiva/defensiva.

## ⚠️ Aviso de uso ético e legal

Use apenas em logs próprios ou com autorização expressa do proprietário. O mapeamento MITRE é educacional — não substitui uma análise forense profissional.

## Status

Laboratório educacional funcional e testado (17 testes).

## Funcionalidades

- **Parse de log SSH** (`parser.py`): `parse_line` → `SshEvent` com timestamp, origem, destino, status (Failed/Accepted/Disconnected/Other).
- **Mapeamento MITRE** (`mitre.py`): `map_event` → `MitreMapping` com técnica, tática e ID associados (ex.: T1110 Brute Force, T1078 Valid Accounts).
- **Análise** (`analisador.py`): agregar eventos por IP, contar tentativas, gerar resultado em JSON.
- **CLI**: `analisador-ssh-mitre <arquivo.log>` ou pipe stdin.

## Arquitetura

Pacote `analisador_ssh_mitre` com módulos: `parser` (parse do log), `models` (dataclasses SshEvent/MitreMapping), `mitre` (mapeamento), `analisador` (agregação/JSON).

## Stack

- Python ≥ 3.10, stdlib apenas
- pytest (dev)

## Estrutura do repositório

```
analisador-logs-ssh-mitre/
├── pyproject.toml · BRIEF.md
├── src/analisador_ssh_mitre/
│   ├── parser.py     # parse de log SSH
│   ├── models.py     # dataclasses
│   ├── mitre.py      # mapeamento MITRE ATT&CK
│   ├── analisador.py # agregação/JSON
│   └── __main__.py   # CLI
├── tests/            # 17 testes
└── LICENSE           # MIT
```

## Pré-requisitos e instalação

```bash
pip install -e .
```

## Como executar

```bash
analisador-ssh-mitre /var/log/auth.log
cat /var/log/auth.log | analisador-ssh-mitre
```

## Testes e qualidade

```bash
PYTHONPATH=src python -m pytest tests/
# 17 passed
```

## Decisões técnicas e trade-offs

- Parser específico para logs SSH: simples e direto; não cobre syslog genérico nem formatos não padronizados.
- Stdlib: zero dependências; em troca, sem suporte a regex avançado ou machine learning.

## Limitações conhecidas

- Parse específico para logs de autenticação SSH estilo syslog; outros formatos de log não funcionam.
- O mapeamento MITRE é uma aproximação educacional — a atribuição real depende de contexto adicional.

## Processo de desenvolvimento

Projeto individual de Kelvin Oliveira, construído com agentes de IA orquestrados e revisado pelo autor.

## Licença e autor

MIT — Copyright (c) 2026 Kelvin Rebelo de Oliveira. Autor: [Kelvin Oliveira](https://github.com/KelvinOliveiraCode) · [Portfólio](https://kelvinoliveiracode.github.io/portfolio/)
