# BRIEF — analisador-logs-ssh-mitre

## Projeto

**Nome:** analisador-logs-ssh-mitre
**Área:** Cibersegurança
**Objetivo:** Parsear logs SSH e mapear eventos para técnicas MITRE ATT&CK,
emitindo JSON determinístico.
**Stack:** Python, regex, JSON (sem dependências externas).

## Entregas

| Caminho | Conteúdo |
|---------|----------|
| `pyproject.toml` | Metadados do projeto, ponto de entrada CLI (`analisador-ssh-mitre`), build setuptools |
| `src/analisador_ssh_mitre/__init__.py` | Exportação pública do pacote |
| `src/analisador_ssh_mitre/models.py` | Modelos de dados (`SshEvent`, `MitreMapping`, `AnalisadorResult`) |
| `src/analisador_ssh_mitre/parser.py` | Parser de linhas de log SSH (failed password, accepted password, invalid user) |
| `src/analisador_ssh_mitre/mitre.py` | Mapeamento de eventos para técnicas MITRE ATT&CK |
| `src/analisador_ssh_mitre/analisador.py` | Análise principal + emissão de JSON determinístico |
| `src/analisador_ssh_mitre/__main__.py` | CLI (arquivo ou stdin, opção `--fonte`) |
| `tests/conftest.py` | Fixture de log sintético |
| `tests/test_parser.py` | Testes do parser |
| `tests/test_mitre.py` | Testes do mapeamento MITRE |
| `tests/test_analisador.py` | Testes do analisador e do JSON |
| `README.md` | Documentação completa bilíngue PT-BR + EN |
| `BRIEF.md` | Este documento |

## Critérios de aceitação (do PLANO_50_PROJETOS.md)

- [x] Saída JSON ATT&CK com técnica, sub-técnica e tática por evento
- [x] Suíte pytest que passa (17 testes, logs sintéticos)
- [x] README PT-BR + EN completo (título, descrição, como usar, testes, licença MIT, autor)

## Como verificar

1. Instalar o pacote em modo editável:
   ```bash
   pip install -e .
   ```
2. Executar os testes:
   ```bash
   python -m pytest -q
   ```
   Resultado esperado: `17 passed`.
3. Executar a CLI sobre um ficheiro de log:
   ```bash
   python -m analisador_ssh_mitre caminho/do/auth.log --fonte auth.log
   ```
   Deve imprimir um JSON válido com as chaves `source`, `total_events`,
   `events` e `techniques`, ordenado por carimbo de hora.
4. Conferir determinismo: executar duas vezes o mesmo input e comparar as
   saídas (devem ser idênticas).

## Autor

Kelvin Oliveira
