# analisador-logs-ssh-mitre

Analisador de logs SSH que mapeia eventos para técnicas MITRE ATT&CK.
Emite um JSON determinístico, pronto para consumo por ferramentas de
cibersegurança.

Stack: Python, regex, JSON. Sem dependências externas.

## Descrição / Description

**PT-BR:** Lê linhas de log do SSH (formato syslog, tipo `auth.log` ou
`secure`), identifica tentativas de senha falhadas, autenticações bem-sucedidas
e usuários inválidos, extrai carimbo de hora, usuário, IP e porta, e associa
cada evento a uma técnica MITRE ATT&CK (exemplo: `T1110 Brute Force`).

**EN:** Reads SSH log lines (syslog format, `auth.log` or `secure`),
identifies failed password attempts, successful authentications, and invalid
users, extracts timestamp, user, IP, and port, and associates each event with a
MITRE ATT&CK technique (example: `T1110 Brute Force`).

## O que faz / What it does

Reconhece três padrões de linha de log:

| Padrão | Significado | Técnica MITRE |
|--------|-------------|---------------|
| `Failed password for invalid user <user> from <ip> port <port> ssh2` | Tentativa com usuário inexistente | T1110 Brute Force / T1110.001 Password Guessing |
| `Failed password for <user> from <ip> port <port> ssh2` | Senha falhada para usuário existente | T1110 Brute Force / T1110.001 Password Guessing |
| `Accepted password for <user> from <ip> port <port> ssh2` | Autenticação por senha bem-sucedida | T1078 Valid Accounts |

Linhas que não correspondem a esses padrões (exemplo: `Accepted publickey`,
`Connection closed`) são ignoradas.

A saída é um JSON ordenado por carimbo de hora, com chaves ordenadas, sem
datas de execução nem valores aleatórios: o mesmo input produz sempre o mesmo
output.

## Como usar / How to use

Instalação:

```bash
pip install -e .
```

Execução pela CLI (lê de um ficheiro):

```bash
python -m analisador_ssh_mitre caminho/do/auth.log --fonte auth.log
```

Ou leitura do stdin:

```bash
cat caminho/do/auth.log | python -m analisador_ssh_mitre --fonte auth.log
```

Exemplo de saída JSON:

```json
{
  "events": [
    {
      "event_type": "invalid_user",
      "ip": "192.168.1.10",
      "port": 22000,
      "timestamp": "Oct 10 10:23:45",
      "user": "admin"
    },
    {
      "event_type": "accepted_password",
      "ip": "10.0.0.5",
      "port": 51235,
      "timestamp": "Oct 10 10:23:46",
      "user": "ubuntu"
    }
  ],
  "source": "auth.log",
  "techniques": [
    {
      "sub_technique_id": "T1110.001",
      "sub_technique_name": "Password Guessing",
      "tactic": "Credential Access",
      "technique_id": "T1110",
      "technique_name": "Brute Force"
    },
    {
      "sub_technique_id": null,
      "sub_technique_name": null,
      "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
      "technique_id": "T1078",
      "technique_name": "Valid Accounts"
    }
  ],
  "total_events": 2
}
```

API em Python:

```python
from analisador_ssh_mitre import analyze, to_json

with open("auth.log", encoding="utf-8") as f:
    resultado = analyze(f, source="auth.log")
print(to_json(resultado))
```

## Testes / Tests

O projeto usa `pytest` com logs sintéticos. Para executar:

```bash
python -m pytest -q
```

Resultado esperado: todos os testes aprovados (17 testes em 3 módulos:
`test_parser`, `test_mitre`, `test_analisador`).

## Técnicas MITRE ATT&CK mapeadas / MITRE ATT&CK techniques mapped

| Evento | Technique ID | Technique name | Sub-technique | Tactic |
|--------|--------------|----------------|---------------|--------|
| failed_password | T1110 | Brute Force | T1110.001 Password Guessing | Credential Access |
| invalid_user | T1110 | Brute Force | T1110.001 Password Guessing | Credential Access |
| accepted_password | T1078 | Valid Accounts | — | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

## Licença / License

MIT

## Autor / Author

Kelvin Oliveira
