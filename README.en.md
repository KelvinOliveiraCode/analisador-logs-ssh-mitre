# analisador-logs-ssh-mitre

SSH log analyzer that maps events to MITRE ATT&CK techniques. Emits deterministic JSON, ready for consumption by cybersecurity tools.

Stack: Python, regex, JSON. No external dependencies. Requires Python 3.10 or higher.

## What it does

Reads SSH log lines (syslog format, `auth.log` or `secure`) and recognizes three patterns:

| Line pattern | Meaning | MITRE technique |
|---|---|---|
| `Failed password for invalid user <user> from <ip> port <port> ssh2` | Attempt with nonexistent user | T1110 Brute Force / T1110.001 Password Guessing |
| `Failed password for <user> from <ip> port <port> ssh2` | Failed password for existing user | T1110 Brute Force / T1110.001 Password Guessing |
| `Accepted password for <user> from <ip> port <port> ssh2` | Successful password authentication | T1078 Valid Accounts |

Lines that do not match these patterns (for example, `Accepted publickey`, `Connection closed`) are ignored.

The output is JSON ordered by timestamp, with sorted keys, no execution timestamps and no random values: the same input always produces the same output.

## How to use

Installation:

```bash
pip install -e .
```

CLI execution (reads from a file):

```bash
python -m analisador_ssh_mitre path/to/auth.log --fonte auth.log
```

Or reading from stdin:

```bash
cat path/to/auth.log | python -m analisador_ssh_mitre --fonte auth.log
```

Example JSON output:

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

Python API:

```python
from analisador_ssh_mitre import analyze, to_json

with open("auth.log", encoding="utf-8") as f:
    resultado = analyze(f, source="auth.log")
print(to_json(resultado))
```

The `analyze` function accepts an iterable of lines (for example, the list returned by `splitlines()` or the file object itself) and `source` is the source identifier reported in the JSON output.

## Tests

The project uses `pytest` with synthetic logs. To run:

```bash
python -m pytest -q
```

Expected result: 17 tests approved in 3 modules (`test_parser`, `test_mitre`, `test_analisador`).

## MITRE ATT&CK techniques mapped

| Event | Technique ID | Technique name | Sub-technique | Tactic |
|---|---|---|---|---|
| failed_password | T1110 | Brute Force | T1110.001 Password Guessing | Credential Access |
| invalid_user | T1110 | Brute Force | T1110.001 Password Guessing | Credential Access |
| accepted_password | T1078 | Valid Accounts | — | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

## License

MIT

## Author

Kelvin Oliveira
