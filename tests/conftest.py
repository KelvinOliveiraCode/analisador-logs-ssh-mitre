"""Fixtures compartilhadas para os testes do analisador de logs SSH."""

import pytest

SAMPLE_LOG = """Oct 10 10:23:45 host sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 22000 ssh2
Oct 10 10:23:46 host sshd[1234]: Failed password for root from 10.0.0.5 port 51234 ssh2
Oct 10 10:23:47 host sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 51235 ssh2
Oct 10 10:23:48 host sshd[1234]: Accepted publickey for ubuntu from 10.0.0.5 port 51236 ssh2
Oct 10 10:23:49 host sshd[1234]: Connection closed by 10.0.0.5 port 51235 [preauth]
"""


@pytest.fixture
def sample_log():
    """Retorna as linhas do log de amostra como uma lista de strings."""
    return SAMPLE_LOG.splitlines()
