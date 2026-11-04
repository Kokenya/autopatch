"""Hunt mode: buried vulns (bypassable sanitizer) + secret scanning."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.hunt import audit_file, hunt, suspicious_files
from autopatch.llm import MetaLLM
from autopatch.scanner import scan_secrets

HIDDEN = '''import sqlite3

_db = sqlite3.connect(":memory:")
_db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
_db.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])


def clean(value):
    # Strip quotes so the value is "safe" to interpolate.
    return str(value).replace("'", "").replace('"', "")


def find_by_id(uid):
    cur = _db.cursor()
    cur.execute("SELECT name FROM users WHERE id = " + clean(uid))
    return cur.fetchall()
'''


class FakeAuditLLM(MetaLLM):
    def __init__(self):
        self.key, self.base, self.model = "fake", "", "fake"

    def chat(self, system, user, timeout=120):
        assert "bypass" in system or "sanitizers" in system
        return json.dumps({"findings": [{
            "line": 14, "cwe": "CWE-89", "rule": "hunt/sqli-through-sanitizer",
            "severity": "critical",
            "message": "clean() strips quotes but the value lands in a numeric SQL context; '1 OR 1=1' needs no quotes",
        }]})


def _setup(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "db.py").write_text(HIDDEN)
    (repo / "tests" / "test_db.py").write_text(
        "from db import find_by_id\n\n\ndef test_one():\n    assert find_by_id('1') == [('alice',)]\n")
    return repo


def test_scoring_finds_the_buried_file(tmp_path):
    repo = _setup(tmp_path)
    files = suspicious_files(repo)
    assert files and files[0][1].name == "db.py"


def test_audit_and_hunt_dedup(tmp_path):
    repo = _setup(tmp_path)
    found = audit_file(FakeAuditLLM(), repo, repo / "db.py")
    assert len(found) == 1 and found[0].kind == "sql-injection"
    again = hunt(repo, FakeAuditLLM(), known=found)
    assert again == []  # already known to the scanner pass


def test_secret_scan_redacts_and_skips_placeholders(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "config.py").write_text(
        'API_KEY = "sk-live-9f8e7d6c5b4a39281706"\n'
        'EXAMPLE_KEY = "your_api_key_here_123456"\n'
        'AWS = "AKIAIOSFODNN7EXAMPLE"\n')
    alerts = scan_secrets(repo)
    rules = {a.rule for a in alerts}
    assert "secrets/generic-secret-assignment" in rules
    assert all("sk-live" not in a.message for a in alerts)  # value never copied out
    assert all(a.kind == "hardcoded-secret" for a in alerts)
