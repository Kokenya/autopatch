"""Stage 1: structure-aware spans. Large files are patched by splicing only
the enclosing definition; every line outside the span stays byte-identical."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import Alert
from autopatch.context import enclosing_span
from autopatch.llm import MetaLLM

PY = """import os
import sqlite3


def helper(x):
    return x * 2


class Store:
    def find(self, name):
        q = f"SELECT * FROM t WHERE n = '{name}'"
        return q

    def other(self):
        return 1
"""

JS = """import express from 'express';

export function render(name) {
  return '<div>' + name + '</div>';
}

export const twice = (n) => {
  return n * 2;
};
"""


def test_python_span_is_innermost_def_with_imports():
    span = enclosing_span(PY, 11, "python")
    assert span is not None
    assert span.extract(PY).startswith("    def find(self, name):")
    assert "import sqlite3" in span.header
    out = span.splice(PY, span.extract(PY).replace("f\"SELECT", "\"SELECT"))
    assert out.splitlines()[:9] == PY.splitlines()[:9]  # prefix untouched


def test_js_span_brace_balance():
    span = enclosing_span(JS, 4, "javascript")
    assert span is not None
    assert span.start == 3 and span.end == 5
    assert "render" in span.extract(JS)


class FakeSpanLLM(MetaLLM):
    def __init__(self):
        self.key, self.base, self.model = "fake", "", "fake"
        self.saw_prompt = ""

    def chat(self, system, user, timeout=120):
        self.saw_prompt = user
        assert "patched_snippet" in system
        return json.dumps({
            "patched_snippet": (
                "def find_user(name):\n"
                "    cur = _db.cursor()\n"
                "    cur.execute(\"SELECT name FROM users WHERE name = ?\", (name,))\n"
                "    return cur.fetchone()\n"),
            "test_code": ("from big import find_user\n\n\n"
                          "def test_sqli():\n    assert find_user(\"' OR '1'='1\") is None\n"),
            "explanation": "parameterized",
        })


def test_large_file_patched_via_span(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    filler = "".join(f"def filler_{i}():\n    return {i}\n\n\n" for i in range(150))
    big = ("import sqlite3\n\n_db = sqlite3.connect(':memory:')\n"
           "_db.execute(\"CREATE TABLE users (name TEXT)\")\n"
           "_db.execute(\"INSERT INTO users VALUES ('alice')\")\n\n\n"
           + filler
           + "def find_user(name):\n    cur = _db.cursor()\n"
             "    cur.execute(f\"SELECT name FROM users WHERE name = '{name}'\")\n"
             "    return cur.fetchone()\n")
    (repo / "big.py").write_text(big)
    (repo / "tests" / "test_big.py").write_text(
        "from big import find_user\n\n\ndef test_alice():\n    assert find_user('alice') == ('alice',)\n")
    line = big.splitlines().index("def find_user(name):") + 2
    alert = Alert(id="big-1", rule="py/sql-injection", severity="critical",
                  file="big.py", line=line, message="sqli", cwe="CWE-89")
    llm = FakeSpanLLM()

    rep = remediate(repo, alert, llm=llm)

    assert rep.status == "verified-pr", rep.detail
    assert "Definition to patch" in llm.saw_prompt
    assert "filler_149" not in llm.saw_prompt  # whole file was NOT sent
    import subprocess
    show = subprocess.run(["git", "show", f"{rep.pr['branch']}:big.py"], cwd=repo,
                          capture_output=True, text=True).stdout
    assert ", (name,)" in show and "def filler_149" in show  # splice kept the rest
