"""Product-grade paths: JS runner, dependency CVE bump, baseline-aware gate 3,
robust SARIF parsing, sandbox env scrub, dedup. All offline/deterministic."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import Alert, dedup_alerts, load_alerts
from autopatch.llm import MetaLLM
from autopatch.patcher import FilePatch, PatchResult
from autopatch.sandbox import verify


def _offline() -> MetaLLM:
    llm = MetaLLM()
    llm.key = ""
    return llm


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# --- dependency CVE bump (no LLM) -------------------------------------------------

def test_dependency_bump_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "flask==2.0.0\nrequests>=2.28\n")
    _write(repo / "app.py", "def ok():\n    return 1\n")
    _write(repo / "tests/test_app.py", "from app import ok\n\n\ndef test_ok():\n    assert ok() == 1\n")
    alert = Alert(id="dep-1", rule="CVE-2023-30861", severity="high",
                  file="requirements.txt", line=1, message="flask session cookie vuln",
                  cwe="CWE-539", package="flask", fixed_version="2.2.5")

    rep = remediate(repo, alert, llm=_offline())

    assert rep.status == "verified-pr", rep.detail
    assert rep.patch_source == "dependency-bump"
    import subprocess
    show = subprocess.run(["git", "show", f"{rep.pr['branch']}:requirements.txt"],
                          cwd=repo, capture_output=True, text=True)
    assert "flask>=2.2.5" in show.stdout


# --- baseline-aware gate 3 ---------------------------------------------------------

def test_baseline_failures_do_not_block(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "mod.py", "def greet(name):\n    return 'hi ' + name\n")
    _write(repo / "tests/test_mod.py",
           "from mod import greet\n\n\ndef test_greet():\n    assert greet('a') == 'hi a'\n\n\n"
           "def test_preexisting_broken():\n    assert False, 'was already red'\n")
    original = (repo / "mod.py").read_text()
    # Behavior-preserving for valid input: test_greet keeps passing.
    patch = PatchResult(
        files=[FilePatch("mod.py", original,
                         "def greet(name):\n    return 'hi ' + name.replace('!', '')\n")],
        test_file="tests/test_autopatch_x.py",
        test_code=("from mod import greet\n\n\ndef test_bang_stripped():\n"
                   "    assert greet('a!') == 'hi a'\n"),
        explanation="x", source="rule-fallback")

    v = verify(repo, patch)

    assert v.verified, v.reasons
    assert any("no new suite failures" in r for r in v.reasons)


def test_new_failure_is_rejected(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "mod.py", "def greet(name):\n    return 'hi ' + name\n")
    _write(repo / "tests/test_mod.py",
           "from mod import greet\n\n\ndef test_greet():\n    assert greet('a') == 'hi a'\n")
    original = (repo / "mod.py").read_text()
    patch = PatchResult(
        files=[FilePatch("mod.py", original, original.replace("'hi '", "'hello '"))],
        test_file="tests/test_autopatch_x.py",
        test_code=("from mod import greet\n\n\ndef test_new_greeting():\n"
                   "    assert greet('a') == 'hello a'\n"),
        explanation="x", source="rule-fallback")

    v = verify(repo, patch)

    assert not v.verified
    assert any("breaks" in r or "new test failures" in r for r in v.reasons)


# --- env scrub: secrets must not reach repo tests ---------------------------------

def test_sandbox_does_not_leak_env(tmp_path, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "sekrit")
    repo = tmp_path / "repo"
    _write(repo / "mod.py", "VALUE = 1\n")
    _write(repo / "tests/test_mod.py", "def test_ok():\n    assert True\n")
    patch = PatchResult(
        files=[FilePatch("mod.py", "VALUE = 1\n", "VALUE = 2\n")],
        test_file="tests/test_autopatch_x.py",
        test_code=("import os\n\n\ndef test_no_secret_and_patched():\n"
                   "    assert os.environ.get('META_API_KEY') is None\n"
                   "    from mod import VALUE\n    assert VALUE == 2\n"),
        explanation="x", source="rule-fallback")

    v = verify(repo, patch)

    assert v.verified, v.reasons  # would fail at gate 2 if the secret leaked


# --- JS runner with a fake LLM ------------------------------------------------------

class _FakeJSLLM(MetaLLM):
    def __init__(self):
        self.key, self.base, self.model = "fake", "", "fake"

    def chat(self, system, user, timeout=120):
        return json.dumps({
            "patched_files": {"src/util.mjs":
                "export function greet(name) {\n  return 'hello ' + String(name).replace(/[<>&]/g, '');\n}\n"},
            "test_code": (
                "import { test } from 'node:test';\nimport assert from 'node:assert/strict';\n"
                "import { greet } from './util.mjs';\n\n"
                "test('xss payload stripped', () => {\n"
                "  assert.equal(greet('<b>a</b>'), 'hello ba/b');\n});\n"),
            "explanation": "strip html metacharacters",
        })


def test_javascript_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "package.json", json.dumps(
        {"name": "x", "type": "module", "scripts": {"test": "node --test src/"}}))
    _write(repo / "src/util.mjs",
           "export function greet(name) {\n  return 'hello ' + name;\n}\n")
    _write(repo / "src/base.test.mjs",
           "import { test } from 'node:test';\nimport assert from 'node:assert/strict';\n"
           "import { greet } from './util.mjs';\n"
           "test('plain', () => { assert.equal(greet('bob'), 'hello bob'); });\n")
    alert = Alert(id="js-1", rule="js/xss", severity="high", file="src/util.mjs",
                  line=2, message="unsanitized html", cwe="CWE-79")

    rep = remediate(repo, alert, llm=_FakeJSLLM())

    assert rep.status == "verified-pr", rep.detail
    import subprocess
    show = subprocess.run(["git", "show", f"{rep.pr['branch']}:src/util.mjs"],
                          cwd=repo, capture_output=True, text=True)
    assert "replace(" in show.stdout


# --- robust SARIF + dedup ------------------------------------------------------------

def test_sarif_robust_and_dedup(tmp_path):
    sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "py/sql-injection", "level": "error", "message": {"text": "CWE-89 bad"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                             "region": {"startLine": 3}}}]},
        {"ruleId": "broken/no-loc", "message": {"text": "x"}},          # no locations -> skipped
        {"message": {"text": "no rule id"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}}}]},
    ]}]}
    p = tmp_path / "in.sarif"
    p.write_text(json.dumps(sarif))
    alerts = load_alerts(p)
    assert len(alerts) == 2
    assert alerts[0].cwe == "CWE-89" and alerts[0].severity == "high"
    assert dedup_alerts(alerts + alerts) == alerts
