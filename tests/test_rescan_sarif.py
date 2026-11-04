"""Rescan gate (4th gate) + SARIF output. Skip rescan when semgrep absent."""

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import RunReport
from autopatch.alerts import Alert, load_alerts
from autopatch.config import Config
from autopatch.patcher import FilePatch, PatchResult
from autopatch.sandbox import verify
from autopatch.sarif_out import reports_to_sarif

MD5_RULE = "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"
SRC = "import hashlib\n\n\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"


def _repo(tmp_path) -> Path:
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "mod.py").write_text(SRC)
    (repo / "tests" / "test_mod.py").write_text(
        "from mod import h\n\n\ndef test_h():\n    assert len(h('x')) == 64\n")  # sha256 already expected
    return repo


def _patch(to_sha256: bool) -> PatchResult:
    patched = SRC.replace("md5", "sha256") if to_sha256 else SRC.replace("h(p)", "h(p)  # touched")
    return PatchResult(
        files=[FilePatch("mod.py", SRC, patched)],
        test_file="tests/test_autopatch_h.py",
        test_code="from mod import h\n\n\ndef test_sha256_len():\n    assert len(h('x')) == 64\n",
        explanation="x", source="meta-llm")


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_rescan_gate_proves_alert_gone(tmp_path):
    repo = _repo(tmp_path)
    alert = Alert(id="r1", rule=MD5_RULE, severity="medium", file="mod.py", line=5,
                  message="md5", cwe="CWE-327")
    v = verify(repo, _patch(True), cfg=Config(rescan=True), alert=alert)
    assert v.verified, v.reasons
    assert any("re-scan: scanner no longer reports" in r for r in v.reasons)


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
def test_rescan_gate_rejects_cosmetic_patch(tmp_path):
    repo = _repo(tmp_path)
    alert = Alert(id="r1", rule=MD5_RULE, severity="medium", file="mod.py", line=5,
                  message="md5", cwe="CWE-327")
    # Cosmetic change: regression test here can't pass gate 2 on md5 (len 32),
    # so use a patch that passes gates 1-3 but keeps md5 reachable: wrap it.
    patch = PatchResult(
        files=[FilePatch("mod.py", SRC,
                         "import hashlib\n\n\ndef h(p):\n"
                         "    return hashlib.sha256(p.encode()).hexdigest()\n\n\n"
                         "def _legacy(p):\n    return hashlib.md5(p.encode()).hexdigest()\n")],
        test_file="tests/test_autopatch_h.py",
        test_code="from mod import h\n\n\ndef test_sha256_len():\n    assert len(h('x')) == 64\n",
        explanation="x", source="meta-llm")
    v = verify(repo, patch, cfg=Config(rescan=True), alert=alert)
    assert not v.verified
    assert any("re-scan: scanner still reports" in r for r in v.reasons)


def test_sarif_shape(tmp_path):
    alert = Alert(id="a1", rule="py/sql-injection", severity="critical",
                  file="app.py", line=9, message="sqli", cwe="CWE-89")
    rep = RunReport(alert, "verified-pr", "fixed", pr={"diff": "-a\n+b\n"},
                    verdict_reasons=["ok"], attempts=1, patch_source="meta-llm")
    sarif = reports_to_sarif([rep])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AutoPatch"
    res = run["results"][0]
    assert res["ruleId"] == "py/sql-injection" and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 9
    assert res["properties"]["autopatchVerifiedDiff"] == "-a\n+b\n"
    p = tmp_path / "out.sarif"
    p.write_text(json.dumps(sarif))
    back = load_alerts(p)  # our own SARIF loader reads it back
    assert back and back[0].rule == "py/sql-injection"
