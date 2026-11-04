"""Regression tests for the security-hardening review findings (kit review round 1)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import Alert
from autopatch.deps import dependency_patch
from autopatch.llm import MetaLLM
from autopatch.patcher import FilePatch, PatchResult
from autopatch.paths import PathEscape, safe_join
from autopatch.sandbox import verify


def _offline():
    llm = MetaLLM()
    llm.key = ""
    return llm


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_safe_join_containment(tmp_path):
    assert safe_join(tmp_path, "a/b.py") == (tmp_path / "a/b.py").resolve()
    for bad in ("../x.py", "../../etc/passwd", "/etc/passwd", "a/../../x"):
        try:
            safe_join(tmp_path, bad)
            raise AssertionError(f"escaped: {bad}")
        except PathEscape:
            pass


def test_alert_path_traversal_rejected(tmp_path):
    """A crafted alert.file must never be read (or shipped to an LLM)."""
    repo = tmp_path / "repo"
    _write(repo / "app.py", "x = 1\n")
    _write(tmp_path / "outside.py", "SECRET = 1\n")
    alert = Alert(id="evil", rule="py/sql-injection", severity="high",
                  file="../outside.py", line=1, message="m", cwe="CWE-89")
    rep = remediate(repo, alert, llm=_offline())
    assert rep.status == "error" and "escapes" in rep.detail


def test_vacuous_marker_test_rejected(tmp_path):
    """The demonstrated exploit: patch adds MARKER, test imports it.
    Gate 1 must refuse import-error 'failures' on the vulnerable code."""
    repo = tmp_path / "repo"
    src = "def f(name):\n    return 'q=' + name\n"
    _write(repo / "app.py", src)
    _write(repo / "tests/test_app.py", "from app import f\n\n\ndef test_f():\n    assert f('a') == 'q=a'\n")
    patch = PatchResult(
        files=[FilePatch("app.py", src, src + "MARKER = 1\n")],  # vuln untouched
        test_file="tests/test_autopatch_m.py",
        test_code="from app import MARKER\n\n\ndef test_marker():\n    assert MARKER == 1\n",
        explanation="x", source="meta-llm")
    v = verify(repo, patch)
    assert not v.verified
    assert any("does not execute the bug" in r for r in v.reasons)


def test_deps_injection_blocked(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "flask==2.0.0\n")
    evil = Alert(id="d", rule="CVE-x", severity="high", file="requirements.txt",
                 line=1, message="m", package="flask",
                 fixed_version='1.0"); import os; os.system("id") #')
    assert dependency_patch(evil, repo) is None
    evil2 = Alert(id="d", rule="CVE-x", severity="high", file="../../requirements.txt",
                  line=1, message="m", package="flask", fixed_version="2.2.5")
    assert dependency_patch(evil2, repo) is None


def test_sandbox_copy_excludes_secrets(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "mod.py", "VALUE = 1\n")
    _write(repo / ".env", "SECRET=hunter2\n")
    _write(repo / "tests/test_mod.py", "def test_ok():\n    assert True\n")
    patch = PatchResult(
        files=[FilePatch("mod.py", "VALUE = 1\n", "VALUE = 2\n")],
        test_file="tests/test_autopatch_s.py",
        test_code=("import os\nfrom pathlib import Path\n\n\n"
                   "def test_no_dotenv_in_sandbox():\n"
                   "    assert not Path('.env').exists(), '.env copied into sandbox'\n"
                   "    assert 'hunter2' not in os.environ.get('SECRET', '')\n"
                   "    from mod import VALUE\n    assert VALUE == 2\n"),
        explanation="x", source="meta-llm")
    v = verify(repo, patch)
    assert v.verified, v.reasons
