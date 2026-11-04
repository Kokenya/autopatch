"""Learnings from the first real-world PR review (replayr #456, closed unmerged):
test placement follows the target's own suite; false positives are triaged,
not cosmetically 'fixed'."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import Alert
from autopatch.config import Config
from autopatch.llm import MetaLLM
from autopatch.runner import detect_runner


def test_test_file_lands_in_components_own_tests_dir(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tools" / "home-reader" / "home_reader").mkdir(parents=True)
    (repo / "tools" / "home-reader" / "tests").mkdir(parents=True)
    (repo / "tools" / "home-reader" / "home_reader" / "net.py").write_text("x = 1\n")
    (repo / "tests").mkdir()  # root tests exists too; nearest must win

    runner = detect_runner(repo, "tools/home-reader/home_reader/net.py", Config())

    assert runner.test_file_for("semgrep-0", "tools/home-reader/home_reader/net.py") == \
        "tools/home-reader/tests/test_autopatch_semgrep_0.py"


class _FalsePositiveLLM(MetaLLM):
    def __init__(self):
        self.key, self.base, self.model = "fake", "", "fake"

    def chat(self, system, user, timeout=120):
        assert "false_positive" in system
        return json.dumps({"false_positive": "TLS socket is already wrapped with a verifying context above the flagged call"})


def test_false_positive_is_reported_not_patched(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "app.py").write_text("def ok():\n    return 1\n")
    (repo / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n")
    alert = Alert(id="fp-1", rule="audit/httpsconnection", severity="medium",
                  file="app.py", line=1, message="audit", cwe="CWE-295")

    rep = remediate(repo, alert, llm=_FalsePositiveLLM())

    assert rep.status == "false-positive"
    assert "already wrapped" in rep.detail
    assert not rep.pr  # no branch, no PR
