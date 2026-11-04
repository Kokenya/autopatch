"""Retry loop: a sandbox-rejected LLM patch is regenerated with feedback."""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import load_alerts
from autopatch.llm import MetaLLM
from autopatch.patcher import _fix_sql_injection

DEMO = Path(__file__).resolve().parents[1] / "examples" / "vuln_demo"

GOOD_TEST = (
    "from app import find_user\n\n"
    "def test_sqli():\n    assert find_user(\"' OR '1'='1\") is None\n"
)
VACUOUS_TEST = "def test_nothing():\n    assert True\n"


class FakeLLM(MetaLLM):
    """First reply: correct patch but vacuous test (must be rejected).
    Second reply (after feedback): correct patch + real regression test."""

    def __init__(self, source: str):
        self.key, self.base, self.model = "fake", "", "fake-model"
        self._patched = _fix_sql_injection(source)
        self.prompts: list[str] = []

    def chat(self, system: str, user: str, timeout: int = 120) -> str:
        self.prompts.append(user)
        test = GOOD_TEST if "REJECTED" in user else VACUOUS_TEST
        return json.dumps({"patched_file": self._patched, "test_code": test,
                           "explanation": "parameterized query"})


def test_retry_with_feedback(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    alert = load_alerts(DEMO / "alerts.json")[0]
    llm = FakeLLM((repo / "app.py").read_text())

    rep = remediate(repo, alert, llm=llm)

    assert rep.status == "verified-pr", rep.detail
    assert "attempt 2" in rep.detail
    assert len(llm.prompts) == 2
    assert "does not prove the bug" in llm.prompts[1]
