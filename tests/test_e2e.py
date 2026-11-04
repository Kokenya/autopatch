"""End-to-end: vulnerable demo repo -> verified PR branch, fully offline.

The LLM is disabled on purpose (empty key) so the suite is deterministic
and never spends API credits; the live-LLM path is exercised by demo.sh.
"""

import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import load_alerts
from autopatch.llm import MetaLLM

DEMO = Path(__file__).resolve().parents[1] / "examples" / "vuln_demo"


def _offline_llm() -> MetaLLM:
    llm = MetaLLM()
    llm.key = ""  # force the deterministic rule-fallback path
    return llm


def _setup_repo(tmp_path, name):
    repo = tmp_path / name
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    return repo


def test_sqli_remediation(tmp_path):
    repo = _setup_repo(tmp_path, "repo_sqli")
    alert = load_alerts(DEMO / "alerts.json")[0]

    rep = remediate(repo, alert, llm=_offline_llm())

    assert rep.status == "verified-pr", rep.detail
    assert len(rep.verdict_reasons) == 3
    branch = rep.pr["branch"]
    show = subprocess.run(["git", "show", f"{branch}:app.py"], cwd=repo,
                          capture_output=True, text=True)
    assert ", (name,)" in show.stdout and "f\"" not in show.stdout.split("find_user")[1].split("return")[0]
    assert Path(rep.pr["pr_body_file"]).exists()


def test_path_traversal_remediation(tmp_path):
    repo = _setup_repo(tmp_path, "repo_path")
    alert = load_alerts(DEMO / "alerts.json")[1]
    assert alert.kind == "path-traversal"

    rep = remediate(repo, alert, llm=_offline_llm())

    assert rep.status == "verified-pr", rep.detail
    assert len(rep.verdict_reasons) == 3
    show = subprocess.run(["git", "show", f"{rep.pr['branch']}:app.py"], cwd=repo,
                          capture_output=True, text=True)
    assert "_autopatch_safe_join(DOCS, name)" in show.stdout
    assert Path(rep.pr["pr_body_file"]).exists()
