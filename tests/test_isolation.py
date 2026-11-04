"""Stage 3: remediation must never touch the operator's live working tree."""

import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.agent import remediate
from autopatch.alerts import load_alerts
from autopatch.llm import MetaLLM

DEMO = Path(__file__).resolve().parents[1] / "examples" / "vuln_demo"


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


def test_uncommitted_work_survives_remediation(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    _git(repo, "init", "-b", "main")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "base")

    # Operator's uncommitted work, on a feature branch:
    _git(repo, "checkout", "-b", "my-feature")
    (repo / "notes.txt").write_text("work in progress, do not lose\n")
    (repo / "app.py").write_text((repo / "app.py").read_text() + "\n# local tweak\n")

    llm = MetaLLM()
    llm.key = ""
    alert = load_alerts(DEMO / "alerts.json")[0]
    rep = remediate(repo, alert, llm=llm)

    assert rep.status == "verified-pr", rep.detail
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "my-feature"
    assert (repo / "notes.txt").read_text() == "work in progress, do not lose\n"
    assert (repo / "app.py").read_text().endswith("# local tweak\n")
    status = _git(repo, "status", "--porcelain").stdout
    assert "notes.txt" in status and "app.py" in status  # still dirty, untouched


def test_rerun_is_skipped_not_duplicated(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(DEMO, repo, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    llm = MetaLLM()
    llm.key = ""
    alert = load_alerts(DEMO / "alerts.json")[0]

    first = remediate(repo, alert, llm=llm)
    second = remediate(repo, alert, llm=llm)

    assert first.status == "verified-pr"
    assert second.status == "skipped"
    assert "already exists" in second.detail
