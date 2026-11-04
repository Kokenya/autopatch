"""GitHub delivery: verified patch -> branch -> commit -> Pull Request (gh).

Branch creation happens in a temporary `git worktree`, never by checking
out branches in the operator's live working tree — uncommitted work there
is untouched. Re-runs for an alert whose branch already exists are skipped.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .alerts import Alert
from .patcher import PatchResult
from .sandbox import Verdict

_GIT_ID = ["-c", "user.email=autopatch@example.dev", "-c", "user.name=AutoPatch",
           "-c", "core.hooksPath=/dev/null"]  # never run target-repo git hooks


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    import os
    env = {k: v for k, v in os.environ.items() if k != "META_API_KEY"}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args],
                          cwd=repo, capture_output=True, text=True, env=env)


def pr_body(alert: Alert, patch: PatchResult, verdict: Verdict) -> str:
    checks = "\n".join(f"- ✅ {r}" for r in verdict.reasons)
    files = "\n".join(f"- `{fp.file}`" for fp in patch.files)
    return f"""## AutoPatch: fix {alert.rule} ({alert.cwe})

**Alert:** `{alert.file}:{alert.line}` — {alert.message}
**Severity:** {alert.severity} · **Patch source:** {patch.source}

{patch.explanation}

### Changed files
{files}
- `{patch.test_file}` — regression test (fails before, passes after)

### Sandbox verification (isolated, pre-PR)
{checks}

### Diff
```diff
{patch.diff}```

*— AutoPatch, an autonomous vulnerability remediation agent*
"""


def open_pr(repo: Path, alert: Alert, patch: PatchResult, verdict: Verdict,
            push: bool = False) -> dict:
    """Create branch+commit locally; open a real GitHub PR when push=True and gh is authed."""
    branch = f"autopatch/{alert.id.replace('/', '-')}"
    body = pr_body(alert, patch, verdict)
    body_file = repo / ".autopatch" / f"pr-{alert.id.replace('/', '-')}.md"
    body_file.parent.mkdir(parents=True, exist_ok=True)
    body_file.write_text(body)
    result: dict = {"branch": branch, "pr_body_file": str(body_file), "pr_url": None,
                    "diff": patch.diff}

    if _git(repo, "rev-parse", "--git-dir").returncode != 0:
        _git(repo, "init", "-b", "main")
        # Baseline commit must never sweep secrets into history.
        gitignore = repo / ".gitignore"
        existing = gitignore.read_text() if gitignore.is_file() else ""
        gitignore.write_text(existing + "\n.env\n.env.*\n*.pem\n*.key\nid_rsa*\nid_ed25519*\n")
        _git(repo, *_GIT_ID, "add", "-A")
        _git(repo, *_GIT_ID, "commit", "-m", "import: baseline for AutoPatch verification")

    if _git(repo, "rev-parse", "--verify", f"refs/heads/{branch}").returncode == 0:
        result["skipped"] = f"branch {branch} already exists (previous AutoPatch run)"
        return result

    with tempfile.TemporaryDirectory(prefix="autopatch-worktree-") as td:
        wt = Path(td) / "wt"
        add = _git(repo, "worktree", "add", "-b", branch, str(wt), "HEAD")
        if add.returncode != 0:
            result["error"] = f"git worktree add failed: {add.stderr.strip()}"
            return result
        try:
            from .paths import PathEscape, safe_join
            try:
                targets = [(fp, safe_join(wt, fp.file)) for fp in patch.files]
                tp = safe_join(wt, patch.test_file)
            except PathEscape as exc:
                result["error"] = f"patch path escapes worktree: {exc}"
                return result
            for fp, target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(fp.patched)
            tp.parent.mkdir(parents=True, exist_ok=True)
            tp.write_text(patch.test_code)
            paths = [fp.file for fp in patch.files] + [patch.test_file]
            _git(wt, "add", *paths)
            commit = _git(wt, *_GIT_ID, "commit", "-m",
                          f"fix({alert.kind}): {alert.rule} in {alert.file} [AutoPatch verified]")
            if commit.returncode != 0:
                result["error"] = f"git commit failed: {commit.stderr.strip()}"
        finally:
            _git(repo, "worktree", "remove", "--force", str(wt))

    if push:
        if not shutil.which("gh"):
            result["error"] = "--push requested but gh CLI not found"
        else:
            p = _git(repo, "push", "-u", "origin", branch)
            if p.returncode != 0:
                result["error"] = f"git push failed: {p.stderr.strip()[-400:]}"
            else:
                pr = subprocess.run(
                    ["gh", "pr", "create", "--title",
                     f"AutoPatch: fix {alert.rule} in {alert.file}",
                     "--body-file", str(body_file), "--head", branch],
                    cwd=repo, capture_output=True, text=True)
                result["pr_url"] = pr.stdout.strip() or None
                if pr.returncode != 0:
                    result["error"] = f"gh pr create failed: {pr.stderr.strip()[-400:]}"
    return result
