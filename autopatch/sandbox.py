"""Isolated sandbox verification.

The repo is copied to a throwaway directory and tests run there with a
scrubbed environment (operator secrets such as META_API_KEY are NOT passed
to untrusted repo code). A patch is *verified* only if:
  1. the generated regression test FAILS on the vulnerable code (it really
     exercises the vulnerability, not a vacuous assertion),
  2. the same test PASSES after the patch, and
  3. the repo's pre-existing test suite has no NEW failures versus the
     unpatched baseline (real repos are rarely 100% green; a patch must
     not make things worse, and may even fix pre-existing failures).
Anything else is rejected and never reaches a Pull Request.

Note: this is process-level isolation (temp copy + env scrub + timeout),
not a VM/container. For hostile repos run AutoPatch itself in a container
(see Dockerfile) — the sandbox gates inherit that boundary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .patcher import PatchResult
from .runner import Runner

_SAFE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "SYSTEMROOT")


@dataclass
class Verdict:
    verified: bool
    reasons: list[str] = field(default_factory=list)
    logs: dict[str, str] = field(default_factory=dict)


def _scrubbed_env(home: Path | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in _SAFE_ENV if k in os.environ}
    if home is not None:  # never the operator's real HOME (~/.ssh, ~/.config, ...)
        env["HOME"] = str(home)
    env |= {"PYTHONDONTWRITEBYTECODE": "1", "CI": "1", "AUTOPATCH_SANDBOX": "1"}
    # Forward a venv's interpreter context without forwarding secrets.
    if os.environ.get("VIRTUAL_ENV"):
        env["VIRTUAL_ENV"] = os.environ["VIRTUAL_ENV"]
    return env


def _run(cmd: list[str], cwd: Path, timeout: int, home: Path | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=_scrubbed_env(home))
        # Keep enough output for failure-id parsing (gate 3); logs stored are tailed by callers.
        return p.returncode, (p.stdout + p.stderr)[-200000:]
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "test run timed out"


_FAILED_ID = re.compile(r"^(?:FAILED|ERROR|not ok \d+ -|✕)\s+(\S[^-\n]*)", re.M)


_COLLECTION_ERROR = re.compile(
    r"ImportError|ModuleNotFoundError|SyntaxError|errors? during collection|"
    r"ERR_MODULE_NOT_FOUND|Cannot find module", re.I)


def _is_assertion_failure(log: str, language: str) -> bool:
    """Gate 1 must prove the test EXECUTED the bug: an assertion failure,
    not an import/collection crash (which a vacuous marker test produces)."""
    if _COLLECTION_ERROR.search(log):
        return False
    if language == "javascript":
        return bool(re.search(r"# fail [1-9]", log))
    # pytest: a test that ran and failed (collection problems report "errors",
    # and import crashes are filtered above).
    return bool(re.search(r"\d+ failed", log))


def failing_tests(log: str) -> set[str]:
    """Best-effort failing-test identifiers (pytest -q / node --test output)."""
    return {m.group(1).strip() for m in _FAILED_ID.finditer(log)}


def verify(repo: Path, patch: PatchResult, runner: Runner | None = None,
           cfg: Config | None = None, alert=None) -> Verdict:
    from .config import load_config
    from .runner import detect_runner

    cfg = cfg or load_config(repo)
    runner = runner or detect_runner(repo, patch.file, cfg)
    v = Verdict(verified=False)
    timeout = cfg.timeout

    with tempfile.TemporaryDirectory(prefix="autopatch-sandbox-") as td:
        work = Path(td) / "repo"
        shutil.copytree(repo, work, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".pytest_cache", "*.pyc", "node_modules",
            ".venv", "venv", ".autopatch",
            ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*"))
        cwd = work / runner.workdir

        if runner.setup:
            rc, log = _run(runner.setup, cwd, timeout, home=work)
            v.logs["setup"] = log
            if rc != 0:
                v.reasons.append("sandbox setup command failed; cannot verify safely")
                return v

        # Baseline suite failures on the unpatched copy (for gate 3).
        baseline_failures: set[str] | None = None
        baseline_rc = 0
        if runner.test_all:
            baseline_rc, log = _run(runner.test_all, cwd, timeout, home=work)
            v.logs["full_suite_baseline"] = log
            baseline_failures = failing_tests(log)

        # 1. regression test against vulnerable code must fail
        from .paths import PathEscape, safe_join
        try:
            test_path = safe_join(work, patch.test_file)
            patch_targets = [(fp, safe_join(work, fp.file)) for fp in patch.files]
        except PathEscape as exc:
            v.reasons.append(f"patch path escapes sandbox: {exc}")
            return v
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.write_text(patch.test_code)
        rc, log = _run(runner.test_one(patch.test_file), work, timeout, home=work)
        v.logs["regression_on_vulnerable"] = log
        if rc == 0:
            v.reasons.append("regression test passes on vulnerable code — does not prove the bug")
            return v
        if not _is_assertion_failure(log, runner.language):
            v.reasons.append("regression test does not execute the bug on vulnerable code "
                             "(import/collection/syntax error, not an assertion failure)")
            return v
        v.reasons.append("regression test fails on vulnerable code (bug reproduced)")

        # 2. apply patch (all files), test must pass
        for fp, target in patch_targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(fp.patched)
        # Dependency bumps only take effect after a reinstall.
        if runner.setup and any(Path(fp.file).name in
                                 ("package.json", "pnpm-lock.yaml", "requirements.txt",
                                  "pyproject.toml", "package-lock.json")
                                 for fp in patch.files):
            rc, log = _run(runner.setup, cwd, timeout, home=work)
            v.logs["setup_after_patch"] = log
            if rc != 0:
                v.reasons.append("setup/install fails after the dependency change")
                return v
        rc, log = _run(runner.test_one(patch.test_file), work, timeout, home=work)
        v.logs["regression_on_patched"] = log
        if rc != 0:
            v.reasons.append("regression test still fails after patch")
            return v
        v.reasons.append("regression test passes after patch (bug fixed)")

        # 3. existing suite: no new failures versus baseline
        if runner.test_all is None:
            v.reasons.append("WARNING: no existing test suite detected — gate 3 not run")
        else:
            rc, log = _run(runner.test_all, cwd, timeout, home=work)
            v.logs["full_suite_on_patched"] = log
            if baseline_rc == 0 and rc != 0:
                v.reasons.append("existing test suite breaks after patch (backwards-compat failure)")
                return v
            new_failures = failing_tests(log) - (baseline_failures or set())
            if new_failures:
                v.reasons.append(
                    "patch introduces new test failures: " + ", ".join(sorted(new_failures)[:5]))
                return v
            if baseline_rc == 0:
                v.reasons.append("full existing test suite passes after patch")
            else:
                v.reasons.append(
                    f"no new suite failures versus baseline ({len(baseline_failures or ())} pre-existing)")

        # 4. optional re-scan gate: the originating scanner rule must be gone
        if cfg.rescan and alert is not None:
            from .scanner import alert_still_present
            still = alert_still_present(work, alert, timeout=timeout)
            if still is True:
                v.reasons.append("re-scan: scanner still reports this alert on the patched code")
                return v
            if still is None:
                v.reasons.append("re-scan: enabled but could not run — failing closed")
                return v
            v.reasons.append("re-scan: scanner no longer reports this alert")

    v.verified = True
    return v
