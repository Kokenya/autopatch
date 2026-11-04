"""AutoPatch agent loop: alert -> context -> patch -> test -> sandbox -> PR.

An LLM patch that the sandbox rejects is regenerated with the verdict as
feedback (up to `max_attempts`). Only a verified patch reaches a PR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .alerts import Alert
from .config import Config, load_config
from .github_pr import open_pr
from .llm import MetaLLM
from .patcher import FalsePositive, LLMError, generate_patch
from .runner import detect_runner
from .sandbox import verify


@dataclass
class RunReport:
    alert: Alert
    status: str  # verified-pr | rejected | no-patch | error | skipped
    detail: str = ""
    pr: dict = field(default_factory=dict)
    verdict_reasons: list[str] = field(default_factory=list)
    attempts: int = 0
    patch_source: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert.id, "rule": self.alert.rule,
            "file": self.alert.file, "line": self.alert.line,
            "cwe": self.alert.cwe, "severity": self.alert.severity,
            "status": self.status, "detail": self.detail,
            "attempts": self.attempts, "patch_source": self.patch_source,
            "verdict_reasons": self.verdict_reasons, "pr": self.pr,
        }


def remediate(repo: str | Path, alert: Alert, push: bool = False,
              llm: MetaLLM | None = None, max_attempts: int | None = None,
              cfg: Config | None = None, dry_run: bool = False) -> RunReport:
    repo = Path(repo)
    cfg = cfg or load_config(repo)
    attempts_cap = max_attempts if max_attempts is not None else cfg.max_attempts
    runner = detect_runner(repo, alert.file, cfg)

    from .paths import PathEscape, safe_join

    source = ""
    if alert.kind != "dependency":
        try:
            target = safe_join(repo, alert.file)
        except PathEscape:
            return RunReport(alert, "error", f"alert file escapes repo root: {alert.file}")
        if not target.is_file():
            return RunReport(alert, "error", f"alert file not found in repo: {alert.file}")
        source = target.read_text(errors="replace")

    feedback = ""
    last_reasons: list[str] = []
    for attempt in range(1, attempts_cap + 1):
        try:
            patch = generate_patch(alert, source, llm=llm, feedback=feedback,
                                   repo=repo, runner=runner)
        except FalsePositive as exc:
            return RunReport(alert, "false-positive",
                             f"model judged this a false positive: {exc} "
                             "(unverified — a human should confirm before closing the alert)",
                             verdict_reasons=last_reasons, attempts=attempt)
        except LLMError as exc:
            return RunReport(alert, "error", str(exc), verdict_reasons=last_reasons,
                             attempts=attempt)
        if patch is None:
            return RunReport(alert, "no-patch",
                             "no patch generated (LLM unavailable/unchanged output and "
                             "no deterministic fix for this class)",
                             verdict_reasons=last_reasons, attempts=attempt)
        verdict = verify(repo, patch, runner=runner, cfg=cfg, alert=alert)
        last_reasons = verdict.reasons
        if verdict.verified:
            detail = patch.explanation
            if attempt > 1:
                detail += f" (verified on attempt {attempt}/{attempts_cap})"
            if dry_run:
                return RunReport(alert, "verified-pr", detail + " [dry-run: no branch/PR created]",
                                 pr={"diff": patch.diff}, verdict_reasons=verdict.reasons,
                                 attempts=attempt, patch_source=patch.source)
            pr = open_pr(repo, alert, patch, verdict, push=push)
            status = "verified-pr"
            if pr.get("skipped"):
                status, detail = "skipped", pr["skipped"]
            return RunReport(alert, status, detail, pr=pr,
                             verdict_reasons=verdict.reasons, attempts=attempt,
                             patch_source=patch.source)
        if patch.source != "meta-llm":
            break  # deterministic patches would regenerate identically
        feedback = "\n".join(f"- {r}" for r in verdict.reasons)
        tail = next((log for log in reversed(list(verdict.logs.values())) if log), "")
        if tail:
            feedback += f"\nSandbox test output (tail):\n{tail[-1500:]}"
    return RunReport(alert, "rejected", "; ".join(last_reasons),
                     verdict_reasons=last_reasons, attempts=attempts_cap)
