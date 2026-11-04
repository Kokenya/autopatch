"""Run a scanner to produce alerts (Semgrep + secret patterns), re-scan for closure."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .alerts import Alert, _from_semgrep

# --- secret patterns: things scanners miss outside their rulesets, buried in
# configs, fixtures and scripts. Values are never copied into the alert.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("generic-secret-assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{12,}['\"]")),
]
_SECRET_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv"}
_PLACEHOLDER_HINT = ("example", "changeme", "placeholder", "your_", "xxx", "test", "dummy", "sample")


def scan_secrets(repo: Path, max_file_kb: int = 512) -> list[Alert]:
    out: list[Alert] = []
    for path in sorted(Path(repo).rglob("*")):
        if not path.is_file() or any(p in _SECRET_SKIP for p in path.parts):
            continue
        if path.suffix in (".png", ".jpg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff2"):
            continue
        try:
            if path.stat().st_size > max_file_kb * 1024:
                continue
            text = path.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        rel = str(path.relative_to(repo))
        for i, line in enumerate(text.splitlines(), start=1):
            if any(h in line.lower() for h in _PLACEHOLDER_HINT):
                continue
            for name, pat in _SECRET_PATTERNS:
                if pat.search(line):
                    out.append(Alert(
                        id=f"secret-{len(out)}", rule=f"secrets/{name}",
                        severity="critical", file=rel, line=i,
                        message=f"possible hard-coded secret ({name}); value redacted — rotate it and move it to env/secret storage",
                        cwe="CWE-798"))
                    break
    return out

_DEFAULT_CONFIGS = ("p/security-audit", "p/python", "p/javascript", "p/typescript")


def run_semgrep(repo: Path, configs: tuple[str, ...] = _DEFAULT_CONFIGS,
                timeout: int = 600) -> list[Alert]:
    if not shutil.which("semgrep"):
        raise RuntimeError("semgrep not installed (pip install semgrep) — "
                           "or pass pre-made --alerts instead")
    cmd = ["semgrep", "--json", "--quiet"]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(str(repo))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"semgrep output not JSON: {p.stderr[-300:]}") from exc
    alerts = _from_semgrep(data)
    for a in alerts:  # make file paths repo-relative
        try:
            a.file = str(Path(a.file).resolve().relative_to(Path(repo).resolve()))
        except ValueError:
            pass
    return alerts


def alert_still_present(work: Path, alert: Alert, timeout: int = 300) -> bool | None:
    """Re-scan `work` (a patched copy): True if the same rule still fires on
    the same file, False if it is gone, None if the check cannot run
    (scanner missing / rule not Semgrep-shaped) — caller decides honesty."""
    if not shutil.which("semgrep") or "." not in alert.rule:
        return None
    try:
        found = run_semgrep(work, timeout=timeout)
    except (RuntimeError, subprocess.TimeoutExpired):
        return None
    return any(a.rule == alert.rule and a.file == alert.file for a in found)


def alerts_to_json(alerts: list[Alert]) -> str:
    return json.dumps([
        {"id": a.id, "rule": a.rule, "severity": a.severity, "file": a.file,
         "line": a.line, "message": a.message, "cwe": a.cwe,
         "package": a.package, "fixed_version": a.fixed_version}
        for a in alerts
    ], indent=2)
