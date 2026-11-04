"""Hunt mode: find vulnerabilities scanners miss.

Rule-based scanners see known patterns in single files. Buried bugs hide in
data flow: taint passing through helper functions, home-grown sanitizers
that can be bypassed, an authorization check present on sibling routes but
missing on one, unsafe operations wrapped in innocent-looking helpers.

Hunt scores files by attack-surface signals, audits the most suspicious
ones with the LLM, and emits *candidate* alerts. A candidate means nothing
until the normal agent loop proves it: the generated regression test must
fail on the current code in the sandbox (false positives die there).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .alerts import Alert
from .llm import MetaLLM
from .patcher import LLMError

_SIGNALS: list[tuple[str, int]] = [
    (r"request\.|req\.|input\(|argv|environ|headers\[|cookies\[", 3),   # untrusted input
    (r"execute\(|executemany|raw\(|extra\(|text\(", 3),                  # SQL sinks
    (r"subprocess|os\.system|popen|exec\(|eval\(|__import__", 3),        # command/code sinks
    (r"open\(|send_file|sendfile|read_file|Path\(", 2),                  # file sinks
    (r"pickle\.loads|yaml\.load\(|marshal|unserialize|fromhex.*decode", 3),  # deserialization
    (r"replace\(|strip\(|sanitize|clean_|escape", 2),                     # home-grown sanitizers
    (r"login|auth|permission|token|session|password", 2),                # auth surface
    (r"upload|filename|content-type", 2),                                # upload surface
    (r"redirect\(|url_for|next_page|return_url", 1),                     # redirect surface
    (r"html|render|mark_safe|innerHTML|dangerouslySetInnerHTML", 1),     # markup sinks
]
_SUFFIXES = {".py", ".js", ".mjs", ".ts", ".tsx", ".jsx"}
_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "tests", "test", "dist"}


def suspicious_files(repo: Path, max_files: int = 20) -> list[tuple[int, Path]]:
    scored: list[tuple[int, Path]] = []
    for path in Path(repo).rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SUFFIXES:
            continue
        if any(p in _SKIP for p in path.parts) or "test" in path.name:
            continue
        try:
            text = path.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        score = sum(w * len(re.findall(pat, text, re.I)) for pat, w in _SIGNALS)
        if score:
            scored.append((score, path))
    scored.sort(key=lambda t: (-t[0], str(t[1])))
    return scored[:max_files]


_SYS = (
    "You are a security auditor hunting vulnerabilities that rule-based "
    "scanners miss: taint flowing through helper functions into sinks, "
    "home-grown sanitizers that can be bypassed (incomplete replace/strip, "
    "prefix-only checks, double-encoding), authorization checks missing on "
    "one route while siblings have them, unsafe deserialization or path "
    "handling wrapped in innocent helpers, and logic flaws an attacker "
    "controls. Read carefully and follow data across functions in the file. "
    "Reply with JSON only: {\"findings\": [{\"line\": <1-based int>, "
    "\"cwe\": \"CWE-<n>\", \"rule\": \"hunt/<short-kebab-name>\", "
    "\"severity\": \"low|medium|high|critical\", "
    "\"message\": \"<what is exploitable and how, naming the payload shape>\"}]}. "
    "Report ONLY issues you can trace to attacker-controlled input. If the "
    "file is clean, return an empty findings list — do not speculate."
)


def audit_file(llm: MetaLLM, repo: Path, path: Path) -> list[Alert]:
    source = path.read_text(errors="replace")
    rel = str(path.relative_to(repo))
    numbered = "\n".join(f"{i + 1:4} {l}" for i, l in enumerate(source.splitlines()))
    if len(numbered) > 60000:
        numbered = numbered[:60000] + "\n… (truncated)"
    try:
        raw = llm.chat(_SYS, f"File: {rel}\n```\n{numbered}\n```")
        data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
    except Exception as exc:
        raise LLMError(f"hunt audit failed for {rel}: {exc}") from exc
    out: list[Alert] = []
    for f in data.get("findings", []):
        try:
            out.append(Alert(
                id=f"hunt-{len(out)}-{Path(rel).stem}",
                rule=str(f.get("rule", "hunt/unknown")),
                severity=str(f.get("severity", "high")),
                file=rel, line=int(f.get("line", 1) or 1),
                message=str(f.get("message", "")),
                cwe=str(f.get("cwe", "")),
            ))
        except (TypeError, ValueError):
            continue
    return out


def hunt(repo: Path, llm: MetaLLM, max_files: int = 20,
         known: list[Alert] | None = None) -> list[Alert]:
    from .alerts import dedup_alerts

    candidates: list[Alert] = []
    for _, path in suspicious_files(repo, max_files=max_files):
        candidates += audit_file(llm, repo, path)
    known_keys = {(a.file, a.line) for a in (known or [])}
    fresh = [a for a in candidates if (a.file, a.line) not in known_keys]
    return dedup_alerts(fresh)
