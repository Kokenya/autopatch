"""Static-analysis alert ingesting.

Accepted inputs:
  * SARIF 2.1 (CodeQL, Semgrep --sarif, Bandit via sarif converters)
  * Semgrep native JSON (--json)
  * simple list / {"alerts": [...]} (demo + normalized scanners, Dependabot-style
    dependency alerts carrying package + fixed_version)

Parsing is defensive: a malformed result entry is skipped, never fatal.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "low"}


@dataclass
class Alert:
    id: str
    rule: str            # e.g. "py/sql-injection"
    severity: str        # low | medium | high | critical
    file: str            # repo-relative path (manifest path for dependency alerts)
    line: int
    message: str
    cwe: str = ""
    package: str = ""        # dependency alerts: vulnerable package name
    fixed_version: str = ""  # dependency alerts: first fixed version

    @property
    def kind(self) -> str:
        if self.package:
            return "dependency"
        r = self.rule.lower()
        if r.startswith("secrets/") or "hardcoded" in r or "hard-coded" in r:
            return "hardcoded-secret"
        if "sql" in r:
            return "sql-injection"
        if "xss" in r or "cross-site" in r:
            return "xss"
        if "redirect" in r:
            return "open-redirect"
        if "xxe" in r or "external-entity" in r or "defused" in r or ("xml" in r and "pars" in r):
            return "xxe"
        if "path" in r or "traversal" in r:
            return "path-traversal"
        if "command" in r or "shell" in r:
            return "command-injection"
        if "depend" in r or "cve-" in r:
            return "dependency"
        return "generic"

    @property
    def dedup_key(self) -> tuple:
        return (self.rule, self.file, self.line, self.package)


def _cwe_from(text: str) -> str:
    m = re.search(r"CWE[- ]?(\d+)", text or "", re.I)
    return f"CWE-{m.group(1)}" if m else ""


def _from_sarif(data: dict) -> list[Alert]:
    out: list[Alert] = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in
                 run.get("tool", {}).get("driver", {}).get("rules", []) if r.get("id")}
        for i, res in enumerate(run.get("results", [])):
            try:
                locs = res.get("locations") or []
                loc = (locs[0].get("physicalLocation") if locs else {}) or {}
                uri = loc.get("artifactLocation", {}).get("uri", "")
                line = int(loc.get("region", {}).get("startLine", 1) or 1)
                if not uri:
                    continue
                rule_id = res.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                text = res.get("message", {}).get("text", "")
                tags = " ".join(rule.get("properties", {}).get("tags", []))
                out.append(Alert(
                    id=f"sarif-{len(out)}",
                    rule=rule_id,
                    severity=_LEVEL_SEVERITY.get(res.get("level", ""), "high"),
                    file=uri,
                    line=line,
                    message=text,
                    cwe=_cwe_from(tags) or _cwe_from(text),
                ))
            except (KeyError, TypeError, ValueError, IndexError):
                continue
    return out


def _from_semgrep(data: dict) -> list[Alert]:
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for i, r in enumerate(data.get("results", [])):
        try:
            extra = r.get("extra", {})
            out.append(Alert(
                id=f"semgrep-{i}",
                rule=r.get("check_id", "unknown"),
                severity=sev.get(extra.get("severity", ""), "medium"),
                file=r.get("path", ""),
                line=int(r.get("start", {}).get("line", 1) or 1),
                message=extra.get("message", ""),
                cwe=_cwe_from(str(extra.get("metadata", {}).get("cwe", ""))),
            ))
        except (TypeError, ValueError):
            continue
    return [a for a in out if a.file]


def load_alerts(path: str | Path) -> list[Alert]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict) and "runs" in data:
        return _from_sarif(data)
    if isinstance(data, dict) and "results" in data and "errors" in data:
        return _from_semgrep(data)
    items = data if isinstance(data, list) else data.get("alerts", [])
    fields = Alert.__dataclass_fields__
    return [Alert(**{k: a[k] for k in fields if k in a}) for a in items if isinstance(a, dict)]


def dedup_alerts(alerts: list[Alert]) -> list[Alert]:
    seen, out = set(), []
    for a in alerts:
        if a.dedup_key not in seen:
            seen.add(a.dedup_key)
            out.append(a)
    return out
