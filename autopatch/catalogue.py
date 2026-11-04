"""Measured CWE support catalogue (ROADMAP stage 2).

Support claims come from the benchmark harness (benchmarks/run.py), not
from optimism. Each entry states HOW a class is fixed:
  deterministic — exact transform, no LLM (offline-capable)
  llm           — model-generated patch, still gated by the 3 sandbox gates
  none          — not attempted; the alert is reported, never silently dropped

`benchmarks/results.json` (written by the harness) carries the measured
verified-fix rate per class; `python -m autopatch catalogue` prints it.
"""

from __future__ import annotations

import json
from pathlib import Path

CATALOGUE: dict[str, dict] = {
    "sql-injection": {
        "cwe": "CWE-89", "support": "deterministic+llm",
        "how": "parameterize the query (f-string/%/.format patterns offline; LLM otherwise)"},
    "path-traversal": {
        "cwe": "CWE-22", "support": "deterministic+llm",
        "how": "confine joined paths to the base directory (realpath prefix check)"},
    "dependency": {
        "cwe": "CWE-1035/CVE", "support": "deterministic",
        "how": "bump manifest pin to >= first fixed version (requirements/pyproject/package.json)"},
    "xss": {
        "cwe": "CWE-79", "support": "deterministic+llm",
        "how": "escape interpolated values at the markup sink (Python + JS); LLM otherwise"},
    "command-injection": {
        "cwe": "CWE-78", "support": "deterministic+llm",
        "how": "os.system string -> argv-list subprocess (no shell); LLM otherwise"},
    "open-redirect": {
        "cwe": "CWE-601", "support": "deterministic+llm",
        "how": "strengthen startswith('/') checks with a netloc test (blocks //evil.example)"},
    "xxe": {
        "cwe": "CWE-611", "support": "deterministic+llm",
        "how": "swap stdlib ElementTree imports to defusedxml (entities/DTDs forbidden)"},
    "hardcoded-secret": {
        "cwe": "CWE-798", "support": "detect-only",
        "how": "secret-pattern scan redacts values; rotation is a human action, never auto-patched"},
    "generic": {
        "cwe": "any", "support": "llm",
        "how": "model patch for any other scanner rule, sandbox-gated; rejected if unverifiable"},
}


def support_for(kind: str) -> dict:
    return CATALOGUE.get(kind, {"cwe": "", "support": "none", "how": "not attempted"})


def load_benchmark_results(root: Path | None = None) -> dict:
    path = (root or Path(__file__).resolve().parents[1]) / "benchmarks" / "results.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def render(root: Path | None = None) -> str:
    results = load_benchmark_results(root)
    lines = ["AutoPatch CWE catalogue (measured on benchmarks/corpus — run "
             "`python3 benchmarks/run.py` to refresh):", ""]
    for kind, info in CATALOGUE.items():
        measured = results.get(kind)
        rate = (f"measured verified-fix rate: {measured['verified']}/{measured['total']}"
                if measured else "not yet measured")
        lines.append(f"- {kind} ({info['cwe']}): {info['support']} — {info['how']} · {rate}")
    return "\n".join(lines)
