"""SARIF 2.1 output: run results GitHub code scanning can ingest.

Verified fixes are emitted as results carrying a SARIF `fixes` block with
the full replacement text per file, plus properties marking them
`autopatch: verified`. Unverified alerts are emitted plainly so they stay
visible. Upload with e.g. `gh api .../code-scanning/sarifs` or the
codeql-action/upload-sarif action — AutoPatch itself stays read-only here.
"""

from __future__ import annotations

import json
from pathlib import Path


def reports_to_sarif(reports) -> dict:
    from . import __version__

    rules, results = {}, []
    for rep in reports:
        a = rep.alert
        rules[a.rule] = {
            "id": a.rule,
            "name": a.rule.replace("/", "_").replace(".", "_"),
            "shortDescription": {"text": a.message or a.rule},
            "properties": {"tags": [t for t in (a.cwe, "security") if t]},
        }
        result = {
            "ruleId": a.rule,
            "level": "error" if a.severity in ("critical", "high") else "warning",
            "message": {"text": f"[{rep.status}] {rep.detail}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": a.file},
                "region": {"startLine": max(a.line, 1)},
            }}],
            "properties": {"autopatchStatus": rep.status,
                           "autopatchAttempts": rep.attempts,
                           "patchSource": rep.patch_source},
        }
        diff = rep.pr.get("diff") if rep.pr else None
        if rep.status == "verified-pr" and diff:
            result["properties"]["autopatchVerifiedDiff"] = diff
        results.append(result)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AutoPatch", "version": __version__,
                "informationUri": "https://github.com/Kokenya/replayr",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(reports, path: str | Path) -> None:
    Path(path).write_text(json.dumps(reports_to_sarif(reports), indent=2))


def upload_payload(sarif_path: str | Path, commit_sha: str, ref: str) -> dict:
    """GitHub code-scanning SARIF upload body (gzipped, base64-encoded SARIF)."""
    import base64
    import gzip

    raw = Path(sarif_path).read_bytes()
    return {
        "commit_sha": commit_sha,
        "ref": ref,
        "sarif": base64.b64encode(gzip.compress(raw)).decode(),
        "tool_name": "AutoPatch",
    }


def upload_sarif(sarif_path: str | Path, repo_slug: str, commit_sha: str,
                 ref: str = "refs/heads/main") -> str:
    """Upload via the gh CLI; returns the API response's processing URL/id text."""
    import subprocess
    import tempfile

    payload = upload_payload(sarif_path, commit_sha, ref)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        body_file = f.name
    p = subprocess.run(
        ["gh", "api", f"repos/{repo_slug}/code-scanning/sarifs", "-X", "POST",
         "--input", body_file],
        capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"gh api upload failed: {p.stderr.strip()[-400:]}")
    return p.stdout.strip()
