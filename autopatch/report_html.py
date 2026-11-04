"""Single-file HTML run report: the artifact a human (or a jury) opens.

No external assets; the diff and gate verdicts are inlined. Status colors
follow the outcome, never the model's confidence.
"""

from __future__ import annotations

import html
from pathlib import Path

_STATUS_STYLE = {
    "verified-pr": ("#137333", "VERIFIED — PR ready"),
    "rejected": ("#b3261e", "REJECTED by sandbox"),
    "false-positive": ("#8a6d00", "TRIAGED: false positive"),
    "no-patch": ("#5f6368", "NO PATCH"),
    "error": ("#b3261e", "ERROR"),
    "skipped": ("#5f6368", "SKIPPED"),
}

_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#1f2328;background:#fff}
h1{font-size:1.5rem} .sub{color:#5f6368;margin-top:-.6rem}
.card{border:1px solid #d0d7de;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
.badge{color:#fff;border-radius:999px;padding:.15rem .6rem;font-size:.8rem;font-weight:600}
.meta{color:#5f6368;font-size:.9rem}
ul.gates{list-style:none;padding-left:0} ul.gates li::before{content:'✓ ';color:#137333;font-weight:700}
pre{background:#f6f8fa;border-radius:8px;padding:.8rem;overflow-x:auto;font-size:.82rem;line-height:1.45}
.add{color:#137333}.del{color:#b3261e}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #eaeef2;padding:.4rem .5rem;text-align:left;font-size:.92rem}
"""


def _diff_html(diff: str) -> str:
    out = []
    for line in diff.splitlines():
        esc = html.escape(line)
        if line.startswith("+") and not line.startswith("+++"):
            out.append(f'<span class="add">{esc}</span>')
        elif line.startswith("-") and not line.startswith("---"):
            out.append(f'<span class="del">{esc}</span>')
        else:
            out.append(esc)
    return "\n".join(out)


def reports_to_html(reports, title: str = "AutoPatch run report") -> str:
    from . import __version__

    counts = {}
    for r in reports:
        counts[r.status] = counts.get(r.status, 0) + 1
    summary = " · ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    cards = []
    for rep in reports:
        a = rep.alert
        color, label = _STATUS_STYLE.get(rep.status, ("#5f6368", rep.status.upper()))
        gates = "".join(f"<li>{html.escape(r)}</li>" for r in rep.verdict_reasons)
        diff = rep.pr.get("diff") if rep.pr else None
        pr_link = ""
        if rep.pr.get("pr_url"):
            pr_link = f' · <a href="{html.escape(rep.pr["pr_url"])}">Pull Request</a>'
        elif rep.pr.get("branch"):
            pr_link = f' · branch <code>{html.escape(rep.pr["branch"])}</code>'
        cards.append(f"""
<div class="card">
  <span class="badge" style="background:{color}">{label}</span>
  <h3>{html.escape(a.rule)} <span class="meta">({html.escape(a.cwe or "—")}, {html.escape(a.severity)})</span></h3>
  <p class="meta"><code>{html.escape(a.file)}:{a.line}</code> · attempts: {rep.attempts} · source: {html.escape(rep.patch_source or "—")}{pr_link}</p>
  <p>{html.escape(rep.detail)}</p>
  <ul class="gates">{gates}</ul>
  {f'<pre>{_diff_html(diff)}</pre>' if diff else ''}
</div>""")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title><style>{_CSS}</style></head>
<body>
<h1>AutoPatch run report</h1>
<p class="sub">v{__version__} · {len(reports)} alert(s): {html.escape(summary or "none")}<br>
A patch is proposed only after the sandbox gates pass: regression test fails on the
vulnerable code, passes after the patch, and the existing suite has no new failures.</p>
{''.join(cards)}
</body></html>
"""


def write_html(reports, path: str | Path) -> None:
    Path(path).write_text(reports_to_html(reports))
