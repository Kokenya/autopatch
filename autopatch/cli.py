"""CLI:
  python -m autopatch run   --repo PATH --alerts alerts.json [--push] [--dry-run] [--report run.json]
  python -m autopatch scan  --repo PATH --out alerts.json          (Semgrep)
  python -m autopatch serve --repo PATH --port 8080 [--push]       (GitHub webhook)

Exit codes for `run`: 0 = at least one verified fix (or no alerts),
1 = alerts processed, none verified, 2 = operational error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import remediate
from .alerts import dedup_alerts, load_alerts
from .config import load_config
from .llm import MetaLLM


def _cmd_hunt(args) -> int:
    from .hunt import hunt
    from .scanner import alerts_to_json, run_semgrep, scan_secrets

    repo = Path(args.repo)
    llm = MetaLLM()
    if not llm.enabled:
        print("hunt needs the Meta API (META_API_KEY) — set it or use `scan` instead",
              file=sys.stderr)
        return 2
    known: list = []
    if not args.no_scan:
        try:
            known = run_semgrep(repo)
        except RuntimeError as exc:
            print(f"scanner pass skipped: {exc}")
        known += scan_secrets(repo)
    from .patcher import LLMError
    try:
        found = hunt(repo, llm, max_files=args.max_files, known=known)
    except LLMError as exc:
        print(f"hunt failed: {exc}", file=sys.stderr)
        return 2
    alerts = dedup_alerts(known + found)
    Path(args.out).write_text(alerts_to_json(alerts))
    print(f"{len(found)} hidden candidate(s) beyond the scanner's {len(known)}; "
          f"{len(alerts)} total alert(s) written to {args.out}")
    for a in found:
        print(f"  ⚠ {a.rule} ({a.cwe}) {a.file}:{a.line} — {a.message[:110]}")
    if not args.remediate:
        print("Candidates are unproven until remediated: "
              f"`autopatch run --repo {args.repo} --alerts {args.out}`")
        return 0
    cfg = load_config(repo, args.config or None)
    reports = []
    for alert in found:
        print(f"\n▶ {alert.id}  {alert.rule}  {alert.file}:{alert.line}")
        rep = remediate(repo, alert, push=args.push, llm=llm, cfg=cfg, dry_run=args.dry_run)
        reports.append(rep)
        for reason in rep.verdict_reasons:
            print(f"   ✓ {reason}")
        print(f"   → {rep.status}: {rep.detail}")
    ok = sum(r.status == "verified-pr" for r in reports)
    print(f"\n{ok}/{len(reports)} hidden candidate(s) proven and fixed.")
    return 0 if ok or not reports else 1


def _cmd_scan(args) -> int:
    from .scanner import alerts_to_json, run_semgrep, scan_secrets
    try:
        alerts = dedup_alerts(run_semgrep(Path(args.repo)) + scan_secrets(Path(args.repo)))
    except RuntimeError as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2
    Path(args.out).write_text(alerts_to_json(alerts))
    print(f"{len(alerts)} alert(s) written to {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="autopatch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="remediate alerts into verified PR branches")
    r.add_argument("--repo", required=True)
    r.add_argument("--alerts", required=True)
    r.add_argument("--push", action="store_true", help="push branch and open a real GitHub PR via gh")
    r.add_argument("--dry-run", action="store_true", help="verify in sandbox but create no branch/PR")
    r.add_argument("--report", default="", help="write a JSON run report to this path")
    r.add_argument("--sarif-out", default="", help="write SARIF 2.1 results (for GitHub code scanning) to this path")
    r.add_argument("--html", default="", help="write a single-file HTML run report to this path")
    r.add_argument("--config", default="", help="path to autopatch.toml (default: <repo>/autopatch.toml)")
    r.add_argument("--limit", type=int, default=0, help="process at most N alerts (0 = all)")
    r.add_argument("--max-attempts", type=int, default=0, help="override LLM regeneration attempts")
    sub.add_parser("catalogue", help="print measured CWE support (benchmarks/results.json)")
    up = sub.add_parser("upload-sarif", help="upload a SARIF file to GitHub code scanning")
    up.add_argument("--sarif", required=True)
    up.add_argument("--repo-slug", required=True, help="owner/repo")
    up.add_argument("--commit", required=True)
    up.add_argument("--ref", default="refs/heads/main")
    sc = sub.add_parser("scan", help="run Semgrep and write an alerts file")
    sc.add_argument("--repo", required=True)
    sc.add_argument("--out", required=True)
    h = sub.add_parser("hunt", help="LLM audit for buried vulns scanners miss (+ scanner pass)")
    h.add_argument("--repo", required=True)
    h.add_argument("--out", default="hunt-alerts.json")
    h.add_argument("--max-files", type=int, default=20)
    h.add_argument("--no-scan", action="store_true", help="skip the Semgrep/secrets pass")
    h.add_argument("--remediate", action="store_true",
                   help="run the verified-fix loop on the hidden candidates found")
    h.add_argument("--dry-run", action="store_true")
    h.add_argument("--push", action="store_true")
    h.add_argument("--config", default="")
    s = sub.add_parser("serve", help="GitHub webhook receiver")
    s.add_argument("--repo", required=True)
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--push", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "upload-sarif":
        from .sarif_out import upload_sarif
        try:
            print(upload_sarif(args.sarif, args.repo_slug, args.commit, args.ref))
        except RuntimeError as exc:
            print(f"upload failed: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.cmd == "catalogue":
        from .catalogue import render
        print(render())
        return 0
    if args.cmd == "serve":
        from .server import serve
        serve(args.repo, args.port, push=args.push)
        return 0
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "hunt":
        return _cmd_hunt(args)

    repo = Path(args.repo)
    cfg = load_config(repo, args.config or None)
    llm = MetaLLM()
    print(f"AutoPatch · model={'Meta API (' + llm.model + ')' if llm.enabled else 'offline fallback'}"
          f"{' · DRY-RUN' if args.dry_run else ''}")
    try:
        alerts = dedup_alerts(load_alerts(args.alerts))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot load alerts: {exc}", file=sys.stderr)
        return 2
    if args.limit:
        alerts = alerts[:args.limit]

    reports = []
    for alert in alerts:
        print(f"\n▶ {alert.id}  {alert.rule}  {alert.file}:{alert.line}")
        rep = remediate(repo, alert, push=args.push, llm=llm, cfg=cfg,
                        dry_run=args.dry_run,
                        max_attempts=args.max_attempts or None)
        reports.append(rep)
        for reason in rep.verdict_reasons:
            print(f"   ✓ {reason}")
        print(f"   → {rep.status}: {rep.detail}")
        if rep.pr.get("branch"):
            print(f"   branch: {rep.pr['branch']}  PR: {rep.pr.get('pr_url') or rep.pr.get('pr_body_file')}")
        if rep.pr.get("error"):
            print(f"   ! {rep.pr['error']}")

    if args.report:
        Path(args.report).write_text(json.dumps([r.to_dict() for r in reports], indent=2))
        print(f"\nReport: {args.report}")
    if args.sarif_out:
        from .sarif_out import write_sarif
        write_sarif(reports, args.sarif_out)
        print(f"SARIF: {args.sarif_out}")
    if args.html:
        from .report_html import write_html
        write_html(reports, args.html)
        print(f"HTML report: {args.html}")
    ok = sum(r.status == "verified-pr" for r in reports)
    errors = sum(r.status == "error" for r in reports)
    print(f"\n{ok} verified PR(s) ready, {len(reports) - ok - errors} rejected/skipped, {errors} error(s).")
    if errors and not ok:
        return 2
    return 0 if ok or not reports else 1


if __name__ == "__main__":
    sys.exit(main())
