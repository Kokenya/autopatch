"""Benchmark harness: measured verified-fix rate per CWE class.

Each case under corpus/<name>/ is a miniature vulnerable repo:
  alert.json   one alert
  <sources>    the vulnerable code + its own existing tests

The harness copies each case to a temp dir and runs the real agent loop
(patch -> 3 sandbox gates -> branch) against it, then writes
benchmarks/results.json. Default is OFFLINE (no API credits, measures the
deterministic tier). Pass --live to measure with the Meta API configured.

    python3 benchmarks/run.py [--live]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from autopatch.agent import remediate          # noqa: E402
from autopatch.alerts import load_alerts       # noqa: E402
from autopatch.llm import MetaLLM              # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use the configured Meta API (spends credits)")
    args = ap.parse_args()

    llm = MetaLLM()
    if not args.live:
        llm.key = ""
    results: dict[str, dict] = {}
    cases = sorted(p for p in (ROOT / "benchmarks" / "corpus").iterdir() if p.is_dir())
    for case in cases:
        alert = load_alerts(case / "alert.json")[0]
        expected_file = case / "expected.json"
        expected = (json.loads(expected_file.read_text())["status_any_of"]
                    if expected_file.is_file() else ["verified-pr"])
        with tempfile.TemporaryDirectory(prefix="autopatch-bench-") as td:
            repo = Path(td) / case.name
            shutil.copytree(case, repo, ignore=shutil.ignore_patterns("__pycache__"))
            rep = remediate(repo, alert, llm=llm)
        correct = rep.status in expected
        bucket = results.setdefault(alert.kind, {"verified": 0, "correct": 0, "total": 0, "cases": {}})
        bucket["total"] += 1
        bucket["verified"] += rep.status == "verified-pr"
        bucket["correct"] += correct
        bucket["cases"][case.name] = rep.status
        mark = "✓" if correct else "✗ WRONG (expected " + "/".join(expected) + ")"
        print(f"{case.name:28} {alert.kind:16} -> {rep.status} {mark}")

    out = {"mode": "live" if args.live else "offline", **results}
    (ROOT / "benchmarks" / "results.json").write_text(json.dumps(out, indent=2))
    total = sum(v["total"] for v in results.values())
    ok = sum(v["verified"] for v in results.values())
    correct = sum(v["correct"] for v in results.values())
    print(f"\nverified-fix rate: {ok}/{total} · correct outcomes "
          f"(incl. true-negative triage): {correct}/{total} ({out['mode']}) "
          f"-> benchmarks/results.json")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
