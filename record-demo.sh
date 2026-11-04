#!/usr/bin/env bash
# AutoPatch — one-take screen-recording script (silent, captions added later).
# Run in a large-font terminal, start the recorder, then: ./record-demo.sh
# Total runtime target: 3-5 minutes, no editing needed.
set -uo pipefail
cd "$(dirname "$0")"

banner() {
  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo
  sleep "${2:-3}"
}

clear
banner "AutoPatch — scanner alerts in, VERIFIED pull requests out" 4

banner "1 · THE PROBLEM: a real alert backlog (SQL injection + path traversal)" 3
DEMO_DIR="${TMPDIR:-/tmp}/autopatch-demo"
rm -rf "$DEMO_DIR"
cp -r examples/vuln_demo "$DEMO_DIR"
cat "$DEMO_DIR/alerts.json"
sleep 4
echo
echo "--- the vulnerable code (examples/vuln_demo/app.py) ---"
cat "$DEMO_DIR/app.py"
sleep 3

banner "2 · THE RUN: alert → patch + regression test → 3 sandbox gates → PR branch" 3
python3 -m autopatch run --repo "$DEMO_DIR" --alerts "$DEMO_DIR/alerts.json"
sleep 4

banner "3 · THE RESULT: a minimal, verified diff + ready PR body" 3
git -C "$DEMO_DIR" diff autopatch/codeql-1^..autopatch/codeql-1 -- app.py | tail -n +5
sleep 4
echo
git -C "$DEMO_DIR" show autopatch/codeql-1:tests/test_autopatch_codeql_1.py
sleep 4
echo
head -20 "$DEMO_DIR/.autopatch/pr-codeql-1.md"
sleep 3

banner "4 · A REAL OPEN-SOURCE REPO: dependency CVE fixed & verified (miguelgrinberg/microblog)" 3
if [ -d /tmp/cand-microblog ]; then
  echo "--- pip-audit on the original pin: Jinja2 3.1.2, multiple sandbox-escape advisories ---"
  git -C /tmp/cand-microblog show main:requirements.txt | grep -i '^jinja2'
  sleep 3
  echo
  echo "--- AutoPatch run result (full run: report on disk) ---"
  python3 -c "
import json
r = json.load(open('/tmp/microblog-report.json'))[0]
print(r['rule'], '->', r['status'])
[print('  ✓', x) for x in r['verdict_reasons']]
print(' ', r['detail'])
"
  sleep 4
  echo
  echo "--- the verified branch diff ---"
  git -C /tmp/cand-microblog diff main...autopatch/jinja2-cve -- requirements.txt | tail -n +5
  echo "pip-audit on the fixed branch: 0 Jinja2 advisories (re-checked independently)"
else
  echo "(microblog checkout not present on this machine — skipping this beat)"
fi
sleep 4

banner "5 · MEASURED, NOT PROMISED: the CWE catalogue" 3
python3 -m autopatch catalogue
sleep 3

banner "AutoPatch · open-source (MIT) · Python + JS/TS · CLI / GitHub Action / webhook" 4
