#!/usr/bin/env bash
# AutoPatch one-command demo.
#   ./demo.sh           live run (Meta Model API if .env key is set, else offline fallback)
#   ./demo.sh --offline force the deterministic offline fallback (no API credits spent)
set -euo pipefail
cd "$(dirname "$0")"

DEMO_DIR="${TMPDIR:-/tmp}/autopatch-demo"
rm -rf "$DEMO_DIR"
cp -r examples/vuln_demo "$DEMO_DIR"

if [ "${1:-}" = "--offline" ]; then
  export META_API_KEY=""   # real env wins over .env -> offline fallback
  echo "(offline mode: rule-based fallback, no API credits spent)"
fi

python3 -m autopatch run --repo "$DEMO_DIR" --alerts "$DEMO_DIR/alerts.json"

echo
echo "=== Fix branches ==="
git -C "$DEMO_DIR" log --oneline --all
echo
echo "=== Verified diff (SQL injection) ==="
git -C "$DEMO_DIR" show autopatch/codeql-1 --stat --format="" | tail -3
git -C "$DEMO_DIR" diff autopatch/codeql-1^..autopatch/codeql-1 -- app.py | tail -n +5
echo
echo "PR bodies: $DEMO_DIR/.autopatch/pr-codeql-1.md , pr-codeql-2.md"
