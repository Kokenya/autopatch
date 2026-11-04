# Submission draft — AutoPatch

> Working draft for the hackathon form. Edit freely; every claim below is
> verifiable from this repository (benchmarks/results.json, tests/).

**Project name:** AutoPatch

**Tagline:** Scanner alerts in — verified pull requests out.

**What it does.** AutoPatch turns static-analysis alerts (SARIF, Semgrep, CodeQL-style) into fix pull requests that are only proposed after mechanical verification: a generated regression test must fail on the vulnerable code, pass after the patch, and the repo's existing suite must show no new failures. Unverifiable patches are rejected, and alerts the model judges to be false positives are triaged instead of cosmetically "fixed".

**How we built it.** A zero-dependency Python agent around the Meta Model API (muse-spark-1.3): structure-aware context extraction (AST/brace spans so large files are patched surgically), deterministic fallbacks for SQL injection, path traversal and dependency CVEs (including lockfile regeneration and co-pinned docs/scripts), an isolated sandbox (temp copy, scrubbed environment, baseline-aware suite gate, optional scanner re-scan gate), and worktree-based branch/PR creation that never touches the operator's working tree. Python and JavaScript/TypeScript targets; CLI, GitHub Action and a webhook receiver.

**Measured, not promised.** On our 8-case benchmark corpus: 5/8 verified fixes offline, 8/8 with the live API (`benchmarks/run.py`). Tested on a real production codebase (replayr): one PR was reviewed and closed as a false positive — the learnings (false-positive triage, outcome-based tests, suite-native test placement) shipped as product changes with regression tests. A critical dependency advisory fix followed as a full migration PR.

**Challenges.** Making "verified" mean something: vacuous regression tests, test placement outside the target's discovery, version pins split across manifests/scripts/docs, and running untrusted test suites safely.

**Repo: https://github.com/Kokenya/autopatch

**Try it.** `./demo.sh` (or `./demo.sh --offline`, no API key needed). `pip install .` then `autopatch scan|run|serve|catalogue`.

**License:** MIT. **Stack:** Python 3.11 stdlib only; Meta Model API; Semgrep; node --test; Docker.
