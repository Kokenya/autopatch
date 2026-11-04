# AutoPatch — Autonomous Vulnerability Remediation Agent

**Status: Alpha (v0.2).** AutoPatch turns static security alerts into **verified,
ready-to-merge Pull Requests**. Scanners produce alert backlogs; engineers still
have to understand, fix, test and prove every finding by hand. AutoPatch closes
that loop:

```
scanner alert ─▶ structure-aware context ─▶ minimal patch (Meta model or deterministic fix)
              ─▶ targeted regression test ─▶ isolated sandbox verification (3 gates)
              ─▶ branch + Pull Request (only if verified)
```

## The verification contract (the core idea)

A patch is proposed **only** if, inside an isolated copy of the repo:

1. the generated regression test **fails on the vulnerable code** — it proves the bug is real,
2. the same test **passes after the patch** — the bug is actually fixed,
3. the repo's **existing test suite has no new failures** versus the unpatched
   baseline — no backwards-compat break, and pre-existing red tests don't block you.

If the sandbox rejects an LLM patch, the verdict and failing test output are fed
back to the model and the patch is regenerated (up to 3 attempts). Anything still
unverified is reported as rejected — it never becomes a PR.

## What it can fix today (measured, not promised)

Run `python3 -m autopatch catalogue` — the rates come from the benchmark corpus
in `benchmarks/`, refreshed by `python3 benchmarks/run.py [--live]`:

| Class | CWE | How | Benchmark (11 cases) |
|---|---|---|---|
| SQL injection | CWE-89 | deterministic parameterization + LLM | 3/3 verified (offline and live) |
| Path traversal | CWE-22 | deterministic base-dir confinement + LLM | 1/1 verified |
| Vulnerable dependency | CVE | deterministic manifest bump (requirements/pyproject/package.json) | 1/1 verified |
| XSS | CWE-79 | deterministic escaping (Python + JS) + LLM | 2/2 verified (offline and live) |
| Command injection | CWE-78 | deterministic argv-list transform + LLM | 1/1 verified (offline and live) |
| Open redirect | CWE-601 | deterministic netloc check + LLM | 1/1 verified; already-safe code correctly left alone |
| XXE | CWE-611 | deterministic defusedxml swap + LLM | 1/1 verified |
| Hard-coded secrets | CWE-798 | detect + redact (rotation stays human) | scanner-only |
| Any other scanner rule | — | LLM patch, sandbox-gated | unmeasured; rejected if unverifiable |

Languages: **Python** (pytest) and **JavaScript/TypeScript** (`node --test` for
regression tests; the repo's `npm`/`pnpm test` as the suite gate). Multi-file
patches are supported; files over 400 lines are patched span-locally (only the
enclosing function is sent to the model and spliced back, the rest of the file
is preserved byte-for-byte).

## Install

```bash
pip install .            # or: pip install ".[scan]" to also get Semgrep
# Docker (recommended for untrusted repos — their tests execute code):
docker build -t autopatch .
```

## Quickstart

```bash
./demo.sh                # demo target: SQL injection + path traversal, both fixed & verified
./demo.sh --offline      # deterministic tier only, no API credits
```

On your own repo:

```bash
cp .env.example .env     # put META_API_KEY in .env (git-ignored), or omit for offline tier
autopatch scan  --repo . --out alerts.json            # Semgrep -> alerts (or bring SARIF/CodeQL output)
autopatch run   --repo . --alerts alerts.json --report run.json
autopatch run   --repo . --alerts alerts.json --push  # + push branches, open real PRs via gh
```

`run` flags: `--dry-run` (verify only), `--report FILE` (JSON audit trail),
`--limit N`, `--max-attempts N`, `--config FILE`, `--sarif-out FILE`. Set `rescan = true` in `autopatch.toml` to add a 4th gate: the scanner must no longer report the alert on the patched code. Exit codes: 0 = ≥1 verified
fix, 1 = none verified, 2 = operational error.

Per-repo tuning goes in `autopatch.toml` at the repo root (test/setup commands,
timeout, attempts — see `autopatch/config.py` for the schema). Alert inputs:
SARIF 2.1, Semgrep JSON, or the simple JSON list (incl. Dependabot-style
dependency alerts with `package` + `fixed_version`).

## GitHub integration

- **Webhook receiver:** `autopatch serve --repo <checkout> --port 8080 --push`
  accepts `code_scanning_alert` events (HMAC-SHA256 checked when
  `GITHUB_WEBHOOK_SECRET` is set) and runs the loop against that checkout.
  Honest scope: this is a single-repo webhook endpoint you host yourself,
  **not** yet a multi-tenant GitHub App with installation tokens.
- **GitHub Action:** `action.yml` in this repo runs scan + remediation in CI.
- Branch/PR work happens in a temporary `git worktree` — your working tree
  and uncommitted changes are never touched. Re-runs skip alerts whose
  `autopatch/<id>` branch already exists.

## Safety model

Verification runs the target repo's tests — that is arbitrary code execution.
AutoPatch copies the repo to a temp dir, strips secrets (e.g. `META_API_KEY`)
from the test processes' environment, and enforces timeouts. That is process
isolation, not a VM: **run AutoPatch itself in the provided Docker image** for
untrusted repos.

## Layout

| Path | Role |
|---|---|
| `autopatch/alerts.py` | SARIF / Semgrep / simple-JSON alert ingesting, dedup |
| `autopatch/scanner.py` | run Semgrep to produce alerts |
| `autopatch/context.py` | structure-aware enclosing-definition spans (AST / brace scan) |
| `autopatch/patcher.py` | patch + regression test generation (LLM, span-splice, fallbacks) |
| `autopatch/deps.py` | deterministic dependency/CVE version bumps |
| `autopatch/runner.py` · `config.py` | per-language test runners · `autopatch.toml` |
| `autopatch/sandbox.py` | isolated 3-gate, baseline-aware verification |
| `autopatch/github_pr.py` | worktree branch/commit, PR body, `gh pr create` |
| `autopatch/server.py` | GitHub webhook receiver (`/health` included) |
| `autopatch/catalogue.py` | measured CWE support catalogue |
| `benchmarks/` | corpus + harness behind the measured rates |
| `examples/vuln_demo/` · `demo.sh` | demo target · one-command demo |
| `tests/` | 41 tests: e2e (Py+JS+deps), retry loop, spans, isolation, rescan gate, SARIF, server |

## Tests

```bash
python3 -m pytest tests/ -q     # fully offline, no API credits spent
```

## Not yet (honest roadmap)

- Hosted multi-tenant GitHub App (installation tokens, queue, dashboard)
- SARIF: `--sarif-out` writes the file, `autopatch upload-sarif` posts it to GitHub code scanning
- Broader public benchmark (current corpus: 11 cases — small, and labelled as such)
- More languages (Go/Java test runners via the same runner abstraction)
