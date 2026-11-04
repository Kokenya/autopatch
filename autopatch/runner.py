"""Language/test-runner detection.

The verification gates need to run (a) one generated regression test and
(b) the repo's existing suite, in whatever language the alert's file is.
Detection order: autopatch.toml override -> repo conventions -> defaults.

JS/TS regression tests use the built-in `node --test` runner so they work
without installing a framework; the full suite uses the package.json
`test` script when present (npm/pnpm per lockfile).
"""

from __future__ import annotations

import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import Config

_SUFFIX_LANG = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
}


def detect_language(file: str) -> str:
    if Path(file).name == "package.json":
        return "javascript"
    return _SUFFIX_LANG.get(Path(file).suffix.lower(), "python")


@dataclass
class Runner:
    language: str
    test_all: list[str] | None      # None = no suite detected
    setup: list[str] | None
    workdir: str = "."               # relative to repo root (monorepo subdir)
    test_one_template: str = ""      # autopatch.toml override, {file} placeholder
    test_dir: str = "tests"          # nearest existing tests/ to the target file

    def test_one(self, test_file: str) -> list[str]:
        if self.test_one_template:
            return shlex.split(self.test_one_template.replace("{file}", test_file))
        if self.language == "javascript":
            return ["node", "--test", test_file]
        return [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_file]

    def test_file_for(self, alert_id: str, target_file: str = "") -> str:
        safe = alert_id.replace("/", "_").replace("-", "_")
        if self.language == "javascript":
            # Next to the target file, so `import ... from './file.js'` works
            # in any monorepo layout and node --test needs no config.
            parent = str(Path(target_file).parent)
            name = f"autopatch_{safe}.test.mjs"
            return name if parent == "." else f"{parent}/{name}"
        # Into the tests/ dir the target's own suite uses — a test the repo's
        # discovery never collects proves nothing in their CI (learned on replayr).
        return f"{self.test_dir}/test_autopatch_{safe}.py"

    @property
    def test_framework_hint(self) -> str:
        if self.language == "javascript":
            return ("a Node.js built-in test (import { test } from 'node:test'; "
                    "import assert from 'node:assert/strict'; run with `node --test`, "
                    "ES modules; the test file is saved NEXT TO the target file, "
                    "import it as './<basename>')")
        return "a pytest test"


def _nearest_package_dir(repo: Path, file: str) -> Path | None:
    here = (repo / file).parent
    while True:
        if (here / "package.json").is_file():
            return here
        if here == repo or repo not in here.parents:
            return None
        here = here.parent


def _split(cmd: str, file: str = "") -> list[str] | None:
    return shlex.split(cmd.replace("{file}", file)) if cmd.strip() else None


def _nearest_test_dir(repo: Path, file: str) -> str:
    """Walk up from the target file: first existing tests/ (or test/) dir wins."""
    here = (repo / file).parent
    while True:
        for name in ("tests", "test"):
            if (here / name).is_dir():
                return str((here / name).relative_to(repo))
        if here == repo or repo not in here.parents:
            return "tests"
        here = here.parent


def detect_runner(repo: Path, file: str, cfg: Config) -> Runner:
    lang = detect_language(file)
    lc = cfg.lang(lang)
    setup = _split(lc.setup_command or cfg.setup_command)

    if lang == "javascript":
        pkg_dir = _nearest_package_dir(repo, file)
        workdir = str(pkg_dir.relative_to(repo)) if pkg_dir else "."
        runner = Runner(lang, None, setup, workdir, test_one_template=lc.test_one_command)
        if lc.test_command:
            runner.test_all = _split(lc.test_command)
        elif pkg_dir is not None:
            try:
                pkg = json.loads((pkg_dir / "package.json").read_text())
            except (OSError, json.JSONDecodeError):
                pkg = {}
            if pkg.get("scripts", {}).get("test"):
                pm = "pnpm" if (pkg_dir / "pnpm-lock.yaml").exists() else "npm"
                runner.test_all = [pm, "test", "--silent"] if pm == "npm" else [pm, "test"]
        return runner

    runner = Runner(lang, [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], setup,
                    test_one_template=lc.test_one_command,
                    test_dir=_nearest_test_dir(repo, file))
    if lc.test_command:
        runner.test_all = _split(lc.test_command)
    return runner
