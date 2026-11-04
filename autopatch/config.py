"""Per-repo configuration (autopatch.toml).

Real repos differ in test commands, setup steps and layout. Everything that
used to be hardcoded (pytest, timeouts, attempts) can be set here:

    # autopatch.toml in the target repo root (all keys optional)
    [autopatch]
    timeout = 300                # per test-run, seconds
    max_attempts = 3             # LLM regeneration attempts per alert
    setup_command = "pip install -r requirements.txt"

    [autopatch.python]
    test_command = "python -m pytest -q"
    test_one_command = "python -m pytest -q {file}"

    [autopatch.javascript]
    test_command = "npm test --silent"
    test_one_command = "node --test {file}"

Commands are split with shlex and run without a shell.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LangConfig:
    test_command: str = ""
    test_one_command: str = ""
    setup_command: str = ""


@dataclass
class Config:
    timeout: int = 300
    max_attempts: int = 3
    setup_command: str = ""
    rescan: bool = False  # 4th gate: scanner must no longer report the alert
    languages: dict[str, LangConfig] = field(default_factory=dict)

    def lang(self, name: str) -> LangConfig:
        return self.languages.get(name, LangConfig())


def load_config(repo: Path, explicit: str | Path | None = None) -> Config:
    path = Path(explicit) if explicit else Path(repo) / "autopatch.toml"
    cfg = Config()
    if not path.is_file():
        return cfg
    data = tomllib.loads(path.read_text()).get("autopatch", {})
    cfg.timeout = int(data.get("timeout", cfg.timeout))
    cfg.max_attempts = int(data.get("max_attempts", cfg.max_attempts))
    cfg.setup_command = str(data.get("setup_command", ""))
    cfg.rescan = bool(data.get("rescan", False))
    for name in ("python", "javascript"):
        sub = data.get(name, {})
        if sub:
            cfg.languages[name] = LangConfig(
                test_command=str(sub.get("test_command", "")),
                test_one_command=str(sub.get("test_one_command", "")),
                setup_command=str(sub.get("setup_command", "")),
            )
    return cfg
