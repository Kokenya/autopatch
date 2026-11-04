"""Minimal .env loader (no third-party dependency).

Reads the first .env found in the current directory or the project root.
Real environment variables always win over .env values.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_env() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    candidates = [Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"]
    real_env = set(os.environ)
    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key not in real_env:  # real env wins; later .env lines win over earlier
                os.environ[key] = value
        return
