"""Path containment: every repo-relative path from untrusted input
(alerts, LLM replies, webhook payloads) must resolve INSIDE the repo."""

from __future__ import annotations

from pathlib import Path


class PathEscape(ValueError):
    """A repo-relative path resolved outside its root."""


def safe_join(root: Path, rel: str) -> Path:
    target = (Path(root) / rel).resolve()
    base = Path(root).resolve()
    if target != base and base not in target.parents:
        raise PathEscape(f"path escapes repo root: {rel!r}")
    return target
