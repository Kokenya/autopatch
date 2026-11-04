"""Webhook payload mapping (GitHub code_scanning_alert shape)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.server import _alert_from_event


def test_github_code_scanning_payload():
    payload = {
        "alert": {
            "number": 42,
            "rule": {"id": "py/sql-injection", "severity": "critical"},
            "most_recent_instance": {
                "location": {"path": "app.py", "start_line": 19},
                "message": {"text": "SQL built from user data"},
            },
        }
    }
    a = _alert_from_event(payload)
    assert a is not None
    assert (a.id, a.rule, a.file, a.line, a.kind) == (
        "42", "py/sql-injection", "app.py", 19, "sql-injection")


def test_simple_demo_payload_and_empty():
    a = _alert_from_event({"id": "x1", "rule": "py/path-injection",
                           "file": "app.py", "line": 24, "message": "m"})
    assert a is not None and a.kind == "path-traversal"
    assert _alert_from_event({}) is None
    assert _alert_from_event({"rule": "py/sql-injection"}) is None
