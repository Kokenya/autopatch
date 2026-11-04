"""Deterministic fallbacks: command injection, XSS (Python + JS), SARIF upload payload."""

import base64
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.alerts import Alert
from autopatch.patcher import _fix_command_injection, _fix_xss, _fix_xss_js, fallback_patch
from autopatch.sarif_out import upload_payload


def test_command_injection_transform():
    src = 'import os\n\n\ndef ping(host):\n    return os.system("ping -c 1 " + host)\n'
    out = _fix_command_injection(src)
    assert out is not None
    assert "_autopatch_run(['ping', '-c', '1', host])" in out
    assert "os.system" not in out.split("def ping")[1]
    compile(out, "<patched>", "exec")


def test_xss_python_transform():
    src = 'def render(name):\n    return f"<h1>Hello {name}</h1>"\n'
    out = _fix_xss(src)
    assert out is not None and "_autopatch_escape(name)" in out
    assert out.startswith("from html import escape as _autopatch_escape")


def test_xss_js_transform():
    src = "export function render(name) {\n  return '<h1>Hello ' + name + '</h1>';\n}\n"
    out = _fix_xss_js(src)
    assert out is not None and "_autopatchEscape(name)" in out


def test_fallbacks_refuse_unmatched():
    assert _fix_command_injection("x = 1\n") is None
    assert _fix_xss("x = 1\n") is None
    a = Alert(id="z", rule="js/xss", severity="high", file="a.mjs", line=1,
              message="m", cwe="CWE-79")
    assert fallback_patch(a, "export const x = 1;\n") is None


def test_upload_payload_roundtrip(tmp_path):
    sarif = tmp_path / "r.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    payload = upload_payload(sarif, "abc123", "refs/heads/main")
    assert payload["commit_sha"] == "abc123"
    raw = gzip.decompress(base64.b64decode(payload["sarif"]))
    assert json.loads(raw)["version"] == "2.1.0"
