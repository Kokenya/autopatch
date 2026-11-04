"""GitHub App webhook receiver.

Listens for `code_scanning_alert` / check-suite style events (and a simple
JSON POST for demos), maps them to Alert objects and runs the agent loop.
Verify the webhook signature when GITHUB_WEBHOOK_SECRET is set.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .agent import remediate
from .alerts import Alert
from .env import load_env

load_env()


def _alert_from_event(payload: dict) -> Alert | None:
    a = payload.get("alert") or payload
    instance = (a.get("most_recent_instance") or {}).get("location", {})
    rule_obj = a.get("rule")
    rule = rule_obj.get("id", "") if isinstance(rule_obj, dict) else (rule_obj or "")
    file = instance.get("path") or a.get("file", "")
    if not rule or not file:
        return None
    try:
        line = int(instance.get("start_line") or a.get("line", 1))
    except (TypeError, ValueError):
        line = 1
    return Alert(
        id=str(a.get("number") or a.get("id") or rule),
        rule=rule,
        severity=(rule_obj.get("severity") if isinstance(rule_obj, dict) else None)
        or a.get("severity", "high"),
        file=file,
        line=line,
        message=(instance.get("message") or {}).get("text") or a.get("message", ""),
        cwe=a.get("cwe", ""),
    )


def serve(repo: str, port: int, push: bool = False) -> None:
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if push and not secret:
        raise SystemExit("refusing --push without GITHUB_WEBHOOK_SECRET: an "
                         "unauthenticated POST could otherwise trigger pushes "
                         "with your gh credentials")
    if not secret:
        print("WARNING: GITHUB_WEBHOOK_SECRET unset — webhook signatures NOT verified")
    repo_path = Path(repo)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                return self._send(200, {"ok": True, "repo": str(repo_path)})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, {"error": "bad Content-Length"})
            if length > 1_000_000:
                return self._send(413, {"error": "payload too large"})
            body = self.rfile.read(length)
            if secret:
                sig = self.headers.get("X-Hub-Signature-256", "")
                want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, want):
                    return self._send(401, {"error": "bad signature"})
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON"})
            alert = _alert_from_event(payload)
            if alert is None:
                return self._send(400, {"error": "no alert in payload"})
            try:
                rep = remediate(repo_path, alert, push=push)
            except Exception as exc:  # never drop the connection on a bad repo/alert
                print(f"webhook alert={alert.id} outcome=error: {exc}")
                return self._send(500, {"error": f"remediation failed: {exc}"})
            print(f"webhook alert={alert.id} rule={alert.rule} outcome={rep.status}")
            self._send(200, {"status": rep.status, "detail": rep.detail, "pr": rep.pr})

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    print(f"AutoPatch webhook listening on :{port} for repo {repo_path}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
