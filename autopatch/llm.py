"""Meta Model API client (OpenAI-compatible chat completions).

Configuration comes from the environment or a local .env file (see
.env.example) — never hardcode a key in source:
  META_API_KEY   required to enable the LLM path
  META_BASE_URL  default: https://api.meta.ai/v1
  META_MODEL     default: muse-spark-1.3  (set to the model id from your hackathon access)
Without a key, callers fall back to deterministic rule-based patching so the
demo loop always runs end to end.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .env import load_env

load_env()


class MetaLLM:
    def __init__(self) -> None:
        self.key = os.environ.get("META_API_KEY", "")
        self.base = os.environ.get("META_BASE_URL", "https://api.meta.ai/v1").rstrip("/")
        self.model = os.environ.get("META_MODEL", "muse-spark-1.3")

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def chat(self, system: str, user: str, timeout: int = 120) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }
        # Transient failures (timeouts, 429, 5xx) retry with backoff; client
        # errors (auth, bad request, billing) fail immediately and loudly.
        last_exc: Exception | None = None
        for attempt in range(3):
            req = urllib.request.Request(
                f"{self.base}/chat/completions",
                data=json.dumps(payload).encode(),
                headers={
                    "Authorization": f"Bearer {self.key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"]
            except urllib.error.HTTPError as exc:
                if exc.code < 500 and exc.code != 429:
                    raise
                last_exc = exc
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                last_exc = exc
            if attempt < 2:
                time.sleep(2 ** attempt * 2)  # 2s, 4s
        raise RuntimeError(f"Meta API unreachable after 3 attempts: {last_exc}") from last_exc
