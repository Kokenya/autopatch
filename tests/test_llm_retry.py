"""LLM client retry: transient failures retry, client errors fail fast."""

import io
import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import autopatch.llm as llm_mod
from autopatch.llm import MetaLLM


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _ok_body():
    return _Resp(json.dumps({"choices": [{"message": {"content": "pong"}}]}).encode())


def test_timeout_then_success(monkeypatch):
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def flaky(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("read operation timed out")
        return _ok_body()

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", flaky)
    llm = MetaLLM()
    llm.key = "k"
    assert llm.chat("s", "u") == "pong"
    assert calls["n"] == 2


def test_client_error_fails_fast(monkeypatch):
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def bad(req, timeout=None):
        calls["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 402, "billing", None, None)

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", bad)
    llm = MetaLLM()
    llm.key = "k"
    try:
        llm.chat("s", "u")
        raise AssertionError("should have raised")
    except urllib.error.HTTPError:
        pass
    assert calls["n"] == 1  # no retry on 4xx
