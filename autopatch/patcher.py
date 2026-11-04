"""Patch + regression-test generation.

Primary path: Meta code-reasoning model returns a unified diff and a test.
Fallback path: deterministic transforms for well-understood CWE classes, so
verification (the load-bearing part of AutoPatch) can be demoed offline.
Only a patch that later passes sandbox verification is ever proposed.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path

from .alerts import Alert
from .llm import MetaLLM


@dataclass
class FilePatch:
    file: str
    original: str
    patched: str


class PatchResult:
    """One proposed fix: 1..n patched files + one regression test.
    source: "meta-llm" | "rule-fallback" | "dependency-bump"."""

    files: list[FilePatch]
    test_file: str
    test_code: str
    explanation: str
    source: str

    def __init__(self, test_file: str, test_code: str, explanation: str, source: str,
                 files: list[FilePatch] | None = None,
                 file: str = "", original: str = "", patched: str = ""):
        # `file/original/patched` kwargs kept for the single-file call sites.
        self.files = files if files is not None else [FilePatch(file, original, patched)]
        self.test_file, self.test_code = test_file, test_code
        self.explanation, self.source = explanation, source

    @property
    def file(self) -> str:
        return self.files[0].file

    @property
    def original(self) -> str:
        return self.files[0].original

    @property
    def patched(self) -> str:
        return self.files[0].patched

    @property
    def diff(self) -> str:
        out = []
        for fp in self.files:
            out.append("".join(difflib.unified_diff(
                fp.original.splitlines(keepends=True),
                fp.patched.splitlines(keepends=True),
                fromfile=f"a/{fp.file}", tofile=f"b/{fp.file}",
            )))
        return "".join(out)


def context_window(source: str, line: int, radius: int = 25) -> str:
    lines = source.splitlines()
    lo, hi = max(0, line - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1:4} {lines[i]}" for i in range(lo, hi))


# ---------------------------------------------------------------- LLM path

SYS = (
    "You are a defensive security engineer. Produce the SMALLEST patch that "
    "removes the reported vulnerability without changing behavior for valid "
    "inputs. Reply with JSON only: "
    '{"patched_files": {"<repo-relative path>": "<full new file content>"}, '
    '"test_code": "<regression test that FAILS on the vulnerable code and PASSES after the patch>", '
    '"explanation": "<two sentences>"} '
    "The regression test must EXECUTE the vulnerable behavior (call the "
    "function / drive the code path with an attack payload) and assert on the "
    "SECURITY OUTCOME (payload blocked, no row returned, verification enforced) "
    "— never on source text, and never merely that an argument/parameter is "
    "passed (a change with no behavioral effect is not a fix). "
    "If, reading the code, the alert is a FALSE POSITIVE (the dangerous "
    "pattern is already neutralized elsewhere in the shown code), do not "
    'invent a cosmetic patch: reply {"false_positive": "<one-sentence reason>"} '
    "and nothing else. "
    "patched_files must contain the alert file, plus only files that must "
    "change with it (imports, call sites, version pins that must move "
    "together, and living documentation that states the old behavior or "
    "version — a doc still prescribing the old state invites a revert; "
    "never edit changelogs or historical records). "
    "Keep every unchanged line identical. "
    'If the prompt gives you a single definition to patch instead of a full '
    'file, reply with {"patched_snippet": "<replacement for exactly those '
    'lines>", "test_code": ..., "explanation": ...} and no patched_files.'
)


class LLMError(RuntimeError):
    """LLM call/parse failure, surfaced instead of silently looking like no-patch."""


class FalsePositive(RuntimeError):
    """The model judged the alert a false positive on the shown code."""


def llm_patch(llm: MetaLLM, alert: Alert, source: str, feedback: str = "",
              repo: Path | None = None, runner=None) -> PatchResult | None:
    import json

    from .runner import Runner

    runner = runner or Runner("python", None, None)
    # Large files: operate on the enclosing definition span only (stage 1).
    # The model returns a replacement snippet for those exact lines; every
    # line outside the span is preserved byte-for-byte by splicing.
    from .context import enclosing_span

    span = None
    if len(source.splitlines()) > 400:
        span = enclosing_span(source, alert.line, runner.language)
    if span is not None:
        user = (
            f"Alert: {alert.rule} ({alert.cwe}) severity={alert.severity}\n"
            f"Message: {alert.message}\nFile: {alert.file} line {alert.line}\n"
            f"The regression test must be {runner.test_framework_hint}. "
            f"It will be saved as {runner.test_file_for(alert.id, alert.file)}.\n\n"
            f"Module imports (context only, do not repeat):\n```\n{span.header}```\n"
            f"Definition to patch (lines {span.start}-{span.end} of {alert.file}; "
            f"reply with patched_snippet replacing EXACTLY these lines, same "
            f"indentation and signature):\n```\n{span.extract(source)}```"
        )
    else:
        user = (
            f"Alert: {alert.rule} ({alert.cwe}) severity={alert.severity}\n"
            f"Message: {alert.message}\nFile: {alert.file} line {alert.line}\n"
            f"The regression test must be {runner.test_framework_hint}. "
            f"It will be saved as {runner.test_file_for(alert.id, alert.file)}.\n\n"
            f"Context:\n{context_window(source, alert.line)}\n\n"
            f"Full file:\n```\n{source}\n```"
        )
    if feedback:
        user += (
            "\n\nA previous attempt was REJECTED by sandbox verification:\n"
            f"{feedback}\n"
            "Fix exactly that problem. The regression test must FAIL on the "
            "vulnerable code above and PASS after your patch, and the existing "
            "test suite must keep passing."
        )
    try:
        raw = llm.chat(SYS, user)
    except Exception as exc:
        raise LLMError(f"Meta API call failed: {exc}") from exc
    try:
        data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
    except Exception as exc:
        raise LLMError(f"could not parse LLM reply as patch JSON: {exc}") from exc
    if data.get("false_positive"):
        raise FalsePositive(str(data["false_positive"]))
    try:
        if span is not None and data.get("patched_snippet"):
            patched_files = {alert.file: span.splice(source, data["patched_snippet"])}
        else:
            patched_files = data.get("patched_files") or {alert.file: data["patched_file"]}
    except Exception as exc:
        raise LLMError(f"could not parse LLM reply as patch JSON: {exc}") from exc

    files: list[FilePatch] = []
    for path, content in patched_files.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise LLMError(f"LLM returned unsafe path: {path}")
        if path == alert.file:
            original = source
        elif repo is not None and (repo / path).is_file():
            original = (repo / path).read_text()
        else:
            continue  # never invent originals for files we cannot read
        if content.strip() != original.strip():
            files.append(FilePatch(path, original, content))
    if not files or not data.get("test_code", "").strip():
        return None
    return PatchResult(
        files=files,
        test_file=runner.test_file_for(alert.id, alert.file),
        test_code=data["test_code"], explanation=data.get("explanation", ""),
        source="meta-llm",
    )


# ---------------------------------------------------------- fallback path

def _fix_sql_injection(source: str) -> str | None:
    out, changed = [], False
    for line in source.splitlines(keepends=True):
        # cursor.execute(f"... {expr} ...")
        m = re.search(r'(\.execute\()f"([^"]*)"', line)
        if m and "{" in m.group(2):
            exprs = re.findall(r"\{([^}]+)\}", m.group(2))
            sql = re.sub(r"'\{[^}]+\}'", "?", m.group(2))
            sql = re.sub(r"\{[^}]+\}", "?", sql)
            params = ", ".join(exprs) + ("," if len(exprs) == 1 else "")
            line = line[: m.start()] + f'{m.group(1)}"{sql}", ({params})' + line[m.end():]
            changed = True
        # cursor.execute("... %s ..." % expr)
        m = re.search(r'(\.execute\()"([^"]*%s[^"]*)"\s*%\s*(\(?[^)]+\)?)(\))', line)
        if m:
            sql = m.group(2).replace("%s", "?").replace("'?'", "?")
            expr = m.group(3).strip()
            params = expr if expr.startswith("(") else f"({expr},)"
            line = line[: m.start()] + f'{m.group(1)}"{sql}", {params}{m.group(4)}' + line[m.end():]
            changed = True
        # "...".format(expr)
        m = re.search(r'(\.execute\()"([^"]*)\{\}([^"]*)"\.format\(([^)]+)\)(\))', line)
        if m:
            sql = (m.group(2) + "?" + m.group(3)).replace("'?'", "?")
            line = (line[: m.start()] + f'{m.group(1)}"{sql}", ({m.group(4)},){m.group(5)}'
                    + line[m.end():])
            changed = True
        out.append(line)
    return "".join(out) if changed else None


def _fix_path_traversal(source: str) -> str | None:
    if "os.path.join" not in source and "open(" not in source:
        return None
    guard = (
        "def _autopatch_safe_join(base, name):\n"
        "    import os as _os\n"
        "    p = _os.path.realpath(_os.path.join(base, name))\n"
        "    if not p.startswith(_os.path.realpath(base) + _os.sep):\n"
        "        raise ValueError('path escapes base directory')\n"
        "    return p\n\n\n"
    )
    patched, n = re.subn(r"os\.path\.join\(([^,]+),\s*([^)]+)\)",
                         r"_autopatch_safe_join(\1, \2)", source)
    return guard + patched if n else None


def _fix_command_injection(source: str) -> str | None:
    """os.system("cmd " + x) / os.system(f"cmd {x}") -> argv-list subprocess.
    Returns an os.system-compatible status (exit code << 8 on POSIX)."""
    helper = (
        "def _autopatch_run(argv):\n"
        "    import subprocess as _sp\n"
        "    return _sp.run(argv).returncode << 8\n\n\n"
    )
    changed = False

    def argv_of(cmd: str, exprs: list[str]) -> str:
        parts = [repr(w) for w in cmd.split() if w]
        return "[" + ", ".join(parts + exprs) + "]"

    def sub_concat(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"_autopatch_run({argv_of(m.group(1), [m.group(2).strip()])})"

    def sub_fstring(m: re.Match) -> str:
        nonlocal changed
        changed = True
        exprs = re.findall(r"\{([^}]+)\}", m.group(1))
        cmd = re.sub(r"\{[^}]+\}", "", m.group(1))
        return f"_autopatch_run({argv_of(cmd, exprs)})"

    out = re.sub(r'os\.system\(\s*"([^"]*?)"\s*\+\s*([^)]+)\)', sub_concat, source)
    out = re.sub(r"os\.system\(\s*f\"([^\"]*)\"\)", sub_fstring, out)
    out = re.sub(r'os\.system\(\s*"([^"]*?)"\s*%\s*\(?([^)]+)\)', sub_concat, out)
    return helper + out if changed else None


def _fix_xss(source: str) -> str | None:
    """Escape interpolated values in HTML-building strings."""
    changed = False

    def esc_fstring(m: re.Match) -> str:
        nonlocal changed
        body = m.group(2)
        if "<" not in body or "{" not in body:
            return m.group(0)
        changed = True
        body = re.sub(r"\{([A-Za-z_][\w.\[\]()]*)\}", r"{_autopatch_escape(\1)}", body)
        return f"{m.group(1)}f\"{body}\""

    out = re.sub(r'(\breturn\s+)f"([^"]*)"', esc_fstring, source)

    def esc_concat(m: re.Match) -> str:
        nonlocal changed
        if "<" not in m.group(0):
            return m.group(0)
        changed = True
        return f"+ _autopatch_escape({m.group(1)}) +"

    out = re.sub(r"\+\s*([A-Za-z_][\w.]*)\s*\+", esc_concat, out)
    if not changed:
        return None
    if "_autopatch_escape" not in source:
        out = "from html import escape as _autopatch_escape\n\n" + out
    return out


def _fix_open_redirect(source: str) -> str | None:
    """`not x.startswith('/')` misses //evil.example (protocol-relative)
    and /\\evil.example (browsers normalize backslashes). Strengthen to a
    netloc + separator check, the shape mature codebases use."""
    pat = re.compile(r"not\s+([A-Za-z_][\w.]*)\.startswith\(['\"]/['\"]\)")
    if not pat.search(source):
        return None
    if "urlsplit" in source and "netloc" in source and "\\\\" in source:
        return None  # already guards both separators
    def repl(m: re.Match) -> str:
        x = m.group(1)
        return (f"(urlsplit({x}).netloc != '' or not {x}.startswith('/') "
                f"or {x}[1:2] in ('/', chr(92)) "
                f"or any(ord(c) < 32 or ord(c) == 127 for c in {x}))")
    out = pat.sub(repl, source)
    if "urlsplit" not in source:
        out = "from urllib.parse import urlsplit\n" + out
    return out


def _fix_xxe(source: str) -> str | None:
    """Stdlib XML parsing -> defusedxml (forbids entities/DTDs)."""
    out, n = re.subn(r"import\s+xml\.etree\.ElementTree\s+as\s+(\w+)",
                     r"import defusedxml.ElementTree as \1", source)
    out2, n2 = re.subn(r"from\s+xml\.etree\.ElementTree\s+import",
                       "from defusedxml.ElementTree import", out)
    out3, n3 = re.subn(r"from\s+xml\.etree\s+import\s+ElementTree",
                       "import defusedxml.ElementTree as ElementTree", out2)
    return out3 if (n + n2 + n3) else None


_FALLBACK_FIX = {
    "sql-injection": _fix_sql_injection,
    "path-traversal": _fix_path_traversal,
    "command-injection": _fix_command_injection,
    "xss": _fix_xss,
    "open-redirect": _fix_open_redirect,
    "xxe": _fix_xxe,
}

_FALLBACK_NEEDLE = {
    "path-traversal": "os.path.join",
    "command-injection": "os.system",
    "xss": 'f"<',
    "open-redirect": ".startswith(",
    "xxe": "fromstring",
}

def _enclosing_function(source: str, needle: str) -> str | None:
    """Name of the def that contains the first line mentioning `needle`."""
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if needle in line and line[:1].isspace():  # inside a function body
            for j in range(i, -1, -1):
                m = re.match(r"def (\w+)\(", lines[j])
                if m:
                    return m.group(1)
    return None


_FALLBACK_TEST = {
    "sql-injection": '''"""AutoPatch regression test: SQL injection payload must not authenticate."""
from {mod} import *

def test_sqli_payload_rejected():
    # Classic tautology payload: on vulnerable code this returns a row.
    try:
        result = find_user("' OR '1'='1")  # noqa: F821 - name resolved per target repo
    except NameError:
        raise AssertionError("target lookup function not found; LLM test required")
    assert result is None, "injection payload returned a user row"
''',
    "path-traversal": '''"""AutoPatch regression test: ../ payload must not escape the base dir."""
import pytest

from {mod} import {func}


def test_path_traversal_blocked():
    # On vulnerable code this reads the module source itself (outside base).
    with pytest.raises((ValueError, PermissionError)):
        {func}("../{mod}.py")
''',
    "command-injection": '''"""AutoPatch regression test: shell metacharacters must not execute."""
import os

from {mod} import {func}

MARKER = "/tmp/autopatch_cmdinj_marker"


def test_command_injection_blocked():
    if os.path.exists(MARKER):
        os.unlink(MARKER)
    try:
        {func}("127.0.0.1; touch " + MARKER)
    except Exception:
        pass  # an argv-list call may legitimately error on the bogus host
    assert not os.path.exists(MARKER), "shell metacharacters were executed"
''',
    "xss": '''"""AutoPatch regression test: markup in input must be escaped."""
from {mod} import {func}


def test_xss_payload_escaped():
    out = {func}("<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
''',
    "open-redirect": '''"""AutoPatch regression test: protocol-relative URLs must not pass as local."""
from {mod} import {func}


def test_protocol_relative_blocked():
    assert {func}("//evil.example/phish") == "/"
    assert {func}("/" + chr(92) + "evil.example") == "/"
    assert {func}("https://evil.example") == "/"
    assert {func}("/dashboard") == "/dashboard"
''',
    "xxe": '''"""AutoPatch regression test: entity expansion must be refused."""
import pytest

from {mod} import {func}

PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY a "xxxxxxxxxx"> <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"> ]>
<r>&b;</r>"""


def test_xxe_refused():
    with pytest.raises(Exception):
        {func}(PAYLOAD)
''',
}


_JS_ESCAPE = (
    "const _autopatchEscape = (v) => String(v).replace(/&/g, '&amp;')"
    ".replace(/</g, '&lt;').replace(/>/g, '&gt;')"
    ".replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"
)


def _fix_xss_js(source: str) -> str | None:
    changed = False

    def wrap(m: re.Match) -> str:
        nonlocal changed
        changed = True
        return f"+ _autopatchEscape({m.group(1)}) +"

    # '<tag>' + expr + '</tag>' style concatenation only (line must contain '<')
    lines = []
    for line in source.splitlines(keepends=True):
        if "<" in line and "+" in line:
            line = re.sub(r"\+\s*([A-Za-z_$][\w$.]*)\s*\+", wrap, line)
        lines.append(line)
    if not changed:
        return None
    return _JS_ESCAPE + "".join(lines)


_JS_FALLBACK_TEST_XSS = """import {{ test }} from 'node:test';
import assert from 'node:assert/strict';
import {{ {func} }} from './{base}';

test('xss payload is escaped', () => {{
  const out = {func}('<script>alert(1)</script>');
  assert.ok(!out.includes('<script>'), 'raw script tag in output');
  assert.ok(out.includes('&lt;script&gt;'), 'payload not escaped');
}});
"""


def _js_fallback_patch(alert: Alert, source: str) -> PatchResult | None:
    if alert.kind != "xss":
        return None
    patched = _fix_xss_js(source)
    if patched is None or patched == source:
        return None
    from .context import enclosing_span
    from .runner import Runner
    span = enclosing_span(source, alert.line, "javascript")
    func = ""
    if span:
        m = re.search(r"(?:function\s+|const\s+|let\s+|var\s+)(\w+)", span.extract(source))
        func = m.group(1) if m else ""
    if not func:
        return None
    runner = Runner("javascript", None, None)
    return PatchResult(
        file=alert.file, original=source, patched=patched,
        test_file=runner.test_file_for(alert.id, alert.file),
        test_code=_JS_FALLBACK_TEST_XSS.format(func=func, base=Path(alert.file).name),
        explanation=(f"Escapes interpolated values in the generated markup. "
                     f"Fixes {alert.rule} ({alert.cwe})."),
        source="rule-fallback",
    )


def fallback_patch(alert: Alert, source: str) -> PatchResult | None:
    if Path(alert.file).suffix.lower() in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return _js_fallback_patch(alert, source)
    fix = _FALLBACK_FIX.get(alert.kind)
    if not fix:
        return None
    patched = fix(source)
    if patched is None or patched == source:
        return None
    mod = Path(alert.file).stem
    needle = _FALLBACK_NEEDLE.get(alert.kind, "")
    func = _enclosing_function(source, needle) or "" if needle else ""
    if alert.kind == "xss" and not func:
        from .context import enclosing_span
        span = enclosing_span(source, alert.line, "python")
        if span:
            first = span.extract(source).splitlines()[0]
            m = re.search(r"def (\w+)\(", first)
            func = m.group(1) if m else ""
    test = _FALLBACK_TEST.get(alert.kind, "").format(mod=mod, func=func)
    if alert.kind in ("path-traversal", "command-injection", "xss",
                      "open-redirect", "xxe") and not func:
        test = ""
    return PatchResult(
        file=alert.file, original=source, patched=patched,
        test_file=f"tests/test_autopatch_{alert.id.replace('/', '_').replace('-', '_')}.py",
        test_code=test,
        explanation={
            "sql-injection": (
                f"Parameterized the query so user input is bound as data, never parsed as SQL. "
                f"Fixes {alert.rule} ({alert.cwe}) at {alert.file}:{alert.line}."),
            "path-traversal":
                f"Confines joined paths to the base directory. Fixes {alert.rule} ({alert.cwe}).",
            "command-injection":
                f"Runs the command as an argv list without a shell, so metacharacters in input "
                f"are data, not syntax. Fixes {alert.rule} ({alert.cwe}).",
            "xss":
                f"Escapes interpolated values in the generated markup. "
                f"Fixes {alert.rule} ({alert.cwe}).",
            "open-redirect":
                f"Rejects protocol-relative and absolute redirect targets via a netloc check. "
                f"Fixes {alert.rule} ({alert.cwe}).",
            "xxe":
                f"Parses XML with defusedxml, which forbids entities and DTDs. "
                f"Fixes {alert.rule} ({alert.cwe}).",
        }.get(alert.kind, f"Deterministic fix for {alert.rule} ({alert.cwe})."),
        source="rule-fallback",
    )


def generate_patch(alert: Alert, source: str, llm: MetaLLM | None = None,
                   feedback: str = "", repo: Path | None = None,
                   runner=None) -> PatchResult | None:
    llm = llm or MetaLLM()
    if alert.kind == "dependency":
        from .deps import dependency_patch
        return dependency_patch(alert, repo) if repo is not None else None
    if llm.enabled:
        got = llm_patch(llm, alert, source, feedback=feedback, repo=repo, runner=runner)
        if got:
            return got
    return fallback_patch(alert, source)
