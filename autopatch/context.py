"""Structure-aware context extraction (ROADMAP stage 1).

Feeding a whole file to the model blows the context budget on real files
and invites reformatting churn. Instead, for large files AutoPatch sends
only the *enclosing definition span* around the alert line (plus module
imports), asks for a replacement snippet for exactly those lines, and
splices the result back — every line outside the span is preserved
byte-for-byte.

Python spans come from the `ast` module (exact def/class boundaries).
JS/TS spans use a brace-balance scan from the nearest preceding
`function`/`=>`/`class` header. Anything unparseable falls back to None
and the caller uses the whole-file path.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass
class Span:
    start: int  # 1-based, inclusive
    end: int    # 1-based, inclusive
    header: str  # imports / module prelude shown for context (not replaced)

    def extract(self, source: str) -> str:
        lines = source.splitlines(keepends=True)
        return "".join(lines[self.start - 1:self.end])

    def splice(self, source: str, replacement: str) -> str:
        lines = source.splitlines(keepends=True)
        if not replacement.endswith("\n"):
            replacement += "\n"
        return "".join(lines[:self.start - 1]) + replacement + "".join(lines[self.end:])


def _python_span(source: str, line: int) -> Span | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    best: ast.AST | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            if start <= line <= (node.end_lineno or start):
                if best is None or start >= best.lineno:  # innermost enclosing def
                    best = node
    if best is None:
        return None
    lines = source.splitlines(keepends=True)
    header_parts = []
    for node in tree.body:  # module-level imports only
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            header_parts.append("".join(lines[node.lineno - 1:(node.end_lineno or node.lineno)]))
    start = min([d.lineno for d in best.decorator_list] + [best.lineno])
    return Span(start=start, end=best.end_lineno or start, header="".join(header_parts))


_JS_HEADER = re.compile(r"(?:(?:export\s+)?(?:async\s+)?function\s+\w+|class\s+\w+|"
                        r"(?:const|let|var)\s+\w+\s*=.*(?:=>|function)|"
                        r"\w+\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>)")


def _js_span(source: str, line: int) -> Span | None:
    lines = source.splitlines(keepends=True)
    start = None
    for i in range(min(line, len(lines)) - 1, -1, -1):
        if _JS_HEADER.search(lines[i]) and "{" in "".join(lines[i:i + 3]):
            start = i
            break
    if start is None:
        return None
    depth, opened = 0, False
    for j in range(start, len(lines)):
        text = re.sub(r"'(?:\\.|[^'])'|\"(?:\\.|[^\"])*\"|`(?:\\.|[^`])*`", "''", lines[j])
        depth += text.count("{") - text.count("}")
        opened = opened or "{" in text
        if opened and depth <= 0:
            header = "".join(l for l in lines[:start] if l.startswith(("import ", "const ", "require(")))
            return Span(start=start + 1, end=j + 1, header="".join(header))
    return None


def enclosing_span(source: str, line: int, language: str) -> Span | None:
    if language == "javascript":
        return _js_span(source, line)
    return _python_span(source, line)
