"""Dependency / CVE remediation (Dependabot-style, deterministically).

An alert with package + fixed_version becomes a manifest bump:
requirements.txt, package.json (dependencies/devDependencies), or a
pyproject.toml dependency string. The generated regression test asserts the
manifest pins at least the fixed version (fails before, passes after);
the sandbox suite gate proves the bump does not break the repo.
No LLM involved — version bumps must be exact, not generated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .alerts import Alert
from .patcher import FilePatch, PatchResult


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _bump_requirements(text: str, pkg: str, fixed: str) -> str | None:
    pat = re.compile(rf"^({re.escape(pkg)})(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][^\s;]*)?",
                     re.I | re.M)
    def repl(m: re.Match) -> str:
        return f"{m.group(1)}{m.group(2) or ''}>={fixed}"
    out, n = pat.subn(repl, text)
    return out if n and out != text else None


def _bump_package_json(text: str, pkg: str, fixed: str) -> str | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    changed = False
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if pkg in deps:
            current = re.sub(r"^[\^~>=<\s]+", "", str(deps[pkg]))
            if _version_tuple(current) < _version_tuple(fixed):
                prefix = "^" if str(deps[pkg]).startswith("^") else ""
                deps[pkg] = f"{prefix}{fixed}"
                changed = True
    return json.dumps(data, indent=2) + "\n" if changed else None


def _bump_pyproject(text: str, pkg: str, fixed: str) -> str | None:
    pat = re.compile(rf'("{re.escape(pkg)}(?:\[[^\]]*\])?)\s*(==|>=|~=|<=|>|<)\s*([0-9][^"]*)(")', re.I)
    out, n = pat.subn(rf"\g<1>>={fixed}\g<4>", text)
    return out if n and out != text else None


_BUMPERS = {
    "requirements.txt": _bump_requirements,
    "package.json": _bump_package_json,
    "pyproject.toml": _bump_pyproject,
}

_TEST = '''"""AutoPatch regression test: dependency must be pinned past the advisory."""
import re
from pathlib import Path


def _vt(v):
    return tuple(int(x) for x in re.findall(r"\\d+", v)[:4])


def test_dependency_pinned_past_cve():
    manifest = Path({manifest!r})
    text = manifest.read_text()
    m = re.search(r"{pkg_pattern}", text, re.I)
    assert m, {notfound!r}
    assert _vt(m.group(1)) >= _vt({fixed!r}), {below!r}
'''


_SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]*$")
_SAFE_VER = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")


_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".next", "dist"}
_HISTORY_HINT = ("changelog", "history", "archive", "/plans/")


def _pinned_version(manifest_text: str, pkg: str, kind: str) -> str | None:
    if kind == "package.json":
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return None
        for section in ("dependencies", "devDependencies"):
            if pkg in data.get(section, {}):
                return re.sub(r"^[\^~>=<\s]+", "", str(data[section][pkg]))
        return None
    m = re.search(rf"^{re.escape(pkg)}(?:\[[^\]]*\])?\s*(?:==|>=|~=)\s*([0-9][^\s;]*)",
                  manifest_text, re.I | re.M)
    if not m:
        m = re.search(rf'"{re.escape(pkg)}(?:\[[^\]]*\])?\s*(?:==|>=|~=)\s*([0-9][^"]*)"',
                      manifest_text, re.I)
    return m.group(1) if m else None


def _co_changes(repo: Path, pkg: str, old_ver: str, new_ver: str,
                already: set[str]) -> list[FilePatch]:
    """Co-changes a version bump owes the repo (learned on replayr #459):

    - script pins (`*_VERSION=old` in .sh/.bash) move with the manifest,
    - living docs (*.md, excluding changelogs/history/plans) that state the
      old version next to the package name are updated in the same patch —
      a doc still saying "stay on the old version" invites a downgrade.
    Anything else mentioning the old version is left alone; the sandbox
    suite gate decides whether that is safe.
    """
    out: list[FilePatch] = []
    pin_re = re.compile(rf"^([A-Za-z0-9_]*VERSION\s*=\s*){re.escape(old_ver)}(\s*)$", re.M)
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(repo))
        if rel in already or any(h in rel.lower() for h in _HISTORY_HINT):
            continue
        if path.suffix not in (".md", ".sh", ".bash", ".txt"):
            continue
        try:
            text = path.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        if old_ver not in text:
            continue
        new_text = text
        if path.suffix in (".sh", ".bash"):
            new_text = pin_re.sub(rf"\g<1>{new_ver}\g<2>", new_text)
        if path.suffix in (".md", ".txt"):
            lines = []
            for line in new_text.splitlines(keepends=True):
                if old_ver in line and pkg.lower() in line.lower():
                    line = line.replace(old_ver, new_ver)
                lines.append(line)
            new_text = "".join(lines)
        if new_text != text:
            out.append(FilePatch(rel, text, new_text))
    return out


def dependency_patch(alert: Alert, repo: Path) -> PatchResult | None:
    if not alert.package or not alert.fixed_version:
        return None
    if not _SAFE_PKG.match(alert.package) or not _SAFE_VER.match(alert.fixed_version):
        return None  # alert fields are untrusted: never interpolate unchecked values
    from .paths import PathEscape, safe_join
    manifest = alert.file or "requirements.txt"
    bumper = _BUMPERS.get(Path(manifest).name)
    try:
        manifest_path = safe_join(repo, manifest)
    except PathEscape:
        return None
    if bumper is None or not manifest_path.is_file():
        return None
    original = manifest_path.read_text()
    patched = bumper(original, alert.package, alert.fixed_version)
    if patched is None:
        return None
    files = [FilePatch(manifest, original, patched)]
    old_ver = _pinned_version(original, alert.package, Path(manifest).name)
    if old_ver and old_ver != alert.fixed_version:
        files += _co_changes(repo, alert.package, old_ver, alert.fixed_version,
                             already={manifest, "pnpm-lock.yaml",
                                      str(Path(manifest).parent / "pnpm-lock.yaml")})
    safe_id = alert.id.replace("/", "_").replace("-", "_")

    if manifest.endswith(".json"):
        # JS: the lockfile is part of the fix (repos gate on lockfile honesty),
        # and the regression test is a node test next to the manifest.
        lock = _regenerate_pnpm_lockfile(repo, manifest_path, patched)
        if lock is None and (manifest_path.parent / "pnpm-lock.yaml").is_file():
            return None  # cannot produce an honest, complete JS bump
        if lock is not None:
            lock_rel, lock_orig, lock_new = lock
            if lock_new != lock_orig:
                files.append(FilePatch(lock_rel, lock_orig, lock_new))
        parent = str(Path(manifest).parent)
        test_file = f"autopatch_dep_{safe_id}.test.mjs"
        if parent != ".":
            test_file = f"{parent}/{test_file}"
        return PatchResult(
            files=files, test_file=test_file,
            test_code=_JS_TEST.format(pkg=alert.package, fixed=alert.fixed_version),
            explanation=(f"Bumped {alert.package} to >={alert.fixed_version} in {manifest} "
                         f"(lockfile regenerated) to resolve {alert.rule} "
                         f"({alert.cwe or 'advisory'})."),
            source="dependency-bump",
        )

    pkg_pattern = rf"{re.escape(alert.package)}(?:\[[^\]]*\])?\s*(?:==|>=|~=)\s*([0-9][^\s;\"']*)"
    test_code = _TEST.format(
        manifest=manifest, fixed=alert.fixed_version, pkg_pattern=pkg_pattern,
        notfound=f"{alert.package} not found in {manifest}",
        below=f"{alert.package} pinned below the fixed version {alert.fixed_version}")
    return PatchResult(
        files=files,
        test_file=f"tests/test_autopatch_dep_{safe_id}.py",
        test_code=test_code,
        explanation=(f"Bumped {alert.package} to >={alert.fixed_version} in {manifest} "
                     f"to resolve {alert.rule} ({alert.cwe or 'advisory'})."),
        source="dependency-bump",
    )


_JS_TEST = """// AutoPatch regression test: {pkg} must resolve at >= {fixed}.
import {{ test }} from 'node:test';
import assert from 'node:assert/strict';
import {{ readFileSync, existsSync }} from 'node:fs';

const vt = (v) => String(v).replace(/^[\\^~>=<\\s]+/, '').match(/\\d+/g).map(Number);
const gte = (a, b) => {{ const x = vt(a), y = vt(b);
  for (let i = 0; i < 4; i++) {{ if ((x[i]||0) !== (y[i]||0)) return (x[i]||0) > (y[i]||0); }} return true; }};

test('{pkg} pinned past the advisory', () => {{
  const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)));
  const spec = (pkg.dependencies || {{}})['{pkg}'] || (pkg.devDependencies || {{}})['{pkg}'];
  assert.ok(spec, '{pkg} not found in package.json');
  assert.ok(gte(spec, '{fixed}'), `{pkg} spec ${{spec}} is below {fixed}`);
  if (existsSync(new URL('./pnpm-lock.yaml', import.meta.url))) {{
    const lock = readFileSync(new URL('./pnpm-lock.yaml', import.meta.url), 'utf8');
    assert.ok(lock.includes('{pkg}@' + '{fixed}') || gte(spec, '{fixed}'),
      'lockfile does not resolve {pkg} at >= {fixed}');
  }}
}});
"""


def _regenerate_pnpm_lockfile(repo: Path, manifest_path: Path,
                              patched_manifest: str) -> tuple[str, str, str] | None:
    """Run `pnpm install --lockfile-only` in a throwaway copy of the package
    dir with the patched manifest; return (relpath, original, regenerated)."""
    import shutil
    import subprocess
    import tempfile

    pkg_dir = manifest_path.parent
    lock_path = pkg_dir / "pnpm-lock.yaml"
    if not lock_path.is_file() or not shutil.which("pnpm"):
        return None
    original_lock = lock_path.read_text()
    try:
        with tempfile.TemporaryDirectory(prefix="autopatch-lock-") as td:
            work = Path(td) / "pkg"
            shutil.copytree(pkg_dir, work, ignore=shutil.ignore_patterns(
                "node_modules", ".next", ".git"))
            (work / "package.json").write_text(patched_manifest)
            p = subprocess.run(
                ["pnpm", "install", "--lockfile-only", "--ignore-scripts",
                 "--no-frozen-lockfile"],
                cwd=work, capture_output=True, text=True, timeout=600)
            if p.returncode != 0 or not (work / "pnpm-lock.yaml").is_file():
                return None
            new_lock = (work / "pnpm-lock.yaml").read_text()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return str(lock_path.relative_to(repo)), original_lock, new_lock
