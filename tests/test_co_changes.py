"""A version bump must move its co-pins and living docs in the same patch
(learned on replayr #459 review), and never rewrite history."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.alerts import Alert
from autopatch.deps import dependency_patch


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_bump_moves_script_pin_and_living_docs_only(tmp_path, monkeypatch):
    import autopatch.deps as deps
    monkeypatch.setattr(deps, "_regenerate_pnpm_lockfile",
                        lambda repo, m, p: ("frontend/pnpm-lock.yaml", "old-lock", "new-lock"))

    repo = tmp_path / "repo"
    _write(repo / "frontend/package.json",
           json.dumps({"name": "x", "dependencies": {"maplibre-gl": "5.24.0"}}))
    _write(repo / "frontend/pnpm-lock.yaml", "old-lock")
    _write(repo / "infra/scripts/fetch.sh",
           "#!/usr/bin/env bash\n# maplibre must stay on the pinned version\nMAPLIBRE_VERSION=5.24.0\nOTHER=5.24.0\n")
    _write(repo / "docs/setup.md",
           "We pin maplibre-gl at 5.24.0 because of the worker.\nUnrelated 5.24.0 mention stays.\n")
    _write(repo / "CHANGELOG_ARCHIVE.md", "- 2026-01-01 maplibre-gl 5.24.0 shipped\n")
    _write(repo / "docs/plans/map.md", "plan: pin maplibre-gl 5.24.0\n")
    _write(repo / "src/app.py", "VERSION = '5.24.0'\n")

    alert = Alert(id="d1", rule="GHSA-x", severity="critical",
                  file="frontend/package.json", line=1, message="cve",
                  package="maplibre-gl", fixed_version="6.4.1")
    patch = dependency_patch(alert, repo)

    assert patch is not None
    by_file = {fp.file: fp.patched for fp in patch.files}
    assert json.loads(by_file["frontend/package.json"])["dependencies"]["maplibre-gl"] == "6.4.1"
    assert by_file["frontend/pnpm-lock.yaml"] == "new-lock"
    assert "MAPLIBRE_VERSION=6.4.1" in by_file["infra/scripts/fetch.sh"]
    assert "OTHER=5.24.0" in by_file["infra/scripts/fetch.sh"]  # only *_VERSION pins move
    assert "pin maplibre-gl at 6.4.1" in by_file["docs/setup.md"]
    assert "Unrelated 5.24.0 mention stays." in by_file["docs/setup.md"]
    assert "CHANGELOG_ARCHIVE.md" not in by_file          # history is never rewritten
    assert "docs/plans/map.md" not in by_file
    assert "src/app.py" not in by_file                    # code left to the suite gate


def test_python_bump_also_moves_docs(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "requirements.txt", "flask==2.0.0\n")
    _write(repo / "README.md", "Requires flask 2.0.0 exactly.\n")
    alert = Alert(id="d2", rule="CVE-x", severity="high", file="requirements.txt",
                  line=1, message="cve", package="flask", fixed_version="2.2.5")
    patch = dependency_patch(alert, repo)
    assert patch is not None
    by_file = {fp.file: fp.patched for fp in patch.files}
    assert "flask>=2.2.5" in by_file["requirements.txt"]
    assert "flask 2.2.5" in by_file["README.md"]
