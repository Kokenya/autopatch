"""JS dependency bumps: manifest language, generated node test syntax."""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autopatch.alerts import Alert
from autopatch.deps import _JS_TEST, _bump_package_json
from autopatch.runner import detect_language


def test_package_json_is_javascript():
    assert detect_language("frontend/package.json") == "javascript"
    assert detect_language("requirements.txt") == "python"


def test_bump_major_and_rendered_test_is_valid_js(tmp_path):
    manifest = json.dumps({"name": "x", "dependencies": {"maplibre-gl": "5.24.0"}})
    out = _bump_package_json(manifest, "maplibre-gl", "6.4.1")
    assert json.loads(out)["dependencies"]["maplibre-gl"] == "6.4.1"
    assert _bump_package_json(out, "maplibre-gl", "6.4.1") is None  # already fixed

    test_src = _JS_TEST.format(pkg="maplibre-gl", fixed="6.4.1")
    f = tmp_path / "t.test.mjs"
    f.write_text(test_src)
    check = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


def test_js_dep_alert_routes_to_dependency_kind():
    a = Alert(id="d1", rule="GHSA-jrc7-96c5-q579", severity="critical",
              file="frontend/package.json", line=1, message="maplibre cve",
              package="maplibre-gl", fixed_version="6.4.1")
    assert a.kind == "dependency"
