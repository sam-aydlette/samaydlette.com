# Task 7: regression guard for the npm PURL fix (Appendix A — confirmed present).
# A lockfileVersion-3 lockfile with a nested scoped dependency and a hoisted
# duplicate must yield canonical, %40-encoded PURLs with no parent-path leak,
# deduped by PURL.

import importlib.util
import json
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "root"},
        # nested scoped dependency: parent path must NOT leak into the name
        "node_modules/@aws-crypto/sha1-browser/node_modules/@smithy/is-array-buffer":
            {"version": "2.2.0", "integrity": "sha512-aaa"},
        # the same package hoisted to top level (duplicate by package@version)
        "node_modules/@smithy/is-array-buffer": {"version": "2.2.0", "integrity": "sha512-aaa"},
        # an unscoped top-level dep
        "node_modules/semver": {"version": "7.5.0", "integrity": "sha512-bbb"},
    },
}


def _purls():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "package-lock.json"
        p.write_text(json.dumps(LOCK))
        return [c["global_id"]["purl"] for c in ksi.build_npm_components(p)]


def test_nested_scoped_purl_is_canonical_no_path_leak():
    purls = _purls()
    assert "pkg:npm/%40smithy/is-array-buffer@2.2.0" in purls
    # no parent path leaked, no unencoded @
    assert not any("node_modules" in p for p in purls)
    assert not any(p.startswith("pkg:npm/@") for p in purls)


def test_hoisted_duplicate_deduped_by_purl():
    purls = _purls()
    assert purls.count("pkg:npm/%40smithy/is-array-buffer@2.2.0") == 1


def test_unscoped_purl_unchanged():
    assert "pkg:npm/semver@7.5.0" in _purls()
