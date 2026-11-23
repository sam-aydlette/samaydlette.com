"""An app's static bundle comes from a job that ran third-party code and is
published to the site, so the unpacker refuses any unsafe entry, and a refusal
unpacks nothing."""
import importlib.util
import stat
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("unpack", REPO / "scripts" / "unpack-static-bundle.py")
unpack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(unpack)


def _bundle(tmp_path, entries):
    """entries: [(name, data, mode)]; mode None means a regular file."""
    p = tmp_path / "b.zip"
    with zipfile.ZipFile(p, "w") as z:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode if mode is not None else (stat.S_IFREG | 0o644)) << 16
            z.writestr(info, data)
    return p


GOOD = [("index.html", b"<html></html>", None), ("assets/", b"", stat.S_IFDIR | 0o755),
        ("assets/index-abc123.js", b"x", None)]


def test_a_good_bundle_unpacks(tmp_path):
    dest = tmp_path / "out"
    assert unpack.unpack(_bundle(tmp_path, GOOD), dest) == 2
    assert (dest / "index.html").read_bytes() == b"<html></html>"
    assert (dest / "assets" / "index-abc123.js").read_bytes() == b"x"


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize("entry, message", [
    (("/etc/passwd", b"x", None), "not a relative path"),
    (("..\\evil.js", b"x", None), "not a relative path"),
    (("../evil.js", b"x", None), "segment"),
    (("assets/../../evil.js", b"x", None), "segment"),
    (("./evil.js", b"x", None), "segment"),
    (("assets//evil.js", b"x", None), "segment"),
    (("assets/ev il.js", b"x", None), "segment"),
    (("link", b"/etc/passwd", stat.S_IFLNK | 0o777), "not a regular file"),
    (("index.html", b"again", None), "appears twice"),
])
def test_an_unsafe_entry_refuses_the_whole_bundle(tmp_path, entry, message):
    dest = tmp_path / "out"
    with pytest.raises(SystemExit, match=message):
        unpack.unpack(_bundle(tmp_path, [*GOOD, entry]), dest)
    assert not dest.exists()


def test_a_bundle_without_an_index_is_refused(tmp_path):
    with pytest.raises(SystemExit, match="no index.html"):
        unpack.unpack(_bundle(tmp_path, GOOD[1:]), tmp_path / "out")


def test_a_bundle_over_the_limits_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack, "MAX_FILES", 1)
    with pytest.raises(SystemExit, match="more than 1"):
        unpack.unpack(_bundle(tmp_path, GOOD), tmp_path / "out")
    monkeypatch.setattr(unpack, "MAX_FILES", 10)
    monkeypatch.setattr(unpack, "MAX_BYTES", 5)
    with pytest.raises(SystemExit, match="bytes"):
        unpack.unpack(_bundle(tmp_path, GOOD), tmp_path / "out")


def test_an_existing_destination_is_refused(tmp_path):
    (tmp_path / "out").mkdir()
    with pytest.raises(SystemExit, match="already exists"):
        unpack.unpack(_bundle(tmp_path, GOOD), tmp_path / "out")


def test_the_manifest_lists_the_silk_reeling_bundle():
    spec2 = importlib.util.spec_from_file_location("apps_u", REPO / "scripts" / "_apps.py")
    apps = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(apps)
    assert apps.statics(apps.load()) == [("silk-reeling", "silk-reeling-spa.zip", "silk-reeling")]


def test_the_inventory_records_each_static_bundle_on_the_website_bucket(tmp_path):
    spec3 = importlib.util.spec_from_file_location("ksi_static", REPO / "scripts" / "build-ksi-signal.py")
    ksi = importlib.util.module_from_spec(spec3)
    spec3.loader.exec_module(ksi)
    doc = ksi._apps.load()
    comps = [{"component_id": "aws::object_store::website", "attributes": {}}]
    ksi.apply_static_bundles(comps, tmp_path, doc)  # not built in this run
    (entry,) = comps[0]["attributes"]["app_static_bundles"]
    assert entry["sha256"] is None and entry["absent_reason"] and entry["path"] == "/silk-reeling/"
    (tmp_path / "silk-reeling-spa.zip").write_bytes(b"bundle")
    ksi.apply_static_bundles(comps, tmp_path, doc)
    (entry,) = comps[0]["attributes"]["app_static_bundles"]
    assert entry["sha256"] == "1e6ed65d77d6364eeaed5a745ba5c4985ae2b700dd85d7cf7f027bdf294a33fc"  # sha256(b"bundle")
    assert "absent_reason" not in entry


@pytest.mark.parametrize("static, message", [
    ({"bundle": "./silk-reeling-spa.zip"}, "exactly a bundle and a path"),
    ({"bundle": "../spa.zip", "path": "silk-reeling"}, "must be ./<name>.zip"),
    ({"bundle": "./silk-reeling.zip", "path": "silk-reeling"}, "cannot be the package"),
    ({"bundle": "./spa.zip", "path": "silk-reeling/../.well-known"}, "one lowercase path segment"),
    ({"bundle": "./spa.zip", "path": ".well-known"}, "one lowercase path segment"),
])
def test_a_malformed_static_entry_fails_the_manifest(tmp_path, static, message):
    import json
    spec2 = importlib.util.spec_from_file_location("apps_v", REPO / "scripts" / "_apps.py")
    apps = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(apps)
    doc = json.loads(apps.MANIFEST.read_text())
    doc["apps"][1]["static"] = static
    bad = tmp_path / "apps.json"
    bad.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match=message):
        apps.load(bad)
