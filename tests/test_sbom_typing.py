# Task 2 acceptance: ecosystem-faithful component typing + IIW facts.
# A CycloneDX SBOM with one pypi and one npm package must type each by its real
# ecosystem, and the IIW projection must not label a PyPI package as
# "Software Package (npm)" or as a "Lambda runtime dependency".

import importlib.util
import json
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ksi = _load("ksi", "scripts/build-ksi-signal.py")
iiw = _load("iiw", "scripts/build-iiw.py")

SBOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    ],
}


def _build(sbom_name="sbom-python.json"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / sbom_name
        p.write_text(json.dumps(SBOM))
        return ksi.build_sbom_components(p)


def test_components_typed_by_ecosystem():
    comps = {c["attributes"]["name"]: c for c in _build()}
    assert comps["flask"]["type"] == "pypi_package"
    assert comps["left-pad"]["type"] == "npm_package"


def test_iiw_row_not_mislabeled_for_pypi():
    comps = {c["attributes"]["name"]: c for c in _build()}
    row = iiw.project_component(comps["flask"], {"ownership": {}})
    assert row["Asset Type"] == "Software Package (PyPI)"
    assert row["Asset Type"] != "Software Package (npm)"
    assert row["Function"] != "Lambda runtime dependency"
    assert "PyPI" in row["Function"]
    # software fields still populated for pypi
    assert row["Software/Database Name & Version"] == "flask@3.0.0"


def test_npm_sbom_dep_is_not_lambda_runtime():
    comps = {c["attributes"]["name"]: c for c in _build("sbom-js.json")}
    row = iiw.project_component(comps["left-pad"], {"ownership": {}})
    assert row["Function"] != "Lambda runtime dependency"
    assert row["Asset Type"] == "Software Package (npm)"


def test_pypi_package_passes_schema():
    # The KSI signal containing a pypi_package validates against the updated schema.
    schema = json.loads((REPO / "infrastructure/schemas/ksi-signal.schema.json").read_text())
    comp = _build()[0]  # a pypi_package
    # minimal signal envelope: validate the component subschema if present, else
    # confirm the type enum now admits pypi_package.
    type_enum = schema["$defs"]["component"]["properties"]["type"]["enum"]
    assert "pypi_package" in type_enum
    assert comp["type"] in type_enum


# The manifest, not the generator, says how each app tree's packages are described.
import sys  # noqa: E402

import pytest  # noqa: E402

sys.path.insert(0, str(REPO / "scripts"))
import _apps  # noqa: E402

CI_TOOLING_LABEL = "Open-source policy and signing tooling running inside CI"


def _build_from_manifest(sbom_name):
    text = _apps.app_sbom_text(_apps.load())[sbom_name]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / sbom_name
        p.write_text(json.dumps(SBOM))
        return {c["attributes"]["name"]: c for c in ksi.build_sbom_components(p, **text)}


def test_app_dependencies_are_described_by_the_manifest():
    py = _build_from_manifest("sbom-python.json")["flask"]["attributes"]
    assert py["function"] == "Dependency of the Silk Reeling application Lambda (PyPI)"
    assert py["diagram_label"] == "Open-source Python dependency of the Silk Reeling app"
    js = _build_from_manifest("sbom-js.json")["left-pad"]["attributes"]
    assert js["function"] == "Dependency of the Silk Reeling single-page application (npm)"
    assert js["diagram_label"] == "Open-source JavaScript dependency of the Silk Reeling app"


def test_an_app_dependency_never_takes_the_ci_tooling_label():
    # The compliance Lambda's npm default once labelled the SPA's packages as CI tooling.
    for sbom in _apps.app_sboms(_apps.load()):
        for c in _build_from_manifest(sbom).values():
            assert c["attributes"]["diagram_label"] != CI_TOOLING_LABEL


def test_the_generator_names_no_app_in_dependency_text():
    src = (REPO / "scripts" / "build-ksi-signal.py").read_text()
    assert "Dependency of the Silk Reeling" not in src
    assert "dependency of the Silk Reeling app" not in src


@pytest.mark.parametrize("change", [
    lambda t: t.update(dependency_of=""),
    lambda t: t.update(diagram_label=" padded"),
    lambda t: t.update(diagram_label="x" * 121),
    lambda t: t.update(dependency_of="line\nbreak"),
    lambda t: t.update(diagram_label="=HYPERLINK(\"http://x\")"),
    lambda t: t.update(what="a platform-only field"),
])
def test_an_app_tree_without_valid_text_is_refused(tmp_path, change):
    doc = json.loads(_apps.MANIFEST.read_text())
    change(doc["apps"][1]["sbom_trees"][0])
    p = tmp_path / "apps.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(SystemExit):
        _apps.load(p)


def test_a_tree_without_text_is_described_by_its_app_component(tmp_path):
    doc = json.loads(_apps.MANIFEST.read_text())
    for t in doc["apps"][1]["sbom_trees"]:
        t.pop("dependency_of")
        t.pop("diagram_label")
    p = tmp_path / "apps.json"
    p.write_text(json.dumps(doc))
    text = _apps.app_sbom_text(_apps.load(p))["sbom-js.json"]
    assert text == {"dependency_of": "Silk Reeling Mirror application",
                    "diagram_label": "Open-source dependency of the Silk Reeling Mirror application"}
