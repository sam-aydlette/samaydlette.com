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
