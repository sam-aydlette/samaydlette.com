# =============================================================================
# Task 13 regression: build-time figure injection.
# Proves (a) figures are computed from canonical artifacts and reproduce the
# numbers the paper and dashboard publish, (b) stamp() rewrites only marked
# sites, and (c) altering the SSP's implemented-requirement count flows through
# to the stamped HTML — the acceptance check for the injector.
# =============================================================================
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("inject_figures", REPO / "scripts" / "inject-figures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inj = _load()

# The next tests are integration tests: they read the GENERATED
# infrastructure/oscal-ssp.json (built by the pipeline, gitignored), so they
# skip on a fresh checkout / the fast unit gate and run after a build (e.g. in
# the deploy job, where the SSP exists). Figure freshness is separately enforced
# at deploy time by scripts/inject-figures.py. Everything else in this file is a
# pure unit test of stamp() and always runs.
_needs_ssp = pytest.mark.skipif(
    not inj.SSP.exists(),
    reason="requires generated infrastructure/oscal-ssp.json (build the pipeline first)",
)


@_needs_ssp
def test_figures_reproduce_published_numbers():
    f = inj.compute_figures()
    # hub split: hand-written + family-default = total
    assert int(f["hub_handwritten"]) + int(f["hub_generated"]) == int(f["hub_total"])
    assert f["hub_handwritten"] == "115"
    assert f["hub_total"] == "333"
    # FedRAMP Moderate stack sums to the total
    assert int(f["moderate_implemented"]) + int(f["moderate_inherited"]) + int(f["moderate_na"]) == int(f["hub_total"])
    assert f["moderate_coverage"] == "333/333"
    # spokes
    assert f["govramp_coverage"] == "339/339"
    assert f["txramp1_coverage"] == "122/122"
    assert f["txramp2_coverage"] == "322/322"
    # CMMC: fully + shared = inherited count, and the fraction is over the total
    assert int(f["cmmc_osc_fully"]) + int(f["cmmc_osc_shared"]) == int(f["cmmc_osc_inherits_count"])
    assert f["cmmc_osc_inherits"] == f"{f['cmmc_osc_inherits_count']}/{f['cmmc_total']}"
    assert f["cmmc_coverage"] == "110/110"


def test_stamp_replaces_only_marked_sites():
    figures = {"hub_total": "999"}
    html = '<p>before <span data-figure="hub_total">331</span> and plain 331 stays</p>'
    out, changes, unknown, used = inj.stamp(html, figures, "t")
    assert out == '<p>before <span data-figure="hub_total">999</span> and plain 331 stays</p>'
    assert ("t", "hub_total", "331", "999") in changes
    assert not unknown
    assert used == {"hub_total"}


def test_unknown_marker_is_reported():
    out, changes, unknown, used = inj.stamp('<span data-figure="nope">x</span>', {"hub_total": "1"}, "t")
    assert unknown == ["nope"]


def test_attribute_order_tolerated():
    figures = {"moderate_coverage": "332/332"}
    html = '<div class="status-value" data-figure="moderate_coverage">331/331</div>'
    out, changes, _, _ = inj.stamp(html, figures, "t")
    assert ">332/332<" in out


@_needs_ssp
def test_published_targets_are_current():
    """The committed paper + dashboard must already match their sources
    (this is the same invariant the deploy --check step enforces)."""
    figures = inj.compute_figures()
    for path in inj.TARGETS:
        _, changes, unknown, _ = inj.stamp(path.read_text(), figures, path.name)
        assert not unknown, f"{path.name} references unknown figures: {unknown}"
        assert not changes, f"{path.name} has stale figures: {changes}"


@_needs_ssp
def test_altered_ssp_count_flows_to_html(tmp_path, monkeypatch):
    """Acceptance: add one implemented-requirement to the SSP and the stamped
    hub_total / hub_generated / moderate_coverage all move with it."""
    ssp = json.loads(inj.SSP.read_text())
    irs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    baseline = len(irs)
    irs.append({
        "uuid": "00000000-0000-4000-8000-000000000abc",
        "control-id": "zz-99",
        "props": [
            {"name": "implementation-status", "value": "implemented"},
            {"name": "control-origination", "ns": "https://fedramp.gov/ns/oscal", "value": "sp-system"},
        ],
    })
    altered = tmp_path / "altered-ssp.json"
    altered.write_text(json.dumps(ssp))
    monkeypatch.setattr(inj, "SSP", altered)

    f = inj.compute_figures()
    assert f["hub_total"] == str(baseline + 1)
    # hand-written count is unchanged (component def untouched), so generated grows
    assert f["hub_generated"] == str(baseline + 1 - int(f["hub_handwritten"]))
    assert f["moderate_coverage"] == f"{baseline + 1}/{baseline + 1}"

    # and that new value actually lands in the marked HTML
    marked = '<div class="status-value" data-figure="moderate_coverage">331/331</div>'
    out, _, _, _ = inj.stamp(marked, f, "t")
    assert f">{baseline + 1}/{baseline + 1}<" in out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
