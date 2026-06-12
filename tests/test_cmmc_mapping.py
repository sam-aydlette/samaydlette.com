# Task 5 acceptance: no CMMC requirement may be classified inherited/implemented
# over an empty hub_controls set (vacuous inheritance through a crosswalk gap),
# and 3.12.4 (maintain your own SSP) is the customer's responsibility.

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("cmmc", REPO / "scripts" / "build-cmmc.py")
cmmc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmmc)


def test_guard_raises_on_vacuous_inheritance():
    for cls, srm in [("fully-inherited", "inherited"), ("implemented", "inherited"),
                     ("implemented", "osc-responsibility"), ("fully-inherited", "shared")]:
        with pytest.raises(ValueError):
            cmmc.guard_no_vacuous_inheritance("X", cls, srm, hub_controls=[])


def test_guard_allows_customer_responsibility_with_no_hub():
    # Empty hub_controls is fine as long as it is not claimed as inherited.
    cmmc.guard_no_vacuous_inheritance("3.12.4", "customer-responsibility", "osc-responsibility", hub_controls=[])


def test_guard_allows_inheritance_when_backed():
    cmmc.guard_no_vacuous_inheritance("3.5.3", "fully-inherited", "inherited", hub_controls=["ia-2.1"])


def test_3124_dispositioned_as_customer_responsibility():
    disp = json.loads((REPO / "data/dispositions/beyond-moderate.json").read_text())
    d = disp["cmmc_requirement_dispositions"]["3.12.4"]
    assert d["class"] == "customer-responsibility"
    assert d["srm"] == "osc-responsibility"


def test_no_requirement_disposition_claims_inheritance_without_hub():
    # Defensive: no requirement-level disposition may itself assert inheritance,
    # since those carry no hub controls by construction.
    disp = json.loads((REPO / "data/dispositions/beyond-moderate.json").read_text())
    for req, d in disp["cmmc_requirement_dispositions"].items():
        assert d.get("class") not in ("fully-inherited", "implemented"), req
        assert d.get("srm") != "inherited", req
