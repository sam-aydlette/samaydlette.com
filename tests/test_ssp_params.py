# Task 4 acceptance: SSP parameter values satisfy OSCAL's string pattern
# ^\S(.*\S)?$ — no embedded newlines / leading-trailing whitespace.

import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OSCAL_STRING = re.compile(r"^\S(.*\S)?$")

spec = importlib.util.spec_from_file_location("ssp", REPO / "scripts" / "build-oscal-ssp.py")
ssp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssp)


def test_normalize_ws_collapses_newlines_and_strips():
    assert ssp._normalize_ws("line one\n\nline two") == "line one line two"
    assert ssp._normalize_ws("  spaced   out \t value \n") == "spaced out value"
    assert OSCAL_STRING.match(ssp._normalize_ws("a\n\nb"))


def test_loaded_fedramp_params_have_no_pattern_violations():
    bad = []
    for cid, entries in ssp.FEDRAMP_PARAMS.items():
        for entry in entries:
            for v in entry.get("values", []) or []:
                if not OSCAL_STRING.match(v):
                    bad.append((entry["param-id"], v[:40]))
    assert not bad, f"param values violate OSCAL string pattern: {bad[:5]}"


def test_ps3_params_specifically_clean():
    # The two ODP values the review flagged.
    flagged = [e for entries in ssp.FEDRAMP_PARAMS.values() for e in entries
               if e["param-id"] in ("ps-03_odp.01", "ps-03_odp.02")]
    assert flagged, "expected ps-03 ODP parameters to be present"
    for e in flagged:
        for v in e.get("values", []) or []:
            assert "\n" not in v
            assert OSCAL_STRING.match(v)
