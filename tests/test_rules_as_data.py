"""Rules as data (REQ-RUL-1, REQ-RUL-2; Appendix B T19).

Remediation timeframes are read from FedRAMP's machine-readable rules at a
pinned version and never typed into code. The pin is published in the report.
"""
import importlib.util
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "infrastructure" / "schemas" / "fedramp-rules"
BAD = REPO / "tests" / "fixtures" / "rules-bad"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rules = _load("_rules", "scripts/_rules.py")


def _independent_matrix():
    """Read the Class C matrix straight from the vendored file, independently of _rules."""
    d = json.loads((RULES_DIR / "fedramp-consolidated-rules.json").read_text())
    pt = d["FRR"]["VDR"]["data"]["all"]["TFR"]["VDR-TFR-PVR"]["varies_by_class"]["c"]["pain_timeframes"]
    out = {}
    for n, cells in pt.items():
        for key, cell in cells.items():
            lev, irv = {"irv_lev": (True, True), "nirv_lev": (True, False), "nlev": (False, None)}[key]
            for i in ((True, False) if irv is None else (irv,)):
                out[(f"N{n}", lev, i)] = cell["timeframe_num"]
    return out


def test_t19_timeframes_equal_the_pinned_rules():
    assert rules.class_c_timeframes(RULES_DIR) == _independent_matrix()


def test_t19_n1_has_no_timeframe():
    m = rules.class_c_timeframes(RULES_DIR)
    assert not any(k[0] == "N1" for k in m)


def test_t19_no_timeframe_matrix_is_typed_into_the_builder():
    src = (REPO / "scripts" / "build-vdr-report.py").read_text()
    assert "CLASS_C_SLA_DAYS" not in src
    # No literal (pain, lev, irv) -> days table survives anywhere in the builder.
    assert not re.search(r'\("N[1-5]",\s*(True|False),\s*(True|False)\)\s*:\s*\d+', src)


def test_max_accepted_and_evaluation_windows_come_from_rules():
    assert rules.max_accepted_days(RULES_DIR) == 192
    assert rules.evaluation_days(RULES_DIR) == 5


def test_missing_class_c_matrix_fails_closed():
    with pytest.raises(SystemExit):
        rules.class_c_timeframes(BAD / "missing-class-c")


def test_hash_mismatch_fails_closed():
    with pytest.raises(SystemExit):
        rules.load_rules(BAD / "hash-mismatch")


def test_pin_is_published_by_the_builder():
    vdr = _load("vdr", "scripts/build-vdr-report.py")
    pin = vdr.rules_pin()
    sources = json.loads((RULES_DIR / "SOURCES.json").read_text())
    assert pin["commit"] == sources["commit"] and len(pin["commit"]) == 40
    assert pin["sha256"] == sources["sha256"] and pin["version"] == sources["version"]


def test_builder_lookup_uses_the_rules():
    vdr = _load("vdr", "scripts/build-vdr-report.py")
    for (pain, lev, irv), days in _independent_matrix().items():
        assert vdr.class_c_sla_days(pain, lev, irv) == days
    assert vdr.class_c_sla_days("N1", True, True) is None


def test_triage_rego_table_matches_the_rules_until_it_reads_them():
    """policies/triage.rego still carries its own table; it must not drift from the rules."""
    src = (REPO / "policies" / "triage.rego").read_text()
    cells = dict((k, int(v)) for k, v in re.findall(r'"(N[2-5]\|(?:true|false)\|(?:true|false))":\s*(\d+)', src))
    expected = {f"{p}|{str(lev).lower()}|{str(irv).lower()}": d for (p, lev, irv), d in _independent_matrix().items()}
    assert cells == expected
