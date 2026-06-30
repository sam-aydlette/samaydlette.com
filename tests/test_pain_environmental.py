"""PR-B: the deterministic CVSS-Environmental PAIN classifier.

The worked examples below are the memo's own (Section 9), so they double as a
conformance check on the arithmetic: same inputs must yield the same N-level.
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "infrastructure" / "schemas" / "vdr-pain-config.json"


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
CFG, _ = vdr.load_pain_config(str(CONFIG))

# Memo impact / requirement weights, by their words, drawn from the governed config.
IMP = CFG["cvss_impact_weights"]          # none/low/high -> 0/0.22/0.56
REQ = CFG["requirement_weights"]          # low/medium/high -> 0.5/1.0/1.5
N, L, H = IMP["none"], IMP["low"], IMP["high"]
RL, RM, RH = REQ["low"], REQ["medium"], REQ["high"]


def pain(cia, req, m, technical_impact=None):
    return vdr.pain_from_environmental(cia, req, m, CFG, technical_impact)


# --- The memo's worked examples (Section 9) -------------------------------------

def test_example1_rce_crownjewel_multiagency_is_n5():
    assert pain((H, H, H), (RH, RH, RH), m=1) == "N5"


def test_example2_same_cve_on_sandbox_singleagency_is_n3():
    assert pain((H, H, H), (RL, RL, RL), m=0) == "N3"


def test_example3_availability_dos_on_high_AR_is_n4():
    """The blind spot: an availability-only DoS (C=I=None, A=High) on a
    high-availability asset is Debilitating -> N4, even though its vendor severity
    may be Low. The old severity-proxy stub sent this to N1."""
    assert pain((N, N, H), (RH, RH, RH), m=0) == "N4"


def test_example4_info_disclosure_on_low_CR_is_n2():
    assert pain((H, N, N), (RL, RH, RH), m=0) == "N2"


def test_example5_technical_impact_floor_lifts_n3_to_n4():
    weak_rce = ((L, L, L), (RH, RH, RH), 0)
    assert pain(*weak_rce) == "N3"
    assert pain(*weak_rce, technical_impact="total") == "N4"


def test_floor_never_invents_impact_on_a_none_dimension():
    """technical_impact=total floors only the dimensions the CVE actually touches."""
    # A=None stays None even under the floor; this is the Example-3 vector without
    # the availability dimension, so it must not climb to Debilitating.
    assert pain((N, N, N), (RH, RH, RH), m=0, technical_impact="total") == "N1"


# --- Vector parsing + end-to-end assign_pain ------------------------------------

def test_parse_cvss_cia_reads_the_impact_metrics():
    cia = vdr.parse_cvss_cia("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", CFG)
    assert cia == (N, N, H)


def test_parse_cvss_cia_none_without_impact_metrics():
    assert vdr.parse_cvss_cia("CVSS:3.1/AV:N/AC:L", CFG) is None
    assert vdr.parse_cvss_cia(None, CFG) is None


def test_vectorless_finding_uses_severity_proxy():
    """An IaC/config finding (no CVSS vector) keeps the documented fallback."""
    f = {"severity": "HIGH", "resource": "aws_s3_bucket.logs"}
    assert vdr.assign_pain(f, {}, CFG) == vdr.SEVERITY_TO_PAIN["HIGH"]


def test_unresolved_asset_uses_failsafe_classification():
    """A vectored CVE whose asset does not resolve scores loudly (memo s7):
    fail-safe CR/IR/AR are all High, so an all-High impact reaches N4 (m=0)."""
    f = {"severity": "HIGH", "resource": "pkg:pypi/unknown@9", "cve": "CVE-2026-0001",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert vdr.assign_pain(f, {}, CFG) == "N4"


def test_assign_pain_resolves_asset_from_classification_index():
    """End-to-end: a low-criticality public asset pulls an all-High CVE down off
    the fail-safe tier (asset re-weighting is doing the work)."""
    index = {"pkg:pypi/widget@1": {"data_sensitivity": "public",
                                    "mission_criticality": "low",
                                    "internet_reachable": True,
                                    "agency_scope": "single"}}
    f = {"severity": "HIGH", "resource": "pkg:pypi/widget@1", "cve": "CVE-2026-0002",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    # public -> CR low; low -> IR/AR low; all-High impact on all-Low requirements.
    expected = pain((H, H, H), (RL, RL, RL), m=0)  # == N3 (memo Example 2 shape)
    assert vdr.assign_pain(f, index, CFG) == expected == "N3"


def test_build_classification_index_keys_by_purl_and_tf_name():
    signal = {"components": [
        {"component_id": "aws::function::silk_reeling", "resource_type": "aws_lambda_function",
         "native_id": "arn:aws:lambda:us-east-2:1:function:s",
         "attributes": {"tf_name": "silk_reeling",
                        "classification": {"data_sensitivity": "public",
                                           "mission_criticality": "moderate",
                                           "internet_reachable": True,
                                           "agency_scope": "single"}}},
        {"component_id": "pypi::widget@1.0",
         "attributes": {"name": "widget", "purl": "pkg:pypi/widget@1.0",
                        "classification": {"data_sensitivity": "public",
                                           "mission_criticality": "moderate",
                                           "internet_reachable": False,
                                           "agency_scope": "single"}}},
    ]}
    import json, tempfile, os
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(signal).encode()); os.close(fd)
    try:
        idx = vdr.build_classification_index(path)
    finally:
        os.unlink(path)
    assert "aws_lambda_function.silk_reeling" in idx
    assert "silk_reeling" in idx
    assert "pkg:pypi/widget@1.0" in idx
    assert idx["pkg:pypi/widget@1.0"]["mission_criticality"] == "moderate"


def test_build_classification_index_handles_dict_global_id():
    """Regression: the real inventory carries global_id as a dict
    ({"purl": ...} for software, {"sha256": ...} for static artifacts), not a
    scalar. Indexing must read its scalar values, never add the dict to a set
    (which raised TypeError: unhashable type: 'dict' and crashed the VDR build)."""
    cls = {"data_sensitivity": "public", "mission_criticality": "moderate",
           "internet_reachable": False, "agency_scope": "single"}
    signal = {"components": [
        {"component_id": "pypi::widget@1.0",
         "native_id": "arn:aws:lambda:us-east-2:1:function:s",
         "global_id": {"purl": "pkg:pypi/widget@1.0"},
         "attributes": {"name": "widget", "classification": cls}},
        {"component_id": "html::index.html",
         "global_id": {"sha256": "abc123"},
         "attributes": {"classification": cls}},
    ]}
    import json, tempfile, os
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(signal).encode()); os.close(fd)
    try:
        idx = vdr.build_classification_index(path)  # must not raise
    finally:
        os.unlink(path)
    # The purl and sha256 inside global_id become resolvable keys.
    assert "pkg:pypi/widget@1.0" in idx
    assert "abc123" in idx
    assert "arn:aws:lambda:us-east-2:1:function:s" in idx
