# The SSP's implemented->partial auto-downgrade must follow the signal's own
# per-KSI verdict (ksis[].status / evidence.failed_validation_ids), not a
# hardcoded policy-id heuristic that can both miss failing KSIs and drag in
# passing ones.

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("ssp", REPO / "scripts" / "build-oscal-ssp.py")
ssp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssp)


def _signal(ksis=None, validations=None):
    sig = {}
    if ksis is not None:
        sig["ksis"] = ksis
    if validations is not None:
        sig["validations"] = validations
    return sig


def test_uses_signal_ksi_attribution_not_heuristic():
    sig = _signal(
        ksis=[
            {"id": "KSI-SVC-ACM", "status": "fail",
             "evidence": {"failed_validation_ids": ["v-0015"]}},
            {"id": "KSI-MLA-EVC", "status": "pass",
             "evidence": {"failed_validation_ids": []}},
        ],
        # A failing terraform.compliance validation used to hardcode-in
        # KSI-MLA-EVC; the signal above says it passes, so it must stay out.
        validations=[{"result": "fail", "policy": {"id": "terraform.compliance"}}],
    )
    assert ssp._failing_ksis_from_signal(sig) == {"KSI-SVC-ACM"}


def test_failed_validation_ids_alone_marks_failing():
    sig = _signal(ksis=[
        {"id": "KSI-CMT-LMC", "status": "pass",
         "evidence": {"failed_validation_ids": ["v-0002"]}},
    ])
    assert ssp._failing_ksis_from_signal(sig) == {"KSI-CMT-LMC"}


def test_all_pass_means_no_downgrade():
    sig = _signal(
        ksis=[{"id": "KSI-SVC-ACM", "status": "pass",
               "evidence": {"failed_validation_ids": []}}],
        validations=[{"result": "fail", "policy": {"id": "terraform.compliance"}}],
    )
    assert ssp._failing_ksis_from_signal(sig) == set()


def test_legacy_signal_without_ksis_falls_back_to_policy_map():
    sig = _signal(validations=[
        {"result": "fail", "policy": {"id": "terraform.compliance"}},
    ])
    assert ssp._failing_ksis_from_signal(sig) == {"KSI-MLA-EVC", "KSI-SVC-ACM"}
