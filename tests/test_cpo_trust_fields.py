"""Group 5's fields in the Certification Package Overview: the trust center and
secure configuration guidance (CDS-CSO-PUB, CDS-CSO-UTC, SCG-CSO-AUP), the
third-party information resources (MAS-CSO-TPR) and the assessor's overall
summary, quoted verbatim from its signed set (CPO-CSO-OSA)."""
import importlib.util
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _assessor  # noqa: E402
import _ccm  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402
import _tpr  # noqa: E402

spec = importlib.util.spec_from_file_location("build_cpo_g5", REPO / "scripts" / "build-cpo.py")
cpo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpo)

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
SIGNAL = json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text())
PROFILE = json.loads((REPO / "data" / "system-profile.json").read_text())
FRESH = {a["path"] for a in json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
         ["artifacts"]}


def _assessment():
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / "simulated-assessment.json"
        s.write_text((REPO / "tests" / "fixtures" / "assessor" / "simulated-set.json").read_text())
        return _assessor.load_assessment(s, s, verifier=lambda *_a: True)


def _build(assessment=None):
    return cpo.build(_offering.load(), PROFILE, SIGNAL, _ccm.load(_ccm.CALENDAR_PATH, NOW.date()), {}, NOW,
                     cpo.boundary_groups(), _assessment() if assessment is None else assessment)


def test_the_cpo_with_group_5_fields_validates_against_fedramps_schema():
    assert fs.validate(_build(), "cpo") == []


def test_the_trust_center_entry_is_the_landing_page_with_access_instructions():
    tc = _build()["serviceProperties"]["trustCenter"]
    assert tc["url"] == "https://samaydlette.com/trust/index.html"
    assert (REPO / "website" / "trust" / "index.html").is_file()
    assert tc["authenticationRequired"] is False and "No access request is needed" in tc["accessRequestInstructions"]


def test_the_secure_configuration_guidance_links_the_published_guide():
    scg = _build()["serviceProperties"]["secureConfigurationGuidance"]
    assert scg["url"] == "https://samaydlette.com/.well-known/secure-configuration-guide.md"
    assert ".well-known/secure-configuration-guide.json" in FRESH


def test_third_party_resources_are_the_decided_records():
    doc = _build()
    assert doc["thirdPartyInformationResources"] == _tpr.cpo_third_party_information_resources()
    assert doc["thirdPartyInformationResources"]["nonCertified"]


def test_the_overall_summary_is_the_assessors_record_verbatim():
    recs = _assessment()
    ia = _build(recs)["providerExtensions"]["independentAssessment"]
    assert ia["overallSummary"] == _assessor.overall_summary(recs)
    assert "IVV-IAS-OSA" in ia["overallSummary"]["text"] and ia["simulated"] is True
    assert "assessor" not in _build(recs)  # no FedRAMP assessor ID exists; none is invented
    md = cpo.render_markdown(_build(recs))
    assert ia["overallSummary"]["text"][:80] in md


def test_known_bad_an_assessment_without_a_summary_fails():
    recs = [r for r in _assessment() if r["kind"] != "summary"]
    with pytest.raises(SystemExit, match="no overall summary"):
        _build(recs)


def test_the_cpo_refuses_to_build_without_the_assessment():
    with pytest.raises(SystemExit):
        cpo.main(["--output", "/dev/null"])


def test_the_deploy_and_the_maintainer_give_the_cpo_the_assessment():
    wf = REPO / ".github" / "workflows"
    deploy = (wf / "deploy-with-opa.yml").read_text()
    step = deploy.split("- name: Build Certification Package Overview (CPO)", 1)[1].split("\n    - name:", 1)[0]
    assert "--assessment simulated-assessment.json" in step
    maint = (wf / "package-maintenance.yml").read_text()
    step = maint.split("- name: Rebuild the SDR, OCR and CPO at the deployed commit", 1)[1].split("\n    - name:", 1)[0]
    assert len(re.findall(r"^\s+\$ASSESSMENT$", step, re.M)) == 3 and "--assessment $W/simulated-assessment.json" in step
