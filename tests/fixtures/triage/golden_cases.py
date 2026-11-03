"""Golden cases for the triage parity test (T7, G17).

One finding per branch of the decision chain: Figure 7 likely exploitability,
reachability, mitigations, dispositions, deadlines and blocking. The expected
report (golden-report.json) was produced by the Python decision code as of T6,
before the decisions moved into policies/triage.rego. The parity test runs the
same inputs through the current builder and requires an identical report.

Regenerate only when a decision is meant to change, and say so in the PR:
    python3 tests/fixtures/triage/golden_cases.py > tests/fixtures/triage/golden-report.json
"""
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)

FLOOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
NO_IMPACT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N"
V4_FLOOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

SAFE = {"data_sensitivity": "public", "mission_criticality": "low", "agency_scope": "single"}


def _load(repo):
    spec = importlib.util.spec_from_file_location("vdr_golden", Path(repo) / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


def vuln(tid, cve, resource="pkg:npm/a@1", source="grype", **kw):
    return {"tracking_id": tid, "source": source, "tool_id": cve, "cve": cve, "resource": resource,
            "severity": "HIGH", **kw}


def config_finding(tid, tool_id, resource="aws_lambda_function.app", **kw):
    return {"tracking_id": tid, "source": "checkov", "tool_id": tool_id, "resource": resource,
            "severity": "MEDIUM", **kw}


def cases():
    inventory = {
        "index": {"pkg:npm/a@1": "cmp-pkg", "https://example.test": "cmp-edge"},
        "tf": [["cmp-app", "aws_lambda_function", "app"], ["cmp-int", "aws_s3_bucket", "internal"],
               ["cmp-pub", "aws_s3_bucket", "public"]],
        "classes": {"cmp-app": {**SAFE, "internet_reachable": True},
                    "cmp-int": {**SAFE, "internet_reachable": False},
                    "cmp-pub": {**SAFE, "internet_reachable": True},
                    "cmp-edge": {**SAFE, "internet_reachable": True},
                    "cmp-pkg": {**SAFE, "internet_reachable": False}},
        "types": {"cmp-pkg": "npm_package", "cmp-app": "aws_lambda_function",
                  "cmp-int": "aws_s3_bucket", "cmp-pub": "aws_s3_bucket", "cmp-edge": "web_endpoint"},
        "components": {}, "validations": [],
    }
    mit = {"verified_on": "2026-10-31T00:00:00+00:00", "control": {"component_id": "cmp-int"},
           "decided_by": "Operator", "decided_on": "2026-10-31", "review_by": "2027-01-31"}
    mitigation_states = {
        "m-full": {"id": "MIT-1", "effect": "full", "valid": True, **mit},
        "m-nirv": {"id": "MIT-2", "effect": "not-reachable", "valid": True, **mit},
        "m-nlev": {"id": "MIT-3", "effect": "not-likely-exploitable", "valid": True, **mit},
        "m-nlev-kev": {"id": "MIT-4", "effect": "not-likely-exploitable", "valid": True, **mit},
        "m-void": {"id": "MIT-5", "effect": "full", "valid": False, "void_reason": "fingerprint differs", **mit},
        "r-mitigated-ok": {"id": "MIT-6", "effect": "not-reachable", "valid": True, **mit},
        "r-mitigated-other": {"id": "MIT-7", "effect": "not-reachable", "valid": True, **mit},
        "r-mitigated-full": {"id": "MIT-8", "effect": "full", "valid": True, **mit},
    }
    findings = [
        # Figure 7
        vuln("kev-fp", "CVE-0000-1001", cvss_vector=LOCAL),
        vuln("floor", "CVE-0000-1002", resource="aws_s3_bucket.public", cvss_vector=FLOOR),
        vuln("floor-v4", "CVE-0000-1003", resource="aws_s3_bucket.public", cvss_vector=V4_FLOOR),
        vuln("floor-nirv", "CVE-0000-1004", resource="aws_s3_bucket.internal", cvss_vector=FLOOR),
        config_finding("no-impact", "CKV_AWS_999", cvss_vector=NO_IMPACT),
        vuln("pred-hi", "CVE-0000-1005", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("pred-lo", "CVE-0000-1006", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("pred-at", "CVE-0000-1007", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("no-score", "CVE-0000-1008", resource="aws_s3_bucket.internal", severity="MEDIUM"),
        vuln("observed", "CVE-0000-1009", resource="aws_s3_bucket.internal", exploitation="active",
             cvss_vector=LOCAL),
        config_finding("cfg-noscore", "CKV_AWS_998", severity="LOW"),
        # Reachability
        vuln("irv-observed", "ZAP-1", source="zap", resource="https://example.test", internet_reachable=True,
             severity="MEDIUM"),
        vuln("irv-unresolved", "CVE-0000-1010", resource="nowhere", cvss_vector=LOCAL),
        vuln("irv-package", "CVE-0000-1011", resource="pkg:npm/a@1", cvss_vector=LOCAL),
        config_finding("irv-inventory-false", "CKV_AWS_997", resource="aws_s3_bucket.internal"),
        config_finding("irv-inventory-true", "CKV_AWS_996", resource="aws_lambda_function.app"),
        # Mitigations
        vuln("m-full", "CVE-0000-1012", resource="aws_s3_bucket.public", cvss_vector=FLOOR),
        vuln("m-nirv", "CVE-0000-1013", resource="aws_s3_bucket.public", cvss_vector=FLOOR),
        vuln("m-nlev", "CVE-0000-1014", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("m-nlev-kev", "CVE-0000-1015", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("m-void", "CVE-0000-1016", resource="aws_s3_bucket.public", cvss_vector=FLOOR),
        vuln("fm-flag", "CVE-0000-1017", resource="aws_s3_bucket.public", cvss_vector=FLOOR,
             fully_mitigated=True),
        # Register dispositions
        vuln("r-mitigated-ok", "CVE-0000-1020", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-mitigated-none", "CVE-0000-1021", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-mitigated-other", "CVE-0000-1022", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-mitigated-full", "CVE-0000-1023", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-fp-control", "CVE-0000-1024", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-lapsed", "CVE-0000-1025", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-vendor-ok", "CVE-0000-1026", resource="aws_s3_bucket.internal", cvss_vector=FULL,
             fix_state="not-fixed"),
        vuln("r-vendor-fixed", "CVE-0000-1027", resource="aws_s3_bucket.internal", cvss_vector=LOCAL,
             fix_state="fixed", fix_versions=["2.0.0"]),
        vuln("r-vendor-unknown", "CVE-0000-1028", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-unknown-term", "CVE-0000-1029", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-bad-date", "CVE-0000-1030", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-investigating", "CVE-0000-1031", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-oprq", "CVE-0000-1032", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-accepted-noref", "CVE-0000-1033", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-fp", "CVE-0000-1034", resource="aws_s3_bucket.public", cvss_vector=FULL),
        vuln("r-no-review-by", "CVE-0000-1035", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("r-config-ignored", "CVE-0000-1036", source="checkov", resource="aws_s3_bucket.internal"),
        # Check-ID decision records
        config_finding("c-ra", "CKV_AWS_68"),
        config_finding("c-ra-lapsed", "CKV_AWS_86"),
        config_finding("c-ra-tfsec", "CKV_AWS_117", resource="aws_lambda_function.app"),
        config_finding("c-fp", "CKV_AWS_144", resource="aws_s3_bucket.internal"),
        config_finding("c-fp-norecord", "CKV_AWS_23", resource="aws_s3_bucket.internal"),
        # Deadlines and blocking
        vuln("n5-block", "CVE-0000-1040", resource="aws_s3_bucket.public", cvss_vector=FULL),
        vuln("overdue", "CVE-0000-1041", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("mav", "CVE-0000-1042", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("likely-overdue", "CVE-0000-1043", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("likely-overdue-short", "CVE-0000-1044", resource="aws_s3_bucket.public", cvss_vector=FULL),
        config_finding("informational", "CKV_AWS_995", severity="INFO"),
        vuln("legacy-id", "CVE-0000-1045", resource="aws_s3_bucket.internal", cvss_vector=LOCAL,
             legacy_tracking_id="old-legacy-id"),
        vuln("detected-earlier", "CVE-0000-1046", resource="aws_s3_bucket.internal", cvss_vector=LOCAL,
             detected_at=iso(40)),
        # LEV overrides
        vuln("ovr", "CVE-0000-1050", resource="pkg:npm/b@1", cvss_vector=LOCAL),
        vuln("ovr-lapsed", "CVE-0000-1051", resource="pkg:npm/c@1", cvss_vector=LOCAL),
        vuln("ovr-excluded", "CVE-0000-1050", resource="pkg:npm/excluded@1", cvss_vector=LOCAL),
        vuln("ovr-kev", "CVE-0000-1052", resource="pkg:npm/d@1", cvss_vector=LOCAL),
        vuln("ovr-selector-miss", "CVE-0000-1050", resource="aws_s3_bucket.internal", cvss_vector=LOCAL),
        vuln("ovr-raise", "CVE-0000-1053", resource="pkg:npm/e@1", cvss_vector=NO_IMPACT),
    ]
    epss = {"CVE-0000-1001": 0.01, "CVE-0000-1002": 0.01, "CVE-0000-1003": 0.0, "CVE-0000-1004": 0.01,
            "CVE-0000-1005": 0.5, "CVE-0000-1006": 0.01, "CVE-0000-1007": 0.10, "CVE-0000-1009": 0.0,
            "CVE-0000-1010": 0.01, "CVE-0000-1011": 0.01, "CVE-0000-1013": 0.01, "CVE-0000-1014": 0.9,
            "CVE-0000-1015": 0.01, "CVE-0000-1016": 0.01, "CVE-0000-1041": 0.5, "CVE-0000-1042": 0.01,
            "CVE-0000-1043": 0.01, "CVE-0000-1050": 0.5, "CVE-0000-1051": 0.5, "CVE-0000-1052": 0.5,
            "CVE-0000-1053": 0.0, "CVE-0000-1020": 0.5, "CVE-0000-1026": 0.5}
    kev = ["CVE-0000-1001", "CVE-0000-1015", "CVE-0000-1052"]
    rec = {"decided_by": "Operator", "decided_on": "2026-10-01", "review_by": "2027-04-01"}
    register = {
        "CVE-0000-1001": {"disposition": "false-positive", "poam_ref": "POAM-901", **rec},
        "CVE-0000-1020": {"disposition": "mitigated", "poam_ref": "POAM-902", "mitigation": "MIT-6", **rec},
        "CVE-0000-1021": {"disposition": "mitigated", "poam_ref": "POAM-903", **rec},
        "CVE-0000-1022": {"disposition": "mitigated", "poam_ref": "POAM-904", "mitigation": "MIT-99", **rec},
        "CVE-0000-1023": {"disposition": "mitigated", "poam_ref": "POAM-905", "mitigation": "MIT-8", **rec},
        "CVE-0000-1024": {"disposition": "false-positive", "poam_ref": "POAM-906", "mitigation": "MIT-6", **rec},
        "CVE-0000-1025": {"disposition": "operational-requirement", "poam_ref": "POAM-907",
                          "decided_by": "Operator", "decided_on": "2026-01-01", "review_by": "2026-10-01"},
        "CVE-0000-1026": {"disposition": "vendor-dependency", "poam_ref": "POAM-908", **rec},
        "CVE-0000-1027": {"disposition": "vendor-dependency", "poam_ref": "POAM-909", **rec},
        "CVE-0000-1028": {"disposition": "vendor-dependency", "poam_ref": "POAM-910", **rec},
        "CVE-0000-1029": {"disposition": "wont-fix", "poam_ref": "POAM-911", **rec},
        "CVE-0000-1030": {"disposition": "accepted", "poam_ref": "POAM-912", "review_by": "soon"},
        "CVE-0000-1031": {"disposition": "under-investigation", "poam_ref": "POAM-913", **rec},
        "CVE-0000-1032": {"disposition": "operational-requirement", "poam_ref": "POAM-914", **rec},
        "CVE-0000-1033": {"disposition": "accepted", **rec},
        "CVE-0000-1034": {"disposition": "false-positive", "poam_ref": "POAM-915", **rec},
        "CVE-0000-1035": {"disposition": "operational-requirement", "poam_ref": "POAM-916"},
        "CVE-0000-1036": {"disposition": "false-positive", "poam_ref": "POAM-917", **rec},
        "CVE-0000-9999": {"disposition": "false-positive", "poam_ref": "POAM-918", **rec},
    }
    decision_records = {
        "POAM-007": {"id": "POAM-007", **rec},
        "POAM-009": {"id": "POAM-009", "decided_by": "Operator", "decided_on": "2025-01-01",
                     "review_by": "2026-06-01"},
        "POAM-010": {"id": "POAM-010"},
        "POAM-003": {"id": "POAM-003", **rec},
    }
    overrides = {
        "OVR-1": {"advisory": "CVE-0000-1050", "selector": "pkg:npm/*", "exclusions": ["pkg:npm/excluded@1"],
                  "lev": False, "justification": "j", "decided_by": "Operator", "decided_on": "2026-10-01",
                  "review_by": "2027-01-01"},
        "OVR-2": {"advisory": "CVE-0000-1051", "selector": "*", "exclusions": [], "lev": False,
                  "justification": "j", "decided_by": "Operator", "decided_on": "2026-01-01",
                  "review_by": "2026-10-01"},
        "OVR-3": {"advisory": "CVE-0000-1052", "selector": "*", "exclusions": [], "lev": False,
                  "justification": "j", "decided_by": "Operator", "decided_on": "2026-10-01",
                  "review_by": "2027-01-01"},
        "OVR-4": {"advisory": "CVE-0000-1053", "selector": "pkg:npm/?@1", "exclusions": [], "lev": True,
                  "justification": "j", "decided_by": "Operator", "decided_on": "2026-10-01",
                  "review_by": "2027-01-01"},
    }
    ledger = {
        "m-void": {"first_detected": iso(30), "first_evaluated": iso(30),
                   "clock_basis": [{"start": iso(30), "mitigation": None}, {"start": iso(5), "mitigation": "MIT-5"}],
                   "pain": "N1", "historical_pain": "N3",
                   "rating_history": [{"at": iso(30), "pain": "N3", "lev": True, "irv": True,
                                       "reason": "first evaluation"}]},
        "m-full": {"first_detected": iso(20), "first_evaluated": iso(20)},
        "r-vendor-ok": {"first_detected": iso(100), "first_evaluated": iso(100)},
        "overdue": {"first_detected": iso(150), "first_evaluated": iso(150)},
        "mav": {"first_detected": iso(200), "first_evaluated": iso(200)},
        "likely-overdue": {"first_detected": iso(188), "first_evaluated": iso(188)},
        "likely-overdue-short": {"first_detected": iso(14), "first_evaluated": iso(14)},
        "r-oprq": {"first_detected": iso(400), "first_evaluated": iso(400)},
        "c-ra": {"first_detected": iso(90), "first_evaluated": iso(90)},
        "old-legacy-id": {"first_detected": iso(60), "first_evaluated": iso(60)},
        "n5-block": {"first_detected": iso(1), "first_evaluated": iso(1)},
    }
    suppressions = [
        {"tracking_id": "CKV_AWS_68", "source": "checkov-suppression", "tool_id": "CKV_AWS_68",
         "resource": ".checkov.yaml", "pain": "N2", "is_kev": False, "poam_ref": "POAM-007"},
        {"tracking_id": "CKV_AWS_18", "source": "checkov-suppression", "tool_id": "CKV_AWS_18",
         "resource": "aws_s3_bucket.internal", "pain": "N1", "is_kev": False, "cvss_vector": NO_IMPACT,
         "vector_source": "governed-check-vector"},
    ]
    return {"now": NOW.isoformat(), "findings": findings, "suppressions": suppressions, "kev": kev,
            "ledger": ledger, "register": register, "decision_records": decision_records,
            "lev_overrides": overrides, "epss": epss, "inventory": inventory,
            "mitigation_states": mitigation_states}


def build(vdr, c, monkeypatch=None):
    """Run the builder on the cases; mitigation_state is replaced by the recorded
    states (its evidence checks are tested in test_dispositions_mitigations)."""
    states = c["mitigation_states"]

    def fake_state(f, mitigations, inventory, runtime, today):
        return states.get(f["tracking_id"])

    if monkeypatch is not None:
        monkeypatch.setattr(vdr, "mitigation_state", fake_state)
    else:
        vdr.mitigation_state = fake_state
    epss = vdr.EpssScores(c["epss"])
    epss.model_version, epss.score_date = "v2026.06.15", "2026-11-03T00:00:00Z"
    report, blocking = vdr.build_report(
        c["findings"], c["suppressions"], set(c["kev"]), c["ledger"], index={}, epss_scores=epss,
        disposition_register=c["register"], lev_overrides=c["lev_overrides"], inventory=c["inventory"],
        now=datetime.fromisoformat(c["now"]), mitigations={k: {} for k in ("MIT-1", "MIT-unused")},
        decision_records=c["decision_records"])
    report.pop("report_id")
    return {"report": report, "blocking": blocking}


if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else REPO
    print(json.dumps(build(_load(repo), cases()), indent=1, sort_keys=True))
