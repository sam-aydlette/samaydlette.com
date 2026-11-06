"""The Secure Configuration Guide, its live comparison and the cryptographic
module list (SCG-CSO-*, SCG-ENH-*, CMU-CSO-*).

scripts/build-scg.py publishes the guide from data/secure-configuration.json
and data/crypto-modules.json; scripts/check-secure-config.py compares the live
settings with it during the deploy and fails it on an undocumented deviation or
an unreadable setting. Each gate has a known-bad fixture in tests/fixtures/scg.
"""

import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "scg"
SOURCE = REPO / "data" / "secure-configuration.json"
CRYPTO = REPO / "data" / "crypto-modules.json"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
OP = "op-user-not-for-publication"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


scg = _load("build_scg", REPO / "scripts" / "build-scg.py")
chk = _load("check_secure_config", REPO / "scripts" / "check-secure-config.py")


def _in_force():
    return {r["id"] for r in _decisions.in_force(_decisions.load())}


def _crypto():
    return json.loads(CRYPTO.read_text())


def _signal(name="signal-mapped.json"):
    return json.loads((FIX / name).read_text())


# --- the guide ------------------------------------------------------------------------

def test_the_committed_guide_is_released_and_builds():
    src = scg.load(SOURCE)
    doc = scg.build(src, _crypto(), _signal(), NOW)
    assert doc["version"] == src["changelog"][-1]["version"]
    assert {a["level"] for a in doc["accounts"]} == {"top-level", "privileged"}
    assert doc["human_readable"].endswith(".md") and doc["machine_readable"].endswith(".json")
    md = scg.render_markdown(doc)
    assert "How to obtain and use this guide" in md and "Release history" in md


def test_every_setting_says_how_to_read_and_change_it():
    for s in scg.load(SOURCE)["settings"]:
        assert s["read"].strip() and s["change"].strip() and s["implication"].strip(), s["id"]


def test_a_default_changed_without_a_release_fails_the_build():
    with pytest.raises(SystemExit, match="bump the version"):
        scg.load(FIX / "unreleased-default.json")


def test_a_release_with_a_new_digest_is_accepted(tmp_path):
    src = json.loads((FIX / "unreleased-default.json").read_text())
    src["version"] = "2.1.0"
    src["changelog"].append({"version": "2.1.0", "date": "2026-11-06", "changes": ["test"],
                             "defaults_sha256": scg.defaults_digest(src)})
    p = tmp_path / "s.json"
    p.write_text(json.dumps(src))
    assert scg.load(p)["version"] == "2.1.0"


def test_a_guide_naming_a_retired_mechanism_fails_the_build():
    src = scg.load(FIX / "retired-mechanism.json")
    with pytest.raises(SystemExit, match="retired Silk Reeling shared"):
        scg.build(src, _crypto(), _signal(), NOW)


def test_the_policy_page_names_no_retired_mechanism():
    text = (REPO / "docs" / "policies" / "secure-configuration-guide.md").read_text()
    for pat, what in scg.RETIRED:
        assert not pat.search(text), what


def test_a_deviation_must_cite_an_in_force_decision(tmp_path):
    src = json.loads(SOURCE.read_text())
    src["settings"][1]["accepted_deviation"] = "DEC-999"
    with pytest.raises(SystemExit, match="not an in-force decision"):
        scg.validate_source(src, _in_force())


def test_mfa_deviation_is_the_accepted_finding():
    rec = _decisions.records(_decisions.load())["DEC-150"]
    assert rec["status"] == "in-force" and rec["disposition"] == "accepted"
    mfa = [s for s in scg.load(SOURCE)["settings"] if s["id"].endswith("mfa-phishing-resistant")]
    assert {s["account"] for s in mfa} == {"aws-root", "aws-operator-user"}
    assert all(s["accepted_deviation"] == "DEC-150" and s["recommended"] is True for s in mfa)


def test_the_guide_publishes_no_iam_user_name_or_account_id():
    doc = scg.build(scg.load(SOURCE), _crypto(), _signal(), NOW)
    text = json.dumps(doc)
    named = [u.split("::", 1)[1] for r in _decisions.load()["decisions"]
             for u in r["applies_to"].get("resources", []) if u.startswith("aws-iam-user::")]
    assert named and not any(n in text for n in named)
    assert not re.search(r"\b\d{12}\b", text)


# --- cryptographic modules ------------------------------------------------------------

def test_an_unmapped_component_type_fails_the_build():
    with pytest.raises(SystemExit, match="vector_database"):
        scg.module_list(_crypto(), _signal("signal-unmapped-type.json"))


def test_every_validated_module_cites_its_cmvp_certificate_page():
    for key, m in _crypto()["modules"].items():
        if m["cmvp_certificate"]:
            assert m["source"] == ("https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
                                   f"certificate/{m['cmvp_certificate']}"), key
            assert m["standard"].startswith("FIPS 140"), key


def test_paths_without_a_published_validation_are_covered_by_a_decision():
    rec = _decisions.records(_decisions.load())["DEC-152"]
    assert rec["status"] == "in-force"
    unvalidated = [s for s in _crypto()["services"] if s["module"] == "not-published"]
    assert unvalidated and "DEC-152" in _crypto()["modules"]["not-published"]["status"]


def test_every_inventory_type_the_builder_knows_is_mapped():
    """Every component type the inventory builder can emit is either mapped to a
    module or declared cryptography-free, so a new AWS resource type fails here
    first, not in the deploy."""
    bks = _load("bks_scg", REPO / "scripts" / "build-ksi-signal.py")
    known = set(bks.TYPE_BY_TF_TYPE.values()) | {"npm_package", "pypi_package", "html_artifact", "external_service"}
    mapped = {t for s in _crypto()["services"] for t in s["types"]}
    none = set(_crypto()["no_cryptography"]["types"])
    assert not (known - mapped - none), sorted(known - mapped - none)


def test_agency_tenant_defaults_use_the_validated_kms_hsm_in_terraform():
    silk = (REPO / "infrastructure" / "silk-reeling.tf").read_text()
    lam = silk[silk.index('resource "aws_lambda_function" "silk_reeling"'):]
    lam = lam[:lam.index("\n}\n")]
    assert "kms_key_arn = aws_kms_key.silk_reeling[0].arn" in lam
    for m in re.finditer(r'resource "aws_cloudwatch_log_group" "(silk_[a-z_]+)" \{(.*?)\n\}', silk, re.S):
        assert "kms_key_id" in m.group(2) and "aws_kms_key.silk_reeling" in m.group(2), m.group(1)
    key = silk[silk.index('resource "aws_kms_key" "silk_reeling"'):]
    assert "enable_key_rotation     = true" in key[:key.index("\n}\n")]
    cf = (REPO / "infrastructure" / "bootstrap" / "cloudfront.tf").read_text()
    assert 'minimum_protocol_version = "TLSv1.2_2021"' in cf
    assert 'origin_ssl_protocols     = ["TLSv1.2"]' in cf
    kms = _crypto()["modules"]["aws-kms-hsm"]
    assert {"kms_key", "function", "log_group"} <= {t for s in _crypto()["services"]
                                                    if s["module"] == "aws-kms-hsm" for t in s["types"]}
    assert kms["cmvp_certificate"] == "4884"


# --- live comparison ------------------------------------------------------------------

def _fake(name):
    responses = json.loads((FIX / name).read_text())["responses"]

    def call(args):
        r = responses.get(" ".join(args))
        if r is None:
            raise chk.AwsError("AccessDenied")
        if "error" in r:
            raise chk.AwsError(r["error"])
        return r
    return call


def _github():
    return next(c for c in json.loads((FIX / "github-good.json").read_text())["checks"] if c["id"] == "github_settings")


def _repository():
    """The repository settings as the committed files and a clean API read give them."""
    ms = chk._manual_settings()
    return chk.read_repository({"facts": {
        "github-rulesets": {"rulesets": 0, "with_bypass": 0}, "github-dependabot-alerts": True,
        "github-workflow-permissions": ms.workflow_permissions(), "github-dependabot-updates": ms.dependabot_updates()}})


def _compare(aws_fixture, github=None):
    src = json.loads(SOURCE.read_text())
    current = {**chk.read_aws(_fake(aws_fixture), "pool-1", now=NOW), **chk.read_github(github or _github()),
               **_repository()}
    return chk.build(src, chk.compare(src, current, _in_force()), NOW)


def test_a_matching_account_passes_with_mfa_as_the_accepted_deviation():
    doc = _compare("aws-good.json")
    assert chk.failures(doc) == []
    by = {r["id"]: r for r in doc["settings"]}
    assert by["aws-root.mfa-phishing-resistant"]["result"] == "accepted-deviation"
    assert by["aws-root.mfa-phishing-resistant"]["decision"] == "DEC-150"
    assert by["github.owner-2fa"]["result"] == "attested"
    assert by["aws-account.iam-users"]["current"] == 0
    assert by["aws-operator-user.access-keys"]["current"] == {"active": 1, "oldest_age_days": 35}
    assert by["aws-operator-user.access-keys"]["result"] == "matches"


def test_the_known_bad_account_fails_the_deploy():
    bad = {r["id"]: r["result"] for r in chk.failures(_compare("aws-bad.json"))}
    assert bad == {"aws-root.access-keys": "deviation", "aws-account.iam-users": "deviation"}


def test_an_unreadable_setting_fails_the_deploy():
    responses = json.loads((FIX / "aws-good.json").read_text())["responses"]
    del responses["sts get-caller-identity"]

    def call(args):
        r = responses.get(" ".join(args))
        if r is None:
            raise chk.AwsError("AccessDenied")
        if "error" in r:
            raise chk.AwsError(r["error"])
        return r
    src = json.loads(SOURCE.read_text())
    doc = chk.build(src, chk.compare(src, {**chk.read_aws(call, "pool-1", now=NOW), **chk.read_github(_github()),
                                           **_repository()}, _in_force()), NOW)
    assert [r["id"] for r in chk.failures(doc)] == ["aws-account.s3-block-public-access"]


def test_unobserved_github_settings_fail_the_deploy():
    doc = _compare("aws-good.json", {"id": "github_settings", "status": "not_observed", "detail": "no API"})
    assert {r["id"] for r in chk.failures(doc)} == {"github.prod-reviewer", "github.nightly-main-only",
                                                    "github.main-required-checks"}


def test_a_stale_operator_access_key_is_a_deviation():
    keys = chk._access_keys(lambda a: {"AccessKeyMetadata": [{"Status": "Active", "CreateDate": "2026-01-01T00:00:00Z"}]},
                            "u", now=NOW)
    assert keys == {"active": 1, "oldest_age_days": 308}
    assert not chk.matches({"active": {"at_most": 1}, "oldest_age_days": {"at_most": 90}}, keys)


def test_a_wildcard_or_write_inline_policy_is_not_read_only():
    assert chk._is_read_only({"Statement": [{"Effect": "Allow", "Action": ["kms:List*", "apigateway:GET"]}]})
    assert chk._is_read_only({"Statement": [{"Effect": "Deny", "Action": "*"}]})
    assert not chk._is_read_only({"Statement": [{"Effect": "Allow", "Action": "*"}]})
    assert not chk._is_read_only({"Statement": [{"Effect": "Allow", "Action": "s3:PutObject"}]})


def test_the_export_carries_no_user_name_or_account_id():
    text = json.dumps(_compare("aws-good.json")) + chk.render_markdown(_compare("aws-good.json"))
    assert OP not in text and "collector" not in text and "123456789012" not in text


# --- wiring ---------------------------------------------------------------------------

def _step_names():
    return [m.group(1).strip() for m in re.finditer(r"^    - name: (.+)$", WORKFLOW.read_text(), re.M)]


def test_the_deploy_builds_and_compares_before_the_sdr_and_publishes_both():
    names = _step_names()
    sdr = names.index("Build Security Decision Record (SDR — 20x SSP replacement)")
    build = names.index("Build the secure configuration guide (SCG, cryptographic modules)")
    compare = names.index("Compare live security settings with the secure configuration guide")
    assert names.index("Install cosign") < build < compare < sdr
    text = WORKFLOW.read_text()
    publish = text[text.index("- name: Publish all signed artifacts to /.well-known/"):]
    gate = text[text.index("- name: Publication redaction gate (no AWS account ID)"):]
    for a in ("secure-configuration-guide", "security-settings"):
        assert re.search(rf"for a in [^\n]*\b{a}\b[^\n]*; do", publish), a
        assert re.search(rf"for a in [^\n]*\b{a}\b[^\n]*; do", gate), a


def test_the_deploy_role_has_the_reads_the_comparison_makes():
    tf = (REPO / "infrastructure" / "bootstrap" / "deploy-config-reads.tf").read_text()
    for action in ("iam:GetAccountSummary", "iam:ListVirtualMFADevices", "iam:GetAccountPasswordPolicy",
                   "s3:GetAccountPublicAccessBlock", "iam:ListUsers", "iam:ListAccessKeys", "iam:GetRole"):
        assert f'"{action}"' in tf, action
    assert not re.search(r'"iam:(Put|Create|Delete|Update|Attach|Detach|Add|Remove)', tf)
    assert "role   = aws_iam_role.deploy.id" in tf


# --- the unattended publishers' roles -------------------------------------------------

def test_every_ci_role_in_bootstrap_has_its_trust_compared():
    """Each OIDC role bootstrap creates is read and compared, the two unattended
    publishers' roles included, and the deploy role may read each one."""
    roles = set()
    for tf in (REPO / "infrastructure" / "bootstrap").glob("*.tf"):
        roles |= set(re.findall(r'resource "aws_iam_role" "\w+" \{\s*name\s*=\s*"([\w-]+)"', tf.read_text()))
    assert roles and roles == set(chk.ROLES.values())
    reads = (REPO / "infrastructure" / "bootstrap" / "deploy-config-reads.tf").read_text()
    for res in ("deploy", "plan", "evidence_nightly", "package_maintenance", "incident_reports"):
        assert f"aws_iam_role.{res}.arn" in reads, res
    src = json.loads(SOURCE.read_text())
    assert set(chk.ROLES) | set(chk.ROLE_SCOPES) <= {s["check"] for s in src["settings"]}


def test_the_maintainer_scope_recommended_is_the_bootstrap_key_list():
    tf = (REPO / "infrastructure" / "bootstrap" / "package-maintenance.tf").read_text()
    keys = re.findall(r'"([^"]+)"', re.search(r"package_maintenance_keys = \[(.*?)\]", tf, re.S).group(1))
    src = json.loads(SOURCE.read_text())
    scope = next(s for s in src["settings"] if s["check"] == "role-scope-maintenance")
    assert sorted(scope["recommended"]) == sorted(keys)
    assert any(k.endswith(".view.md") for k in keys)
    reads = (REPO / "infrastructure" / "bootstrap" / "deploy-config-reads.tf").read_text()
    assert '"iam:GetRolePolicy"' in reads


def test_known_bad_a_maintainer_role_without_the_view_keys_fails_the_deploy():
    responses = json.loads((FIX / "aws-good.json").read_text())["responses"]
    responses.update(json.loads((FIX / "aws-maintainer-scope-no-views.json").read_text())["responses"])

    def call(args):
        r = responses.get(" ".join(args))
        if r is None:
            raise chk.AwsError("AccessDenied")
        if "error" in r:
            raise chk.AwsError(r["error"])
        return r
    src = json.loads(SOURCE.read_text())
    doc = chk.build(src, chk.compare(src, {**chk.read_aws(call, "pool-1", now=NOW), **chk.read_github(_github()), **_repository()},
                                     _in_force()), NOW)
    assert {r["id"]: r["result"] for r in chk.failures(doc)} == {"ci-roles.maintenance-publish-scope": "deviation"}


def test_the_new_roles_unapplied_fail_the_deploy():
    """Before the bootstrap read grant is applied the reads are denied; the
    comparison then fails the deploy rather than publishing a partial result."""
    responses = json.loads((FIX / "aws-good.json").read_text())["responses"]
    for k in [k for k in responses if "package-maintenance" in k or "incident-reports" in k]:
        del responses[k]

    def call(args):
        r = responses.get(" ".join(args))
        if r is None:
            raise chk.AwsError("AccessDenied")
        if "error" in r:
            raise chk.AwsError(r["error"])
        return r
    src = json.loads(SOURCE.read_text())
    doc = chk.build(src, chk.compare(src, {**chk.read_aws(call, "pool-1", now=NOW), **chk.read_github(_github()), **_repository()},
                                     _in_force()), NOW)
    assert {r["id"]: r["result"] for r in chk.failures(doc)} == {
        "ci-roles.maintenance-trust": "not-read", "ci-roles.incident-trust": "not-read",
        "ci-roles.maintenance-publish-scope": "not-read"}


def test_the_published_scope_carries_no_arn():
    by = {r["id"]: r for r in _compare("aws-good.json")["settings"]}
    cur = by["ci-roles.maintenance-publish-scope"]["current"]
    assert cur and all(k.startswith(".well-known/") for k in cur)
    assert "arn:" not in json.dumps(cur)


def _merged(*overrides, drop=()):
    responses = json.loads((FIX / "aws-good.json").read_text())["responses"]
    for name in overrides:
        responses.update(json.loads((FIX / name).read_text())["responses"])
    for k in drop:
        del responses[k]

    def call(args):
        r = responses.get(" ".join(args))
        if r is None:
            raise chk.AwsError("AccessDenied")
        if "error" in r:
            raise chk.AwsError(r["error"])
        return r
    src = json.loads(SOURCE.read_text())
    doc = chk.build(src, chk.compare(src, {**chk.read_aws(call, "pool-1", now=NOW), **chk.read_github(_github()),
                                           **_repository()}, _in_force()), NOW)
    return {r["id"]: r["result"] for r in chk.failures(doc)}


NIGHTLY_READS = ("iam get-role-policy --role-name github-actions-evidence-nightly-oidc "
                 "--policy-name evidence-nightly-audit-log-review")


def test_known_bad_a_nightly_role_without_lookup_events_fails_the_deploy():
    """The audit-log review (KSI-MLA-RVL) needs exactly cloudtrail:LookupEvents."""
    assert _merged("aws-nightly-no-lookup.json") == {"ci-roles.nightly-audit-reads": "deviation"}


def test_the_nightly_read_grant_unapplied_fails_the_deploy():
    assert _merged(drop=[NIGHTLY_READS]) == {"ci-roles.nightly-audit-reads": "not-read"}


def test_the_nightly_read_check_publishes_actions_only():
    assert chk._allowed_actions(json.loads((FIX / "aws-good.json").read_text())["responses"][NIGHTLY_READS]["PolicyDocument"]) == \
        ["cloudtrail:LookupEvents"]
