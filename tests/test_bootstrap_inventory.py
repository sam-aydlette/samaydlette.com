# =============================================================================
# WS5a: the CI/CD identity plane (infrastructure/bootstrap) is inventoried.
# The bootstrap module's GitHub OIDC provider, deploy/assessment roles, operators
# group, and managed policy must normalize into canonical components with stable
# native_ids and IIW asset types — they are the highest-privilege identities
# governing the system and belong in the inventory, not excused.
# =============================================================================
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("bks", REPO / "scripts" / "build-ksi-signal.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bks = _load()

# The AWS-documentation example account, not the real one — this repo is public.
ACCOUNT = "123456789012"
ACC = f"arn:aws:iam::{ACCOUNT}"
BOOTSTRAP_STATE = {"values": {"root_module": {"resources": [
    {"type": "aws_iam_openid_connect_provider", "name": "github",
     "address": "aws_iam_openid_connect_provider.github",
     "values": {"arn": f"{ACC}:oidc-provider/token.actions.githubusercontent.com",
                "url": "token.actions.githubusercontent.com"}},
    {"type": "aws_iam_role", "name": "deploy", "address": "aws_iam_role.deploy",
     "values": {"arn": f"{ACC}:role/github-actions-deploy-oidc",
                "name": "github-actions-deploy-oidc", "assume_role_policy": "{\"x\":1}"}},
    {"type": "aws_iam_group", "name": "operators", "address": "aws_iam_group.operators",
     "values": {"arn": f"{ACC}:group/operators", "name": "operators"}},
    {"type": "aws_iam_policy", "name": "assessment", "address": "aws_iam_policy.assessment",
     "values": {"arn": f"{ACC}:policy/assessment-readonly", "name": "assessment-readonly",
                "policy": "{\"Statement\":[]}"}},
]}}}


def _by_type(comps):
    out = {}
    for c in comps:
        out.setdefault(c["type"], []).append(c)
    return out


def test_bootstrap_types_normalize():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    bt = _by_type(comps)
    assert "oidc_provider" in bt and "iam_group" in bt
    assert bt["oidc_provider"][0]["resource_type"] == "AWS::IAM::OIDCProvider"
    assert bt["iam_group"][0]["resource_type"] == "AWS::IAM::Group"


def test_managed_policy_uses_its_own_arn():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    pol = [c for c in comps if c["type"] == "iam_policy"][0]
    assert pol["native_id"] == f"{ACC}:policy/assessment-readonly"  # ARN, not synthesized


def test_oidc_and_group_carry_arn_native_ids_and_iiw_type():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    bt = _by_type(comps)
    oidc, grp = bt["oidc_provider"][0], bt["iam_group"][0]
    assert oidc["native_id"].endswith("oidc-provider/token.actions.githubusercontent.com")
    assert grp["native_id"].endswith("group/operators")
    assert oidc["attributes"]["iiw_asset_type"] == "OIDC Identity Provider (IAM)"
    assert grp["attributes"]["iiw_asset_type"] == "IAM Group"


def test_bootstrap_components_evidence_iam_ksis():
    # Once inventoried, the bootstrap identities become evidence for IAM-family KSIs.
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    catalog = {"KSI": {"IAM": {"id": "KSI-IAM", "name": "Identity", "indicators": [
        {"id": "KSI-IAM-ELP", "name": "Least Privilege", "impact": {"moderate": True},
         "controls": [{"control_id": "ac-6"}]}]}}}
    ksis = bks.build_ksi_statuses(catalog, comps, [])
    ksi = next(k for k in ksis if k["id"] == "KSI-IAM-ELP")
    refs = ksi["evidence"]["component_refs"]
    assert any(("oidc_provider" in r) or ("iam_group" in r) or ("iam_role" in r) for r in refs)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_a_resource_both_stacks_know_appears_once(monkeypatch):
    # The CloudFront distribution is managed by the bootstrap stack and read by the
    # application module as a data source; once CI can read the bootstrap state,
    # both walks produce it. Two components with one native_id fail the inventory
    # gate, so the bootstrap walk must keep the existing one and mark who manages it.
    dist_arn = f"arn:aws:cloudfront::{ACCOUNT}:distribution/EXAMPLE"
    cf = {"type": "aws_cloudfront_distribution", "name": "website", "address": "aws_cloudfront_distribution.website",
          "values": {"arn": dist_arn, "id": "EXAMPLE", "domain_name": "d1.cloudfront.net"}}
    state = {"values": {"root_module": {"resources": BOOTSTRAP_STATE["values"]["root_module"]["resources"] + [cf]}}}
    existing = bks.build_cloud_components({"values": {"root_module": {"resources": [dict(cf, address="data.aws_cloudfront_distribution.website", mode="data")]}}}, {})
    assert [c["native_id"] for c in existing] == [dist_arn]
    monkeypatch.setattr(bks, "run_terraform", lambda _args: state)
    fresh = bks.build_bootstrap_components(existing)
    native_ids = [c["native_id"] for c in existing + fresh]
    assert len(native_ids) == len(set(native_ids))
    assert existing[0]["attributes"]["managed_by"] == "bootstrap"
    assert {c["type"] for c in fresh} >= {"oidc_provider", "iam_role", "iam_group"}


# -----------------------------------------------------------------------------
# The inventory's classification of each bootstrap resource must equal the tags
# the bootstrap stack applies to it. Reconciliation invariant (i) compares the
# two on every deploy and fails closed on a mismatch, so drift between
# local.bootstrap_cls (infrastructure/bootstrap/main.tf) and the generator's
# tables blocks deploys. This test catches it at PR time instead.
# -----------------------------------------------------------------------------
import re  # noqa: E402

BOOTSTRAP_DIR = REPO / "infrastructure" / "bootstrap"
TAG_TO_CLS = {"DataSensitivity": "data_sensitivity", "MissionCriticality": "mission_criticality",
              "InternetReachable": "internet_reachable", "Archetype": "archetype"}


def _bootstrap_cls():
    """Parse the local.bootstrap_cls map: {key: {TagKey: value}}."""
    text = (BOOTSTRAP_DIR / "main.tf").read_text()
    body = re.search(r"bootstrap_cls\s*=\s*\{(.*?)\n  \}", text, re.S).group(1)
    return {m.group(1): dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', m.group(2)))
            for m in re.finditer(r"(\w+)\s*=\s*\{([^}]*)\}", body)}


def _tagged_resources():
    """(resource type, name, bootstrap_cls key) for every resource tagged from it."""
    out = []
    for tf in sorted(BOOTSTRAP_DIR.glob("*.tf")):
        text = tf.read_text()
        for m in re.finditer(r'^resource "(\w+)" "(\w+)" \{(.*?)^\}', text, re.S | re.M):
            cls = re.search(r"local\.bootstrap_cls\.(\w+)", m.group(3))
            if cls:
                out.append((m.group(1), m.group(2), cls.group(1)))
    return out


def test_inventory_classification_matches_bootstrap_tags():
    cls = _bootstrap_cls()
    tagged = _tagged_resources()
    assert tagged, "no bootstrap resource is tagged from local.bootstrap_cls"
    checked = 0
    for tf_type, name, key in tagged:
        state = {"values": {"root_module": {"resources": [
            {"type": tf_type, "name": name, "address": f"{tf_type}.{name}", "mode": "managed",
             "values": {"arn": f"arn:aws:x::{ACCOUNT}:{name}", "name": name, "bucket": name}}]}}}
        comps = [c for c in bks.build_cloud_components(state, {})
                 if c.get("attributes", {}).get("tf_name") == name]
        if not comps:
            continue  # a type the inventory does not model (e.g. the lock table)
        got = comps[0]["attributes"]["classification"]
        for tag, inv_key in TAG_TO_CLS.items():
            want = cls[key][tag]
            have = str(got[inv_key]).lower()
            assert have == want, f"{tf_type}.{name}: inventory {inv_key}={have!r}, tag {tag}={want!r}"
        checked += 1
    assert checked >= 5  # the OIDC provider, three CI roles and the state bucket


def test_state_lock_table_is_inventoried():
    # Found missing by the independent corroboration (RAMPART on TAP): the bootstrap
    # stack's DynamoDB lock table had no inventory type, so it was silently skipped.
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_dynamodb_table", "name": "tflock", "address": "aws_dynamodb_table.tflock", "mode": "managed",
         "values": {"arn": f"arn:aws:dynamodb:us-east-2:{ACCOUNT}:table/samaydlette-com-tflock", "name": "samaydlette-com-tflock"}}]}}}
    comps = bks.build_cloud_components(state, {})
    assert [c["component_id"] for c in comps] == ["aws::kv_table::tflock"]
    c = comps[0]
    assert c["resource_type"] == "AWS::DynamoDB::Table"
    assert c["attributes"]["classification"]["archetype"] == "platform-foundation"
    assert c["attributes"]["classification"]["data_sensitivity"] == "public"
