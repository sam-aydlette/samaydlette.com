"""CDS-CSO-IRP: every relevant policy and procedure, with the seven fields, in
both formats, with Related FedRAMP Practices as concrete rule and KSI IDs, and
the documents themselves published beside the index."""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("policy_index", REPO / "scripts" / "build-policy-index.py")
pi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pi)
sys.path.insert(0, str(REPO / "scripts"))
import _rules  # noqa: E402

FIELDS = ("name", "file", "summary", "word_count", "version", "last_updated", "related_practices")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """Built in-process with the git dates stubbed, so it runs in a shallow CI
    checkout too (the dating itself is tested in test_published_claims.py)."""
    mp = pytest.MonkeyPatch()
    mp.setattr(pi, "_is_shallow", lambda: False)
    mp.setattr(pi, "_last_change", lambda _p: ("2026-11-05", "a" * 40))
    d = tmp_path_factory.mktemp("pi")
    mp.setattr(sys, "argv", ["build-policy-index.py", "--output", str(d / "pi.json"), "--md-output",
                             str(d / "pi.md"), "--publish-dir", str(d / "policies")])
    try:
        pi.main()
    finally:
        mp.undo()
    return d, json.loads((d / "pi.json").read_text()), (d / "pi.md").read_text()


def test_every_entry_has_the_seven_fields_and_a_url(built):
    _, index, _ = built
    assert index["access"]
    for e in index["entries"]:
        assert all(e.get(k) not in (None, "") for k in FIELDS if k != "related_practices"), e["file"]
        assert e["url"] == pi.SITE + Path(e["file"]).name


def test_procedures_are_indexed_beside_policies(built):
    _, index, _ = built
    files = {e["file"] for e in index["entries"]}
    assert {"docs/procedures/agency-access.md", "docs/procedures/information-sharing.md",
            "docs/runbooks/vuln-gate-failure.md", "docs/verification.md"} <= files
    assert {e["kind"] for e in index["entries"]} == {"policy", "procedure"}


def test_related_practices_are_real_rule_and_ksi_ids(built):
    _, index, _ = built
    ids, _ = pi.practice_ids()
    applicable = _rules.applicable_provider_rules()
    for e in index["entries"]:
        assert set(e["related_practices"]) <= set(ids)
    sc = next(e for e in index["entries"] if e["file"].endswith("/sc-policy.md"))
    assert {"CMU-CSO-CMD", "CMU-CSO-UVM"} <= set(sc["related_practices"])
    assert all(i in applicable or i.startswith("KSI-") for i in sc["related_practices"])


def test_a_practice_prefix_that_matches_nothing_fails(monkeypatch):
    monkeypatch.setitem(pi.PRACTICES, "agency-access", ("NOPE-",))
    with pytest.raises(SystemExit, match="matches no FedRAMP rule or KSI"):
        pi.related("agency-access", ["CDS-TRC-AAI"], {})


def test_the_markdown_carries_every_field_of_every_entry(built):
    _, index, md = built
    for e in index["entries"]:
        section = md.split(f"## {e['name']}\n", 1)[1].split("\n## ", 1)[0]
        for k in ("file", "version", "last_updated", "summary", "kind", "url"):
            assert str(e[k]) in section, (e["file"], k)
        assert str(e["word_count"]) in section
        assert ", ".join(e["related_practices"]) in section if e["related_practices"] else "none" in section


def test_the_documents_are_copied_for_publication(built):
    d, index, _ = built
    for e in index["entries"]:
        assert (d / "policies" / Path(e["file"]).name).read_bytes() == (REPO / e["file"]).read_bytes()


def test_the_deploy_publishes_the_documents():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    assert re.search(r"build-policy-index\.py [^\n]*--publish-dir policies", wf)
    assert re.search(r'aws s3 cp policies/ "s3://\$BUCKET_NAME/\.well-known/policies/" --recursive', wf)
