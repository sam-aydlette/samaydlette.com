"""Every Checkov disposition cites a decision whose applies_to covers it.

An inline `checkov:skip=<check>:<reason> (DEC-NNN | POAM-NNN)` in the Terraform
is a disposition: the cited decision must claim the check (applies_to.check_ids)
and name the resource the skip sits on (applies_to.resources, either the
resource type alone, "aws-s3-bucket", or the type and its name,
"aws-s3-bucket::<bucket>"). Otherwise a decision is cited for a resource its
text never considered.

KNOWN_UNCOVERED lists the dispositions that were already uncovered when this
check was added (2026-11-06, #526); they are for the operator to settle (widen
the decision or record a new one). The list can only shrink: an entry that
becomes covered fails the test until it is removed.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402

FIXTURE = REPO / "tests" / "fixtures" / "dispositions" / "uncovered-skip.tf.txt"
SKIP = re.compile(r"checkov:skip=([A-Z0-9_]+):(.*)")
REF = re.compile(r"\b(DEC|POAM)-(\d{3})((?:/\d{3})*)")
DOMAIN = "samaydlette-com"

# (file, terraform address, check, cited) already uncovered on 2026-11-06.
KNOWN_UNCOVERED = {
    ("infrastructure/bootstrap/tf-state-backend.tf", "aws_s3_bucket.tfstate", "CKV_AWS_18", "POAM-028"),
    ("infrastructure/bootstrap/tf-state-backend.tf", "aws_s3_bucket.tfstate", "CKV2_AWS_62", "POAM-004"),
    ("infrastructure/cloudtrail.tf", "aws_s3_bucket.cloudtrail", "CKV_AWS_18", "POAM-028"),
    ("infrastructure/cloudtrail.tf", "aws_s3_bucket.cloudtrail", "CKV_AWS_145", "POAM-029"),
    ("infrastructure/cloudtrail.tf", "aws_cloudtrail.management", "CKV_AWS_35", "POAM-029"),
    ("infrastructure/logging.tf", "aws_s3_bucket.logs", "CKV2_AWS_62", "POAM-004"),
}


def _resolve(expr, text):
    expr = expr.strip()
    m = re.fullmatch(r"local\.(\w+)", expr)
    if m:
        expr = re.search(rf"^\s*{m.group(1)}\s*=\s*(.+)$", text, re.M).group(1).strip()
    expr = expr.strip('"')
    expr = expr.replace('${replace(var.domain_name, ".", "-")}', DOMAIN).replace("${local.domain_dashed}", DOMAIN)
    return None if "${" in expr or re.search(r"\b(?:aws_|data\.|var\.)", expr) else expr


def dispositions(path):
    """(address, resource keys, check, cited refs, raw cite) for every skip that cites a decision."""
    text = path.read_text()
    out, res = [], None
    for line in text.splitlines():
        m = re.match(r'resource "(\w+)" "(\w+)"', line)
        if m:
            res = {"type": m.group(1), "name": m.group(2), "id": None}
            block = text[text.index(line):]
            attr = re.search(r'^\s*(?:bucket|name)\s*=\s*(.+)$', block[:block.find("\n}") + 2], re.M)
            res["id"] = _resolve(attr.group(1), text) if attr else None
        s = SKIP.search(line)
        if not s or res is None:
            continue
        refs = [f"{p}-{n}" for m2 in REF.finditer(s.group(2))
                for p, n in [(m2.group(1), m2.group(2))] + [(m2.group(1), x) for x in m2.group(3).split("/") if x]]
        if not refs:
            continue
        kind = res["type"].replace("_", "-")
        keys = {kind} | ({f"{kind}::{res['id']}"} if res["id"] else set())
        raw = REF.search(s.group(2)).group(0)
        out.append((f"{res['type']}.{res['name']}", keys, s.group(1), refs, raw))
    return out


def uncovered(path, recs):
    by = {}
    for r in recs.values():
        by[r["id"]] = r
        if r.get("former_id"):
            by[r["former_id"]] = r
    bad = set()
    for addr, keys, check, refs, raw in dispositions(path):
        ok = any(ref in by and check in by[ref]["applies_to"]["check_ids"]
                 and keys & set(by[ref]["applies_to"]["resources"]) for ref in refs)
        if not ok:
            bad.add((str(path.relative_to(REPO)), addr, check, raw))
    return bad


def _all():
    recs = _decisions.records(_decisions.load())
    return set().union(*(uncovered(p, recs) for p in sorted((REPO / "infrastructure").rglob("*.tf"))
                         if ".terraform" not in p.parts))


def test_every_disposition_is_covered_by_its_decision():
    assert _all() - KNOWN_UNCOVERED == set()


def test_the_known_uncovered_list_only_shrinks():
    assert KNOWN_UNCOVERED - _all() == set(), "now covered: remove from KNOWN_UNCOVERED"


def test_the_recovery_drill_bucket_is_covered():
    recs = _decisions.records(_decisions.load())
    tf = REPO / "infrastructure" / "bootstrap" / "recovery-drill.tf"
    found = dispositions(tf)
    assert {d[2] for d in found} == {"CKV_AWS_145", "CKV2_AWS_62"}
    assert all("aws-s3-bucket::samaydlette-com-recovery-drill" in d[1] for d in found)
    assert uncovered(tf, recs) == set()


def test_known_bad_a_skip_its_decision_does_not_cover_is_caught():
    recs = _decisions.records(_decisions.load())
    assert {(b[2], b[3]) for b in uncovered(FIXTURE, recs)} == {("CKV_AWS_145", "DEC-029"), ("CKV_AWS_21", "DEC-004")}
