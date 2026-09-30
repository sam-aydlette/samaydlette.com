"""Every bucket the inventory lists must be readable by the runtime KSI emitter.

The daily runtime Lambda checks each inventoried object_store's configuration
(versioning, encryption, public access block, tags). A bucket it cannot read is
reported as resource_read_error and leaves KSI-MLA-EVC unassessed at runtime.
That happened twice: the CloudTrail bucket, then the Terraform state bucket
when the bootstrap stack entered the inventory. This test fails the PR instead.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INFRA = REPO / "infrastructure"
CONFIG_READS = ("s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging")


def _lambda_policy() -> str:
    text = (INFRA / "main.tf").read_text()
    m = re.search(r'resource "aws_iam_role_policy" "lambda_opa" \{(.*?)\n\}', text, re.S)
    assert m, "aws_iam_role_policy.lambda_opa not found"
    return m.group(1)


def _config_read_resources() -> str:
    """The Resource lists of every statement that grants all four config reads."""
    out = []
    for stmt in re.split(r"\n\s*\},\s*\n\s*\{", _lambda_policy()):
        if all(a in stmt for a in CONFIG_READS):
            r = re.search(r"Resource\s*=\s*\[(.*?)\]", stmt, re.S)
            if r:
                out.append(r.group(1))
    return "\n".join(out)


def _buckets(directory: Path) -> list[tuple[str, str, str]]:
    """(kind, name, bucket expression) for every bucket resource and data source."""
    found = []
    for tf in sorted(directory.glob("*.tf")):
        text = tf.read_text()
        for m in re.finditer(r'^(resource|data) "aws_s3_bucket" "(\w+)" \{(.*?)^\}', text, re.S | re.M):
            b = re.search(r'^\s*bucket\s*=\s*(.+)$', m.group(3), re.M)
            found.append((m.group(1), m.group(2), b.group(1).strip() if b else ""))
    return found


def test_every_application_bucket_is_readable():
    resources = _config_read_resources()
    for kind, name, _ in _buckets(INFRA):
        ref = f"aws_s3_bucket.{name}.arn" if kind == "resource" else f"data.aws_s3_bucket.{name}.arn"
        assert ref in resources, f"{ref} is inventoried but the runtime Lambda cannot read its configuration"


def test_every_bootstrap_bucket_is_readable_by_name():
    resources = _config_read_resources()
    locals_text = "\n".join(p.read_text() for p in (INFRA / "bootstrap").glob("*.tf"))
    for _, name, expr in _buckets(INFRA / "bootstrap"):
        local = re.fullmatch(r"local\.(\w+)", expr)
        if local:
            expr = re.search(rf'^\s*{local.group(1)}\s*=\s*(".*")\s*$', locals_text, re.M).group(1)
        suffix = re.search(r'\}(-[\w-]+)"$', expr)
        assert suffix, f"cannot resolve the name of bootstrap bucket {name}: {expr}"
        assert re.search(rf'arn:aws:s3:::\$\{{[^}}]+\}}{re.escape(suffix.group(1))}"', resources), (
            f"bootstrap bucket {name} (*{suffix.group(1)}) is inventoried but the runtime Lambda cannot read its configuration")


def test_the_emitter_cannot_read_state_contents():
    for stmt in re.split(r"\n\s*\},\s*\n\s*\{", _lambda_policy()):
        resources = re.search(r"Resource\s*=\s*\[(.*?)\]", stmt, re.S)
        if resources and "tfstate" in resources.group(1):
            actions = re.search(r"Action\s*=\s*\[(.*?)\]", stmt, re.S)
            assert actions and "s3:GetObject" not in actions.group(1)
