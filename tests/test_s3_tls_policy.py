# Guardrail regression test (Prowler s3_bucket_secure_transport_policy, SC-8/SC-13).
# Every S3 bucket policy this repo manages must carry a Deny statement that
# rejects any request made without TLS (aws:SecureTransport = false). This test
# reads the live Terraform source — not a fixture — so removing the deny
# statement from either bucket policy fails the suite. The negative case proves
# the checker actually distinguishes a compliant policy from a non-compliant one.

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Each managed bucket policy: (terraform file, resource name).
MANAGED_BUCKET_POLICIES = [
    ("infrastructure/main.tf", "website"),
    ("infrastructure/logging.tf", "logs"),
]


def _resource_block(text, resource_name):
    """Return the body of resource "aws_s3_bucket_policy" "<name>" { ... } by
    matching braces from the opening brace of the block."""
    start = text.index(f'resource "aws_s3_bucket_policy" "{resource_name}"')
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : i + 1]
    raise AssertionError(f"unbalanced braces for policy {resource_name!r}")


def policy_denies_non_tls(block):
    """True iff the policy block contains a Deny-on-non-TLS statement covering
    all S3 actions when aws:SecureTransport is false."""
    has_deny_sid = '"DenyNonTLS"' in block
    has_deny_effect = re.search(r'Effect\s*=\s*"Deny"', block) is not None
    has_all_actions = re.search(r'Action\s*=\s*"s3:\*"', block) is not None
    has_secure_transport = "aws:SecureTransport" in block
    has_false = re.search(r'"aws:SecureTransport"\s*=\s*"false"', block) is not None
    return all(
        [has_deny_sid, has_deny_effect, has_all_actions, has_secure_transport, has_false]
    )


def test_managed_bucket_policies_deny_non_tls():
    missing = []
    for rel, name in MANAGED_BUCKET_POLICIES:
        text = (REPO / rel).read_text()
        if not policy_denies_non_tls(_resource_block(text, name)):
            missing.append(f"{rel}:{name}")
    assert not missing, f"bucket policies lack a non-TLS Deny statement: {missing}"


def test_checker_rejects_policy_without_deny():
    # A policy that only allows reads (no SecureTransport deny) must not pass —
    # this is the non-compliant fixture the guardrail is meant to catch.
    non_compliant = """{
      bucket = aws_s3_bucket.example.id
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid       = "AllowRead"
            Effect    = "Allow"
            Principal = "*"
            Action    = "s3:GetObject"
            Resource  = "arn:aws:s3:::example/*"
          },
        ]
      })
    }"""
    assert not policy_denies_non_tls(non_compliant)
