"""The unattended nightly's grant for the AWS security services' findings
(infrastructure/bootstrap/evidence-nightly.tf, evidence-nightly-security-findings).

The nightly runs with no reviewer, so its role stays narrow: it may read each
service's status and findings and nothing else. No action in the policy can
create, change, archive, suppress or disable anything.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TF = (REPO / "infrastructure" / "bootstrap" / "evidence-nightly.tf").read_text()
POLICY = re.search(r'data "aws_iam_policy_document" "evidence_nightly_security_findings" \{(.*?)\n\}\n', TF, re.S).group(1)
ACTIONS = set(re.findall(r'"((?:[a-z0-9-]+):[A-Za-z0-9]+)"', POLICY))
READ = re.compile(r":(Get|List|Describe|BatchGet)[A-Za-z]*$")


def test_every_action_is_a_read():
    assert ACTIONS, "parsed no actions"
    assert sorted(a for a in ACTIONS if not READ.search(a)) == []


def test_it_reads_each_services_status_and_findings():
    assert {"securityhub:DescribeHub", "securityhub:GetEnabledStandards", "securityhub:GetFindings",
            "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings",
            "guardduty:GetFindings"} <= ACTIONS


def test_the_security_hub_reads_are_scoped_to_the_hub():
    block = POLICY.split('sid       = "ReadSecurityHubFindings"')[1].split("statement {")[0]
    assert ":hub/default" in block and '"*"' not in block
