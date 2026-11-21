"""The deploy role's grant for the AWS security services
(infrastructure/bootstrap/main.tf, security-services-management).

The automated deploy identity can turn each service on and read it, never turn
it off: no statement allows a delete, disable, stop, unsubscribe or update
action, and service-linked roles can be created only for these services.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MAIN = (REPO / "infrastructure" / "bootstrap" / "main.tf").read_text()
POLICY = re.search(r'data "aws_iam_policy_document" "security_services_management" \{(.*?)\n\}\n', MAIN, re.S).group(1)
ACTIONS = set(re.findall(r'"((?:[a-z0-9-]+):[A-Za-z0-9]+)"', POLICY)) - {"iam:AWSServiceName", "iam:PassedToService"}

TURN_OFF = re.compile(r":(Delete|Disable|Stop|Update|BatchDisable|Disassociate|Remove|Archive)")


def test_no_action_can_turn_a_service_off():
    assert ACTIONS, "parsed no actions"
    assert sorted(a for a in ACTIONS if TURN_OFF.search(a)) == []


def test_each_service_can_be_turned_on():
    for a in ("access-analyzer:CreateAnalyzer", "inspector2:Enable",
              "config:PutConfigurationRecorder", "config:StartConfigurationRecorder", "config:PutDeliveryChannel",
              "securityhub:EnableSecurityHub", "securityhub:BatchEnableStandards",
              "guardduty:CreateDetector"):
        assert a in ACTIONS, a


def test_service_linked_roles_only_for_these_services():
    block = POLICY.split('sid       = "ServiceLinkedRolesForTheseServicesOnly"')[1]
    names = set(re.findall(r'"([a-z0-9-]+\.amazonaws\.com)"', block.split("statement {")[0]))
    assert names == {"access-analyzer.amazonaws.com", "inspector2.amazonaws.com", "config.amazonaws.com",
                     "securityhub.amazonaws.com", "guardduty.amazonaws.com"}


def test_passrole_is_only_configs_own_role_passed_to_config():
    block = POLICY.split('sid       = "PassConfigServiceLinkedRole"')[1].split("statement {")[0]
    assert "AWSServiceRoleForConfig" in block and '"config.amazonaws.com"' in block
    assert block.count("iam:PassRole") == 1 and '"*"' not in block
    assert POLICY.count("iam:PassRole") == 1
