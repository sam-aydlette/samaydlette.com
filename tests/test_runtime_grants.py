"""The runtime emitter's IAM grants match the calls it makes (least privilege).

infrastructure/lambda/index.js calls a fixed set of read-only AWS APIs to
re-validate every machine component (FRC-CSX-VVK, VDR-TFR-MVX). A call the
role is not granted would surface at runtime only as unassessed components;
a grant nothing calls is privilege the function does not need. This test
reads both sides and fails on either, and fails any statement that grants an
action on "*" other than the tagging sweep, which has no resource-level
permissions.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO / "infrastructure" / "lambda" / "index.js"
MAIN_TF = REPO / "infrastructure" / "main.tf"

# SDK client package -> IAM service prefix.
PREFIX = {
    "client-s3": "s3", "client-cloudfront": "cloudfront", "client-kms": "kms",
    "client-secrets-manager": "secretsmanager", "client-iam": "iam", "client-lambda": "lambda",
    "client-cloudwatch-logs": "logs", "client-apigatewayv2": "apigateway",
    "client-cognito-identity-provider": "cognito-idp", "client-sns": "sns", "client-sqs": "sqs",
    "client-cloudwatch": "cloudwatch", "client-eventbridge": "events", "client-cloudtrail": "cloudtrail",
    "client-dynamodb": "dynamodb", "client-route-53": "route53", "client-acm": "acm",
    "client-resource-groups-tagging-api": "tag",
}

# Commands whose IAM action is not "<prefix>:<CommandName>".
ACTION = {
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
    ("apigateway", "GetStages"): "apigateway:GET",
    ("apigateway", "GetRoutes"): "apigateway:GET",
}

# Granted for the platform (logging, env decryption, dead-letter queue) or
# for the emitter's own reads of objects, not for a component reader.
PLATFORM = {
    "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "kms:Decrypt",
    "sqs:SendMessage", "cloudfront:GetDistribution",
}


# Calls for a component type the stack does not currently create: the grant
# has to name the resource's ARN, so it is added with the resource. The
# reader fails closed meanwhile (a secret it cannot describe is a "fail").
DORMANT = {"secretsmanager:DescribeSecret": 'resource "aws_secretsmanager_secret"'}


def called_actions():
    src = INDEX.read_text()
    actions = set()
    for names, pkg in re.findall(r"const \{([^}]*)\}\s*=\s*require\('@aws-sdk/([a-z0-9-]+)'\)", src):
        prefix = PREFIX[pkg]
        for name in re.findall(r"(\w+)Command\b", names):
            if re.search(rf"new {name}Command\(", src):
                actions.add(ACTION.get((prefix, name), f"{prefix}:{name}"))
    return actions


def statements():
    text = MAIN_TF.read_text()
    start = text.index('resource "aws_iam_role_policy" "lambda_opa"')
    block = text[start:text.index("\n}\n", start)]
    return [s for s in re.split(r"\n      \{\n", block)[1:]]


def granted():
    out = []
    for s in statements():
        m = re.search(r"Action\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", s)
        acts = set(re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', m.group(1)))
        star = bool(re.search(r'Resource\s*=\s*"\*"', s) or re.search(r'Resource\s*=\s*\[\s*"\*"', s))
        out.append((acts, star))
    return out


def test_parsers_see_the_policy():
    assert len(called_actions()) >= 30
    assert len(statements()) >= 20


def test_every_call_is_granted():
    allowed = set().union(*(a for a, _ in granted()))
    tf = MAIN_TF.read_text()
    dormant = {a for a, marker in DORMANT.items() if marker not in tf}
    missing = called_actions() - allowed - dormant
    assert not missing, f"index.js calls APIs the lambda_opa role is not granted: {sorted(missing)}"


def test_every_grant_is_used():
    allowed = set().union(*(a for a, _ in granted()))
    unused = allowed - called_actions() - PLATFORM
    assert not unused, f"lambda_opa grants actions nothing calls: {sorted(unused)}"


def test_only_the_tag_sweep_is_granted_on_star():
    on_star = set().union(*(a for a, star in granted() if star))
    assert on_star == {"tag:GetResources"}


def test_no_write_or_data_read_actions_for_readers():
    reader_grants = set().union(*(a for a, _ in granted())) - PLATFORM
    writes = {a for a in reader_grants if re.match(r"[a-z0-9-]+:(Put|Create|Update|Delete|Set|Attach|Detach)", a)}
    assert writes == {"s3:PutObject"}  # the two /.well-known/ keys the signal is published to
    for forbidden in ("secretsmanager:GetSecretValue", "lambda:GetFunction", "logs:GetLogEvents",
                      "logs:FilterLogEvents", "kms:Encrypt", "dynamodb:GetItem", "dynamodb:Scan"):
        assert forbidden not in reader_grants
