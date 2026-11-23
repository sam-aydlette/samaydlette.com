#!/usr/bin/env bash
# Fetch the AWS-native detection feeds into the current directory: the
# platform-specific half of the detection inputs. The cloud-agnostic half is
# scripts/fetch-detection-feeds.sh. scripts/aws-findings-adapter.py turns what
# this writes into normalized findings (infrastructure/schemas/findings.schema.json),
# the only form the VDR build reads; a stack on another platform supplies its
# own fetch script and adapter instead of these two.
#
# As in fetch-detection-feeds.sh, it never substitutes an empty document: a
# fetch that fails leaves no file and writes <file>.error, which
# scripts/detection-gate.py (G7) turns into a failure. It always exits 0.
#
# Environment:
#   AWS_REGION          where IAM Access Analyzer's analyzer and Inspector run
#   ANALYZER_NAME       the external-access analyzer (infrastructure/security-services.tf)
#
# Each feed is wrapped with the service's own status, so the gate can refuse an
# empty findings list from a service that is off or not covering the Lambdas.
# Suppressed (Inspector) and archived (Access Analyzer) findings are fetched with
# the active ones: a decision about a finding lives only in data/decisions.json,
# never in an AWS suppression or archive rule.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_fetch-common.sh
source "$here/_fetch-common.sh"

rm -f inspector-findings.json* access-analyzer-findings.json*

# Amazon Inspector (Lambda standard scanning): the account's scan status, what it
# covers, and every finding not closed.
region="${AWS_REGION:-us-east-2}"
if aws inspector2 batch-get-account-status --region "$region" --output json > inspector-status.json 2> aws.stderr \
    && aws inspector2 list-coverage --region "$region" --output json > inspector-coverage.json 2>> aws.stderr \
    && aws inspector2 list-findings --region "$region" --output json \
         --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"},{"comparison":"EQUALS","value":"SUPPRESSED"}]}' \
         > inspector-list.json 2>> aws.stderr \
    && jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
         --slurpfile s inspector-status.json --slurpfile c inspector-coverage.json --slurpfile f inspector-list.json \
         '{fetched_at: $at, account: ($s[0].accounts[0] // null),
           coverage: ($c[0].coveredResources // null), findings: ($f[0].findings // null)}' > inspector-findings.json; then
  echo "Inspector: $(jq '.findings | length' inspector-findings.json) finding(s), $(jq '.coverage | length' inspector-findings.json) resource(s) covered."
else
  fail inspector-findings.json "Inspector API: $(tr '\n' ' ' < aws.stderr)"
fi
rm -f inspector-status.json inspector-coverage.json inspector-list.json

# IAM Access Analyzer (external access): the analyzer itself, and every finding
# not resolved. ListFindings (not V2) is used because its summaries name the
# principal, the actions and the condition the decision is about.
analyzer="${ANALYZER_NAME:-samaydlette-com-external-access}"
if aws accessanalyzer get-analyzer --region "$region" --analyzer-name "$analyzer" --output json \
       > analyzer.json 2> aws.stderr \
    && arn=$(jq -er '.analyzer.arn' analyzer.json) \
    && aws accessanalyzer list-findings --region "$region" --analyzer-arn "$arn" --output json \
         --filter '{"status":{"eq":["ACTIVE","ARCHIVED"]}}' > analyzer-list.json 2>> aws.stderr \
    && jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile a analyzer.json --slurpfile f analyzer-list.json \
         '{fetched_at: $at, analyzer: ($a[0].analyzer // null), findings: ($f[0].findings // null)}' \
         > access-analyzer-findings.json; then
  echo "Access Analyzer: $(jq '.findings | length' access-analyzer-findings.json) finding(s)."
else
  fail access-analyzer-findings.json "Access Analyzer API: $(tr '\n' ' ' < aws.stderr)"
fi
rm -f analyzer.json analyzer-list.json aws.stderr
exit 0
