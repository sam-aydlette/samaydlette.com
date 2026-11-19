#!/usr/bin/env bash
# Fetch the vulnerability-detection feeds the VDR build reads, into the current
# directory. Shared by the deploy and the nightly so both read the same inputs
# the same way.
#
# It never substitutes an empty document. A fetch that fails leaves no file and
# writes <file>.error with the reason; scripts/detection-gate.py (G7) then fails
# the run. This script itself always exits 0 so every feed is attempted and the
# gate can report all of the failures at once.
#
# Environment:
#   SITE_ORIGIN         where the previous VDR is published (https://samaydlette.com)
#   GITHUB_REPOSITORY   owner/repo
#   DEPENDABOT_TOKEN    a token that can read Dependabot alerts (repo secret
#                       DEPENDABOT_ALERTS_TOKEN; GITHUB_TOKEN cannot)
#   ACTIONS_TOKEN       a token with actions:read, for the DAST artifact (GITHUB_TOKEN)
#   AWS_REGION          where IAM Access Analyzer's analyzer and Inspector run
#   ANALYZER_NAME       the external-access analyzer (infrastructure/security-services.tf)
#
# The two AWS feeds are wrapped with the service's own status, so the gate can
# refuse an empty findings list from a service that is off or not covering the
# Lambdas. Suppressed (Inspector) and archived (Access Analyzer) findings are
# fetched with the active ones: a decision about a finding lives only in
# data/decisions.json, never in an AWS suppression or archive rule.
set -uo pipefail

fail() {  # fail FILE REASON
  rm -f "$1"
  # One line, no workflow-command syntax: the reason can carry API error text.
  # It is published (the detection summary), so AWS account IDs in an error's
  # ARNs are masked as scripts/_redact.py masks them.
  printf '%s' "$2" | tr '\r\n' '  ' | sed -e 's/::/:/g' -e 's/:[0-9]\{12\}:/:ACCOUNT:/g' -e 's/[0-9]\{12\}/ACCOUNT/g' \
    | head -c 300 > "$1.error"
  echo "::warning::$1: $(head -c 200 "$1.error")"
}

rm -f previous-vdr-report.json* dependabot-alerts.json* kev-catalog.json* epss-scores.csv.gz* zap-report.json* \
  inspector-findings.json* access-analyzer-findings.json*

# Previous VDR: the first-detected ledger. Without it every remediation clock restarts.
if curl -sfL --retry 3 --retry-delay 2 -o previous-vdr-report.json "${SITE_ORIGIN}/.well-known/vdr-report.json"; then
  echo "Previous VDR fetched ($(wc -c < previous-vdr-report.json) bytes)."
else
  fail previous-vdr-report.json "could not fetch ${SITE_ORIGIN}/.well-known/vdr-report.json"
fi

# Dependabot alerts, every page. gh prints one JSON array per page; jq joins them.
if [ -z "${DEPENDABOT_TOKEN:-}" ]; then
  fail dependabot-alerts.json "no token that can read Dependabot alerts (repository secret DEPENDABOT_ALERTS_TOKEN is not set)"
elif GH_TOKEN="$DEPENDABOT_TOKEN" gh api --paginate -H "Accept: application/vnd.github+json" \
      "/repos/${GITHUB_REPOSITORY}/dependabot/alerts?state=open&per_page=100" > dependabot-pages.json 2> dependabot.stderr \
    && jq -s 'add // []' dependabot-pages.json > dependabot-alerts.json \
    && jq -e 'type == "array"' dependabot-alerts.json > /dev/null; then
  echo "Dependabot alerts fetched: $(jq 'length' dependabot-alerts.json) open."
else
  fail dependabot-alerts.json "Dependabot alerts API: $(tr '\n' ' ' < dependabot.stderr)"
fi
rm -f dependabot-pages.json dependabot.stderr

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
if curl -sfL --retry 3 --retry-delay 2 -o kev-catalog.json "$KEV_URL"; then
  echo "CISA KEV catalog: version $(jq -r '.catalogVersion' kev-catalog.json 2>/dev/null), $(jq '.vulnerabilities | length' kev-catalog.json 2>/dev/null) CVEs."
else
  fail kev-catalog.json "could not fetch $KEV_URL"
fi

EPSS_URL="https://epss.cyentia.com/epss_scores-current.csv.gz"
if curl -sfL --retry 3 --retry-delay 2 -o epss-scores.csv.gz "$EPSS_URL"; then
  echo "EPSS scores fetched ($(wc -c < epss-scores.csv.gz) bytes)."
else
  fail epss-scores.csv.gz "could not fetch $EPSS_URL"
fi

# DAST: the latest successful main-branch run of the weekly ZAP workflow. Its
# age is enforced by the VDR builder (detection.zap.stale); its absence by
# detection.zap.missing.
if [ -z "${ACTIONS_TOKEN:-}" ]; then
  fail zap-report.json "no token to read the ZAP workflow's artifact"
else
  run_id=$(GH_TOKEN="$ACTIONS_TOKEN" gh run list -R "$GITHUB_REPOSITORY" --workflow zap-dast.yml --branch main \
             --status success --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
  rm -rf zap-dast
  if [ -n "$run_id" ] && GH_TOKEN="$ACTIONS_TOKEN" gh run download "$run_id" -R "$GITHUB_REPOSITORY" \
        -n zap-dast-report -D zap-dast > /dev/null 2>&1 \
      && [ -f zap-dast/report_json.json ]; then
    mv zap-dast/report_json.json zap-report.json
    echo "ZAP report from run ${run_id}: generated $(jq -r '."@generated"' zap-report.json 2>/dev/null)."
  else
    fail zap-report.json "no zap-dast-report artifact from a successful main-branch ZAP DAST Scan run"
  fi
  rm -rf zap-dast
fi

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
