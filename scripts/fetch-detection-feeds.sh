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
#   ACTIONS_TOKEN       GITHUB_TOKEN with actions:read (the DAST artifacts) and
#                       security-events:read (the CodeQL code-scanning alerts)
set -uo pipefail

fail() {  # fail FILE REASON
  rm -f "$1"
  # One line, no workflow-command syntax: the reason can carry API error text.
  printf '%s' "$2" | tr '\r\n' '  ' | sed 's/::/:/g' | head -c 300 > "$1.error"
  echo "::warning::$1: $(head -c 200 "$1.error")"
}

rm -f previous-vdr-report.json* dependabot-alerts.json* kev-catalog.json* epss-scores.csv.gz* zap-report.json* \
      zap-api-report.json* codeql-alerts.json*

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

# DAST: the latest successful main-branch run of the ZAP workflow, whatever
# triggered it (daily schedule, a deploy to main via workflow_run, or a manual
# dispatch: all three run on main). A run succeeds only when both of its scans
# did, so the site baseline and the authenticated API scan come from the same
# run. The baseline's age is enforced by the VDR builder (detection.zap.stale)
# and its absence by detection.zap.missing; the API report's presence and age by
# the detection gate (detection.zap-api).
if [ -z "${ACTIONS_TOKEN:-}" ]; then
  fail zap-report.json "no token to read the ZAP workflow's artifact"
  fail zap-api-report.json "no token to read the ZAP workflow's artifact"
else
  run_id=$(GH_TOKEN="$ACTIONS_TOKEN" gh run list -R "$GITHUB_REPOSITORY" --workflow zap-dast.yml --branch main \
             --status success --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
  for pair in "zap-dast-report:zap-report.json" "zap-api-report:zap-api-report.json"; do
    artifact=${pair%%:*} out=${pair#*:}
    rm -rf zap-dl
    if [ -n "$run_id" ] && GH_TOKEN="$ACTIONS_TOKEN" gh run download "$run_id" -R "$GITHUB_REPOSITORY" \
          -n "$artifact" -D zap-dl > /dev/null 2>&1 \
        && [ -f zap-dl/report_json.json ]; then
      mv zap-dl/report_json.json "$out"
      # The run is named in this log only; nothing built from these files carries it.
      echo "ZAP ${artifact}: generated $(jq -r '."@generated"' "$out" 2>/dev/null)."
    else
      fail "$out" "no ${artifact} artifact from a successful main-branch ZAP DAST Scan run"
    fi
    rm -rf zap-dl
  done
fi

# SAST: open CodeQL alerts on main, with the analyses behind them (newest first,
# one page: the gate needs only the latest per category, and a category not in
# the last hundred analyses is older than its window anyway). Filtered to
# CodeQL: Checkov and tfsec also upload SARIF to code scanning, and those are
# read from their own files. Only the fields the gate and builder read are kept.
if [ -z "${ACTIONS_TOKEN:-}" ]; then
  fail codeql-alerts.json "no token to read code-scanning alerts"
elif GH_TOKEN="$ACTIONS_TOKEN" gh api -H "Accept: application/vnd.github+json" \
      "/repos/${GITHUB_REPOSITORY}/code-scanning/analyses?tool_name=CodeQL&ref=refs/heads/main&per_page=100" \
      > codeql-analyses.json 2> codeql.stderr \
    && GH_TOKEN="$ACTIONS_TOKEN" gh api --paginate -H "Accept: application/vnd.github+json" \
      "/repos/${GITHUB_REPOSITORY}/code-scanning/alerts?tool_name=CodeQL&state=open&ref=refs/heads/main&per_page=100" \
      > codeql-pages.json 2>> codeql.stderr \
    && jq -s '{analyses: ([.[0][] | {category, created_at, error, results_count, commit_sha,
                                     tool: {name: .tool.name, version: .tool.version}}]),
               alerts: ([.[1:][][] | {number, state, created_at,
                                      rule: {id: .rule.id, name: .rule.name, description: .rule.description,
                                             severity: .rule.severity,
                                             security_severity_level: .rule.security_severity_level},
                                      most_recent_instance: {category: .most_recent_instance.category,
                                                             location: .most_recent_instance.location,
                                                             message: .most_recent_instance.message}}])}' \
         codeql-analyses.json codeql-pages.json > codeql-alerts.json \
    && jq -e '(.analyses | type == "array") and (.alerts | type == "array")' codeql-alerts.json > /dev/null; then
  echo "CodeQL: $(jq '.alerts | length' codeql-alerts.json) open alert(s); $(jq '[.analyses[].category] | unique | length' codeql-alerts.json) categories analysed."
else
  fail codeql-alerts.json "code-scanning API: $(tr '\n' ' ' < codeql.stderr)"
fi
rm -f codeql-analyses.json codeql-pages.json codeql.stderr
exit 0
