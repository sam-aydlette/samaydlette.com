# KNOWN-BAD (tests/test_human_views_published.py): an incident publish step that
# puts each per-incident report and its signature but not its human-readable
# view, so the trust manifest's "every JSON has a .view.md" would be false.
set -euo pipefail
put() {
  aws s3api put-object --bucket "${SITE_BUCKET:-stub}" --key ".well-known/$1" --body "$1" \
    --content-type "$2" --cache-control "public, max-age=300" --query 'ETag' --output text > /dev/null
}
for f in incident-INC-*.json; do
  put "$f" "application/json"
  put "${f%.json}.bundle" "application/json"
done
put incident-deliveries.view.md "text/markdown; charset=utf-8"
put incident-deliveries.json "application/json"
put incident-reports.view.md "text/markdown; charset=utf-8"
put incident-reports.json "application/json"
