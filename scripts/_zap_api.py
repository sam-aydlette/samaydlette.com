"""The authenticated ZAP API scan of the Silk Reeling API, as VDR findings.

.github/workflows/zap-dast.yml runs two scans in one run: the unauthenticated
baseline of the site (artifact zap-dast-report, read by the builder's --zap) and
an authenticated ZAP API scan of the Silk Reeling API (artifact zap-api-report),
driven by the API's own OpenAPI document with a Cognito access token for a
dedicated scanner user. scripts/fetch-detection-feeds.sh takes both from the
same successful run; the detection gate (detection.zap-api) decides the API
report is present, well-formed and fresh before anything is built.

The report is ZAP's own JSON, so the builder's ZAP ingester reads it. Only the
identity differs: the baseline's tracking ids are zap-<alert ref>, so an alert
type found by both scans would otherwise collapse into one finding (and one
decision). The API scan's are zap-api-<alert ref>, so each scan's finding is
decided, clocked and closed on its own.
"""

import json
from pathlib import Path

PREFIX = "zap-api-"


def _fail(msg):
    raise SystemExit(f"::error::ZAP API scan report: {msg} (fail-closed)")


def ingest_zap_api(path, ingest_zap, allowlist):
    """Findings from the API scan report through the builder's ZAP ingester
    (`ingest_zap(path, allowlist)`), re-keyed. Given but missing or malformed:
    the build stops, because an absent scan must never read as zero alerts."""
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        _fail(f"{path} not found; the detection gate should have stopped this run")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{path} is not valid JSON ({type(exc).__name__})")
    if not isinstance(doc, dict) or not isinstance(doc.get("site"), list):
        _fail(f"{path} has no site[]")
    out = []
    for f in ingest_zap(path, allowlist):
        out.append({**f, "tracking_id": PREFIX + str(f["tool_id"])})
    return out
