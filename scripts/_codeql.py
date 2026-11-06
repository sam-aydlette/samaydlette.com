"""CodeQL code-scanning alerts as VDR findings (SAST of first-party code).

.github/workflows/codeql.yml analyses this repository's Python, JavaScript and
GitHub Actions code, and the Silk Reeling app's Python and JavaScript, and
uploads the results to GitHub code scanning. scripts/fetch-detection-feeds.sh
reads the open CodeQL alerts on main and the latest analysis per category into
one document:

    {"analyses": [{"category", "created_at", "error", ...}],
     "alerts":   [{"number", "state", "created_at", "rule": {...},
                   "most_recent_instance": {"location": {"path", ...}, ...}}]}

The detection gate (scripts/detection-gate.py, detection.codeql) decides whether
the analyses are complete and fresh before anything is built. This module turns
the alerts into findings for scripts/build-vdr-report.py. A CodeQL alert is a
weakness in code this system ships, so it is a vulnerability decided through the
decision register (applies_to.vuln_ids names its tracking_id), like a ZAP alert.

Identity: an alert's number is GitHub's own stable identity for it (it follows
the code across commits and line moves), so the tracking id is
codeql-<rule id>-<alert number>: stable, unique and readable.
"""

import json
from pathlib import Path

SOURCE = "codeql"

# CodeQL's security severity first (the CVSS-derived level GitHub shows), then
# the rule's own problem severity for a query that has none.
SECURITY_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
PROBLEM_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "recommendation": "LOW"}


def _fail(msg):
    raise SystemExit(f"::error::CodeQL alerts: {msg} (fail-closed)")


def load(path):
    """The fetched document. Given but missing or malformed: the build stops,
    because zero alerts and no scan must never read the same."""
    p = Path(path)
    if not p.is_file():
        _fail(f"{path} not found; the detection gate should have stopped this run")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{path} is not valid JSON ({type(exc).__name__})")
    if not isinstance(doc, dict) or not isinstance(doc.get("alerts"), list) \
            or not isinstance(doc.get("analyses"), list):
        _fail(f"{path} has no alerts[] and analyses[]")
    return doc


def severity(rule):
    rule = rule or {}
    level = str(rule.get("security_severity_level") or "").lower()
    if level in SECURITY_SEVERITY:
        return SECURITY_SEVERITY[level]
    return PROBLEM_SEVERITY.get(str(rule.get("severity") or "").lower(), "MEDIUM")


def finding(alert):
    """One open alert as a VDR finding, or None for an alert that is not open."""
    if not isinstance(alert, dict) or alert.get("state", "open") != "open":
        return None
    rule = alert.get("rule") or {}
    inst = alert.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    rule_id = str(rule.get("id") or "codeql")
    number = alert.get("number")
    if not isinstance(number, int) or isinstance(number, bool):
        _fail(f"alert for {rule_id} has no number, so it has no stable identity")
    message = str((inst.get("message") or {}).get("text") or "").strip()
    return {
        "source": SOURCE,
        "tool_id": rule_id,
        "tracking_id": f"codeql-{rule_id}-{number}",
        "title": str(rule.get("description") or rule.get("name") or rule_id),
        "description": message[:500],
        "severity": severity(rule),
        "resource": str(loc.get("path") or ""),
        "detected_at": alert.get("created_at"),
    }


def ingest_codeql(path):
    """Findings from the fetched alerts; [] when no path is given."""
    if not path:
        return []
    return [f for f in (finding(a) for a in load(path)["alerts"]) if f]
