#!/usr/bin/env python3
"""G7 Detection: fail the run when detection itself failed (T52, VDR-CSO-FAV).

The VDR build reads scanner outputs and threat-intelligence feeds. Before this
gate, every one of them fell back to an empty document on failure, so a feed
outage published a report that silently checked less: no KEV flags, reset
remediation clocks, no SCA. This gate runs before the build and checks each
input it is given:

    kev           CISA KEV catalog: parseable, non-empty, dateReleased within the window
    epss          FIRST EPSS scores: header score_date within the window, at least one row
    grype         every Grype scan: parseable, has matches[], its DB valid and built within the window
    dependabot    the open-alerts list: a JSON array (fetched, with the token that can read it)
    previous-vdr  the published VDR (the first-detected ledger): an object with findings[]
    checkov       Checkov SARIF: runs[] present, not the old empty "fallback" document
    tfsec         tfsec JSON: an object with a results key
    codeql        CodeQL code-scanning alerts on main: alerts[] present, and every required
                  analysis category analysed without error within the window
    zap-api       the authenticated ZAP API scan report: site[] present, @generated within the window

A fetch step that fails writes `<file>.error` instead of a substitute, and that
text is carried into the failure. The windows come from the governed
infrastructure/schemas/detection-feeds.json; each feed's mode (block or
detect-and-recover) comes from the gate-mode register as detection.<feed>.

Writes a summary (--output) the builder records in the VDR's methodology and the
nightly publishes in its status beacon, then exits 1 if any block-mode feed failed.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _gates  # noqa: E402

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "infrastructure" / "schemas" / "detection-feeds.json"
FEEDS = ("kev", "epss", "grype", "dependabot", "previous-vdr", "checkov", "tfsec", "codeql", "zap-api")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _fail(where, msg):
    raise SystemExit(f"::error::detection feeds config {where}: {msg} (fail-closed)")


def load_config(path=None):
    p = Path(path or DEFAULT_CONFIG)
    if not p.is_file():
        _fail(p, "not found")
    raw = p.read_bytes()
    try:
        cfg = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(p, f"not valid JSON: {exc}")
    for key in ("version", "decided_by", "rationale"):
        if not isinstance(cfg.get(key), str) or not cfg[key].strip():
            _fail(p, f"{key} must be a non-empty string")
    for key in ("decided_on", "review_by"):
        if not isinstance(cfg.get(key), str) or not DATE_RE.match(cfg[key]):
            _fail(p, f"{key} must be an ISO date")
    feeds = cfg.get("feeds")
    if not isinstance(feeds, dict) or set(feeds) != set(FEEDS):
        _fail(p, f"feeds must list exactly {list(FEEDS)}")
    for name in ("kev", "epss", "grype", "codeql", "zap-api"):
        w = feeds[name].get("max_age_hours")
        if isinstance(w, bool) or not isinstance(w, (int, float)) or not 0 < w <= 8760:
            _fail(p, f"{name}.max_age_hours must be a number in (0, 8760]")
    cats = feeds["codeql"].get("categories")
    if not isinstance(cats, list) or not cats or not all(isinstance(c, str) and c for c in cats):
        _fail(p, "codeql.categories must be a non-empty list of analysis categories")
    cfg["sha256"] = hashlib.sha256(raw).hexdigest()
    return cfg


def _parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _age_hours(t, now):
    return round((now - t).total_seconds() / 3600.0, 1)


def _error_text(path):
    e = Path(f"{path}.error")
    if e.is_file():
        return e.read_text(encoding="utf-8", errors="replace").strip()[:300] or "fetch failed"
    return None


def _load_json(path):
    """(doc, problem). A missing file reports its .error text when the fetch left one."""
    p = Path(path)
    if not p.is_file():
        return None, f"missing ({_error_text(path) or 'no file produced'})"
    try:
        return json.loads(p.read_text(encoding="utf-8")), None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"not valid JSON ({exc.__class__.__name__})"


def _windowed(result, t, window, now, what):
    if t is None:
        result["problem"] = f"{what} absent or unparseable"
    else:
        result["source_date"] = t.isoformat()
        result["age_hours"] = _age_hours(t, now)
        if t > now:
            result["problem"] = f"{what} {t.isoformat()} is in the future"
        elif result["age_hours"] > window:
            result["problem"] = f"{what} is {result['age_hours']}h old (max {window}h)"
    return result


def check_kev(path, cfg, now):
    doc, problem = _load_json(path)
    r = {"feed": "kev", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list) or not vulns:
        return {**r, "problem": "no vulnerabilities[] in the catalog"}
    r["count"] = len(vulns)
    return _windowed(r, _parse_time(doc.get("dateReleased")), cfg["feeds"]["kev"]["max_age_hours"], now, "dateReleased")


def check_epss(path, cfg, now):
    r = {"feed": "epss", "file": str(path)}
    p = Path(path)
    if not p.is_file():
        return {**r, "problem": f"missing ({_error_text(path) or 'no file produced'})"}
    raw = p.read_bytes()
    try:
        text = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {**r, "problem": f"unreadable ({exc.__class__.__name__})"}
    lines = text.splitlines()
    header = lines[0] if lines and lines[0].startswith("#") else ""
    m = re.search(r"score_date:([0-9T:+\-.Z]+)", header)
    rows = sum(1 for line in lines if line.startswith("CVE-"))
    r["count"] = rows
    if not rows:
        return {**r, "problem": "no scores"}
    return _windowed(r, _parse_time(m.group(1)) if m else None, cfg["feeds"]["epss"]["max_age_hours"], now,
                     "score_date")


def check_grype(paths, cfg, now):
    out = []
    window = cfg["feeds"]["grype"]["max_age_hours"]
    for path in paths:
        doc, problem = _load_json(path)
        r = {"feed": "grype", "file": str(path)}
        if problem:
            out.append({**r, "problem": problem})
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("matches"), list):
            out.append({**r, "problem": "no matches[] (the scan did not complete)"})
            continue
        r["count"] = len(doc["matches"])
        status = ((doc.get("descriptor") or {}).get("db") or {}).get("status") or {}
        if status.get("valid") is not True:
            out.append({**r, "problem": "the vulnerability database is not reported valid"})
            continue
        out.append(_windowed(r, _parse_time(status.get("built")), window, now, "vulnerability database"))
    if not out:
        out.append({"feed": "grype", "file": None, "problem": "no Grype scans given"})
    return out


def check_dependabot(path):
    doc, problem = _load_json(path)
    r = {"feed": "dependabot", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    if not isinstance(doc, list):
        return {**r, "problem": "not a JSON array of alerts"}
    return {**r, "count": len(doc)}


def check_previous_vdr(path):
    doc, problem = _load_json(path)
    r = {"feed": "previous-vdr", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        return {**r, "problem": "no findings[]"}
    return {**r, "count": len(doc["findings"])}


def check_checkov(path):
    doc, problem = _load_json(path)
    r = {"feed": "checkov", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not isinstance(runs, list) or not runs:
        return {**r, "problem": "no runs[]"}
    if any(((run.get("tool") or {}).get("driver") or {}).get("version") == "fallback" for run in runs):
        return {**r, "problem": "the empty fallback document, not Checkov output"}
    return {**r, "count": sum(len(run.get("results") or []) for run in runs)}


def check_tfsec(path):
    doc, problem = _load_json(path)
    r = {"feed": "tfsec", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    if not isinstance(doc, dict) or "results" not in doc or not isinstance(doc["results"], (list, type(None))):
        return {**r, "problem": "no results key"}
    return {**r, "count": len(doc["results"] or [])}


def check_codeql(path, cfg, now):
    """Open CodeQL alerts on main, with the analyses that produced them. An
    empty alerts list means nothing only when every required category was
    analysed, without error, inside the window; a category never analysed (or
    analysed a week ago) would otherwise read as clean code."""
    doc, problem = _load_json(path)
    r = {"feed": "codeql", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    if not isinstance(doc, dict) or not isinstance(doc.get("alerts"), list) \
            or not isinstance(doc.get("analyses"), list):
        return {**r, "problem": "no alerts[] and analyses[]"}
    r["count"] = len(doc["alerts"])
    latest = {}
    for a in doc["analyses"]:
        if not isinstance(a, dict):
            continue
        t = _parse_time(a.get("created_at"))
        cat = a.get("category")
        if t is not None and isinstance(cat, str) and (cat not in latest or t > latest[cat][0]):
            latest[cat] = (t, a)
    feed = cfg["feeds"]["codeql"]
    missing = [c for c in feed["categories"] if c not in latest]
    if missing:
        return {**r, "problem": f"no analysis on main for {', '.join(missing)}"}
    errored = [c for c in feed["categories"] if latest[c][1].get("error")]
    if errored:
        return {**r, "problem": f"the latest analysis for {', '.join(errored)} reported an error"}
    oldest = min(latest[c][0] for c in feed["categories"])
    return _windowed(r, oldest, feed["max_age_hours"], now, "oldest required analysis")


def _zap_time(value):
    """ZAP's '@generated' header (UTC on the runner), as an aware time."""
    stamp = str(value or "").strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S", "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_zap_api(path, cfg, now):
    doc, problem = _load_json(path)
    r = {"feed": "zap-api", "file": str(path)}
    if problem:
        return {**r, "problem": problem}
    if not isinstance(doc, dict) or not isinstance(doc.get("site"), list) or not doc["site"]:
        return {**r, "problem": "no site[] (the scan did not reach its target)"}
    r["count"] = sum(len(s.get("alerts") or []) for s in doc["site"] if isinstance(s, dict))
    return _windowed(r, _zap_time(doc.get("@generated")), cfg["feeds"]["zap-api"]["max_age_hours"], now,
                     "@generated")


def evaluate(args, cfg, now):
    results = []
    if args.kev:
        results.append(check_kev(args.kev, cfg, now))
    if args.epss:
        results.append(check_epss(args.epss, cfg, now))
    if args.grype:
        results.extend(check_grype(args.grype, cfg, now))
    if args.dependabot:
        results.append(check_dependabot(args.dependabot))
    if args.previous_vdr:
        results.append(check_previous_vdr(args.previous_vdr))
    if args.checkov:
        results.append(check_checkov(args.checkov))
    if args.tfsec:
        results.append(check_tfsec(args.tfsec))
    if args.codeql:
        results.append(check_codeql(args.codeql, cfg, now))
    if args.zap_api:
        results.append(check_zap_api(args.zap_api, cfg, now))
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kev")
    ap.add_argument("--epss")
    ap.add_argument("--grype", nargs="+", help="each Grype scan (grype -o json), not the merged file")
    ap.add_argument("--dependabot")
    ap.add_argument("--previous-vdr")
    ap.add_argument("--checkov")
    ap.add_argument("--tfsec")
    ap.add_argument("--codeql", help="CodeQL alerts and analyses (scripts/fetch-detection-feeds.sh)")
    ap.add_argument("--zap-api", help="the authenticated ZAP API scan report")
    ap.add_argument("--config", default=None, help="detection feed requirements (default: the governed file)")
    ap.add_argument("--output", default="detection.json")
    ap.add_argument("--now", default=None, help="ISO time to evaluate at (tests)")
    args = ap.parse_args(argv)

    gates = _gates.load_gate_modes()
    cfg = load_config(args.config)
    now = _parse_time(args.now) if args.now else datetime.now(timezone.utc)
    if now is None:
        raise SystemExit(f"::error::--now is not an ISO time: {args.now!r}")
    results = evaluate(args, cfg, now)
    if not results:
        raise SystemExit("::error::detection gate given no inputs to check")

    hard = []
    for r in results:
        check = f"detection.{r['feed']}"
        r["status"] = "failed" if r.get("problem") else "ok"
        r["mode"] = _gates.mode_of(gates, check)
        if r["status"] == "ok":
            print(f"G7 {check}: ok ({r.get('count', '?')} item(s)"
                  + (f", {r['age_hours']}h old" if "age_hours" in r else "") + f") {r['file']}")
        elif r["mode"] == _gates.BLOCK:
            hard.append(r)
            print(f"::error::G7 {check}: {_gates._clean(r['problem'])} [{r['file']}]", file=sys.stderr)
        else:
            _gates.record_event(gates, check, f"{r['file']}: {r['problem']}")

    summary = {"schema": "detection/1", "checked_at": now.replace(microsecond=0).isoformat(),
               "config_version": cfg["version"], "config_sha256": cfg["sha256"],
               "result": "failed" if hard else "ok",
               "feeds": [{k: r.get(k) for k in ("feed", "file", "status", "mode", "count", "source_date",
                                                "age_hours", "problem")} for r in results]}
    for f in summary["feeds"]:
        if f["file"]:
            f["file"] = os.path.basename(f["file"])
    Path(args.output).write_text(json.dumps(summary, indent=2) + "\n")
    if hard:
        print(f"::error::G7 detection failed for {len(hard)} input(s); nothing is built or published on "
              "incomplete detection.", file=sys.stderr)
        return 1
    print(f"G7 detection: {len(results)} input(s) ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
