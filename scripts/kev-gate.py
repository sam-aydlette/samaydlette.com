#!/usr/bin/env python3
"""KEV gate before activation (VDR-CSO-AKE).

Providers SHOULD NOT deploy or activate new machine-based resources with Known
Exploited Vulnerabilities. The VDR build's G1 blocks a KEV finding, but in the
deploy it runs after `terraform apply` and the website sync: a Lambda package or
SPA bundle with a KEV dependency would already be live when it fails. This gate
runs before the plan and apply, over the same scanner output the VDR reads
(Grype over every dependency tree, open Dependabot alerts), and stops the deploy
when any matched CVE is in the CISA catalog. It names each KEV with the
catalog's due date (VDR-TFR-KEV).

It follows the governed mode of G1's check, `vdr.kev`, in
infrastructure/schemas/gate-modes.json: in block mode (the decided mode) a KEV
stops the deploy, dispositioned or not; a detect-and-recover mode would record
an event instead. A missing or unreadable input stops it: no catalog or no scan
output cannot read as "no KEV". (The detection gate, G7, has already checked
that each feed is present and fresh.)

    kev-gate.py --kev kev-catalog.json --grype grype-*.json --dependabot dependabot-alerts.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _gates  # noqa: E402

CHECK = "vdr.kev"


def _fail(msg):
    raise SystemExit(f"::error::KEV gate (VDR-CSO-AKE): {msg} (fail-closed)")


def _load(path, what):
    p = Path(path)
    if not p.is_file():
        _fail(f"{what} {path} not found")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{what} {path} is not valid JSON: {exc.__class__.__name__}")


def load_catalog(path):
    """{cveID: {dueDate, dateAdded, name}} from the CISA KEV catalog."""
    doc = _load(path, "KEV catalog")
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list) or not vulns:
        _fail(f"KEV catalog {path} has no vulnerabilities[]")
    return {v["cveID"]: {"due_date": v.get("dueDate"), "date_added": v.get("dateAdded"),
                         "name": v.get("vulnerabilityName")}
            for v in vulns if isinstance(v, dict) and isinstance(v.get("cveID"), str)}


def grype_cves(path):
    """[(cve, package@version, source file)] for every Grype match, including a
    CVE named only as a related vulnerability of a GHSA match."""
    doc = _load(path, "Grype output")
    if not isinstance(doc, dict) or not isinstance(doc.get("matches", []), list):
        _fail(f"Grype output {path} has no matches[]")
    out = []
    for m in doc.get("matches") or []:
        art = m.get("artifact") or {}
        where = f"{art.get('name')}@{art.get('version')}"
        ids = [(m.get("vulnerability") or {}).get("id")]
        ids += [r.get("id") for r in m.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
        for i in ids:
            if isinstance(i, str) and i.upper().startswith("CVE-"):
                out.append((i.upper(), where, Path(path).name))
    return out


def dependabot_cves(path):
    doc = _load(path, "Dependabot alerts")
    if not isinstance(doc, list):
        _fail(f"Dependabot alerts {path} is not a list")
    out = []
    for a in doc:
        adv = (a or {}).get("security_advisory") or {}
        pkg = ((a or {}).get("dependency") or {}).get("package") or {}
        ids = [adv.get("cve_id")] + [i.get("value") for i in adv.get("identifiers") or []
                                     if isinstance(i, dict) and i.get("type") == "CVE"]
        for i in {x.upper() for x in ids if isinstance(x, str) and x.upper().startswith("CVE-")}:
            out.append((i, pkg.get("name") or "?", Path(path).name))
    return out


def kev_hits(catalog, matches):
    """Sorted unique [(cve, where, file, due_date)] for matches in the catalog."""
    return sorted({(c, w, f, catalog[c]["due_date"]) for c, w, f in matches if c in catalog})


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", required=True)
    ap.add_argument("--grype", nargs="+", required=True)
    ap.add_argument("--dependabot", required=True)
    a = ap.parse_args(argv)
    catalog = load_catalog(a.kev)
    matches = [m for g in a.grype for m in grype_cves(g)] + dependabot_cves(a.dependabot)
    hits = kev_hits(catalog, matches)
    gates = _gates.load_gate_modes()
    print(f"KEV gate: {len(matches)} CVE match(es) across {len(a.grype)} Grype scan(s) and Dependabot; "
          f"{len(catalog)} CVEs in the catalog; {len(hits)} known exploited.")
    if not hits:
        return 0
    for cve, where, src, due in hits:
        # Scanner text goes into a GitHub Actions log, which parses `::` commands:
        # _clean strips line breaks and `::` from it.
        line = _gates._clean(f"{cve} in {where} ({src}) is in the CISA KEV catalog, due {due or 'no due date'}")
        if _gates.blocks(gates, CHECK):
            print(f"::error::{line}", file=sys.stderr)
        else:
            _gates.record_event(gates, CHECK, f"pre-apply: {line}")
    if _gates.blocks(gates, CHECK):
        print(f"::error::KEV gate: {len(hits)} known exploited vulnerabilit(y/ies) would be deployed; "
              "remediate before activation (VDR-CSO-AKE).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
