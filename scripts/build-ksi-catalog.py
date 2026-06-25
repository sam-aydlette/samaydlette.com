#!/usr/bin/env python3
# =============================================================================
# KSI CATALOG BUILDER  (CR26 final)
# =============================================================================
# Regenerates infrastructure/schemas/ksi-catalog.json from the FedRAMP
# Consolidated Rules for 2026 (final, launched 2026-06-24). The final corpus
# renumbered the Key Security Indicators from the old numeric scheme
# (KSI-CNA-01) to mnemonic IDs (KSI-CNA-RNT), dropped the AFR family, and
# renamed TPR -> SCR. The corpus ships as markdown only; this script parses the
# 11 KSI markdown files into the same JSON shape the SSP generator already
# consumes (info / FRR.KSI carried forward from the prior vendored catalog;
# the KSI block rebuilt from the markdown).
#
# The catalog is VENDORED reference data, not a CI-built artifact: this script
# is run by the operator when FedRAMP republishes the rules, and the resulting
# JSON is committed. Control titles are reused from the prior catalog where the
# control_id matches (the controls did not change, only the KSI IDs).
#
#   build-ksi-catalog.py --source <corpus>/providers/20x/key-security-indicators
# =============================================================================

import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = Path("/home/saydlette/workspace/final_consolidated_rules_2026/"
                      "2026-markdown/providers/20x/key-security-indicators")
DEFAULT_OLD = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
DEFAULT_OUT = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"

# family code -> (display name, source filename)
FAMILIES = {
    "CED": ("Cybersecurity Education", "cybersecurity-education.md"),
    "CMT": ("Change Management", "change-management.md"),
    "CNA": ("Cloud Native Architecture", "cloud-native-architecture.md"),
    "IAM": ("Identity and Access Management", "identity-and-access-management.md"),
    "INR": ("Incident Response", "incident-response.md"),
    "MLA": ("Monitoring, Logging, and Auditing", "monitoring-logging-and-auditing.md"),
    "PIY": ("Policy and Inventory", "policy-and-inventory.md"),
    "RPL": ("Recovery Planning", "recovery-planning.md"),
    "SCR": ("Supply Chain Risk", "supply-chain-risk.md"),
    "SVC": ("Service Configuration", "service-configuration.md"),
}

KSI_RE = re.compile(r'^\?\?\? abstract "(KSI-[A-Z]{3}-[A-Z0-9]{2,3})"')
HEADING_RE = re.compile(r'^###\s+(.*\S)\s*$')
CONTROL_REF_RE = re.compile(r'\[([A-Z]{2}-\d{1,2}(?:\s*\(\d{1,2}\))?)\]')


def control_id(ref):
    """'AC-17 (03)' -> 'ac-17.3'; 'CM-02' -> 'cm-2'."""
    m = re.match(r'([A-Z]{2})-0*(\d+)(?:\s*\(0*(\d+)\))?', ref)
    fam, num, enh = m.group(1).lower(), m.group(2), m.group(3)
    cid = f"{fam}-{num}"
    if enh:
        cid += f".{enh}"
    return cid


# Control titles not present in the prior catalog's crosswalks (filled in by hand
# from NIST SP 800-53 Rev 5 so no control carries an empty title).
SUPPLEMENTAL_TITLES = {
    "sc-28": "Protection of Information at Rest",
    "sc-28.1": "Cryptographic Protection",
}


def title_map_from_old(old):
    """Build {control_id: title} from the prior catalog's control crosswalks."""
    m = {}
    for fam in old.get("KSI", {}).values():
        for ind in fam.get("indicators", []) or []:
            for c in ind.get("controls", []) or []:
                cid, title = c.get("control_id"), c.get("title")
                if cid and title and cid not in m:
                    m[cid] = title
    return m


def parse_family(path, fam_code):
    """Parse one KSI markdown file -> list of indicator dicts."""
    lines = path.read_text().splitlines()
    indicators = []
    i = 0
    heading = None
    while i < len(lines):
        hm = HEADING_RE.match(lines[i])
        if hm:
            heading = hm.group(1)
            i += 1
            continue
        km = KSI_RE.match(lines[i])
        if not km:
            i += 1
            continue
        ksi_id = km.group(1)
        # advance to the quote block
        j = i + 1
        while j < len(lines) and '!!! quote ""' not in lines[j]:
            j += 1
        # collect the quote block until the next KSI / heading / EOF
        block = []
        k = j + 1
        while k < len(lines):
            if KSI_RE.match(lines[k]) or HEADING_RE.match(lines[k]):
                break
            block.append(lines[k])
            k += 1
        statement, controls, class_c_only = _parse_block(block)
        indicators.append({
            "id": ksi_id,
            "name": heading or ksi_id,
            "statement": statement,
            "impact": {"low": not class_c_only, "moderate": True},
            "controls": controls,
        })
        i = k
    return indicators


def _parse_block(block):
    text = "\n".join(block)
    class_c_only = '=== "Class B"' in text and "Optional" in text
    # statement
    statement = ""
    if '=== "Class C"' in text:
        seg = text.split('=== "Class C"', 1)[1]
        # stop at the next marker
        for stop in ('=== "Class', "**Related", "**Terms", "\n    ---"):
            if stop in seg:
                seg = seg.split(stop, 1)[0]
        statement = _clean(seg)
    else:
        # first non-marker paragraph after the quote opener
        seg = text
        for stop in ("**Related", "**Terms", "\n    ---"):
            if stop in seg:
                seg = seg.split(stop, 1)[0]
        statement = _clean(seg)
    # controls
    controls = []
    cm = re.search(r'\*\*Related SP 800-53 Controls:\*\*(.*)', text, re.DOTALL)
    if cm:
        seg = cm.group(1)
        for stop in ("**Terms", "\n    ---", "\n###"):
            if stop in seg:
                seg = seg.split(stop, 1)[0]
        seen = set()
        for ref in CONTROL_REF_RE.findall(seg):
            cid = control_id(ref)
            if cid not in seen:
                seen.add(cid)
                controls.append(cid)
    return statement, controls, class_c_only


def _clean(s):
    s = s.replace("**Optional:**", "")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SOURCE))
    ap.add_argument("--old", default=str(DEFAULT_OLD))
    ap.add_argument("--output", default=str(DEFAULT_OUT))
    a = ap.parse_args()

    src = Path(a.source)
    old = json.loads(Path(a.old).read_text())
    titles = title_map_from_old(old)
    titles.update(SUPPLEMENTAL_TITLES)

    misses = set()
    ksi_block = {}
    total = 0
    class_c_only_ids = []
    for fam_code, (fam_name, fname) in FAMILIES.items():
        inds = parse_family(src / fname, fam_code)
        for ind in inds:
            enriched = []
            for cid in ind["controls"]:
                t = titles.get(cid)
                if not t:
                    misses.add(cid)
                enriched.append({"control_id": cid, "title": t or ""})
            ind["controls"] = enriched
            if not ind["impact"]["low"]:
                class_c_only_ids.append(ind["id"])
        ksi_block[fam_code] = {
            "id": f"KSI-{fam_code}",
            "name": fam_name,
            "indicators": inds,
        }
        total += len(inds)

    # carry info + FRR.KSI forward, append a CR26-final release note
    info = old.get("info", {})
    releases = info.get("releases", []) or []
    if not any(r.get("id") == "26.06" for r in releases):
        releases.insert(0, {
            "id": "26.06",
            "published_date": "2026-06-24",
            "description": ("Consolidated Rules for 2026 (official launch). Key Security "
                            "Indicators renumbered to mnemonic IDs; the AFR (Authorization "
                            "by FedRAMP) family was retired and TPR (Third-Party) was "
                            "renamed SCR (Supply Chain Risk). Rebuilt from the published "
                            "markdown corpus by scripts/build-ksi-catalog.py."),
        })
    info["releases"] = releases

    out = {
        "$schema": old.get("$schema", "FedRAMP.schema.json"),
        "$id": old.get("$id", "FedRAMP.schema.json"),
        "info": info,
        "FRR.KSI": old.get("FRR.KSI", {}),
        "KSI": ksi_block,
    }
    Path(a.output).write_text(json.dumps(out, indent=2) + "\n")

    print(f"wrote {a.output}")
    print(f"  families: {len(ksi_block)}  indicators: {total}")
    print(f"  Class-C-only (low=false): {len(class_c_only_ids)} -> {', '.join(class_c_only_ids)}")
    if misses:
        print(f"  control titles not found in prior catalog ({len(misses)}): "
              f"{', '.join(sorted(misses))}")


if __name__ == "__main__":
    main()
