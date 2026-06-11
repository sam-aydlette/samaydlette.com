#!/usr/bin/env python3
# =============================================================================
# 800-171 Rev2 OSCAL CATALOG BUILDER  (Phase 2 / CMMC)
# =============================================================================
# Builds an OSCAL catalog of NIST SP 800-171 Rev 2 (the 110 security
# requirements) from NIST's authoritative machine-readable export
# (sp800-171r2-security-reqs.xlsx). CMMC Level 2 = these 110 requirements,
# locked to Rev 2 by DoD class deviation. NIST does not publish 800-171 as
# OSCAL, so this derives the catalog from the authoritative NIST source rather
# than a community conversion.
#
# Output: data/catalogs/NIST_SP-800-171_rev2_catalog.json
# =============================================================================

import argparse
import json
import re
import uuid
from pathlib import Path

import openpyxl

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "data" / "catalogs" / "NIST_SP-800-171_rev2_catalog.json"
NS = uuid.UUID("171a2000-0000-5000-8000-000000000002")
LAST_MODIFIED = "2026-06-10T00:00:00Z"


def sid(*p):
    return str(uuid.uuid5(NS, ":".join(p)))


def build(xlsx_path):
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb["SP 800-171"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))  # row 1 = header

    groups = {}   # family id "3.1" -> {title, controls:[]}
    order = []
    for r in rows:
        family, bod, ident, sortas, req, disc = (r + (None,) * 6)[:6]
        if not ident or not re.match(r"^\d+\.\d+\.\d+$", str(ident).strip()):
            continue
        ident = str(ident).strip()
        fam_id = ".".join(ident.split(".")[:2])  # 3.1.1 -> 3.1
        if fam_id not in groups:
            groups[fam_id] = {"title": str(family).strip(), "controls": []}
            order.append(fam_id)
        control = {
            "id": ident,
            "title": ident,
            "props": [
                {"name": "label", "value": ident},
                {"name": "sort-id", "value": str(sortas).strip() if sortas else ident},
                {"name": "basic-or-derived", "value": str(bod).strip() if bod else ""},
            ],
            "parts": [{"id": f"{ident}_smt", "name": "statement",
                       "prose": str(req).strip() if req else ""}],
        }
        if disc:
            control["parts"].append({"id": f"{ident}_gdn", "name": "guidance",
                                     "prose": str(disc).strip()})
        groups[fam_id]["controls"].append(control)
    wb.close()

    catalog = {
        "catalog": {
            "uuid": sid("catalog", "800-171r2"),
            "metadata": {
                "title": "NIST SP 800-171 Revision 2 — Protecting CUI in Nonfederal Systems",
                "last-modified": LAST_MODIFIED,
                "version": "Rev 2",
                "oscal-version": "1.2.2",
                "remarks": ("Derived from NIST's authoritative machine-readable export "
                            "(sp800-171r2-security-reqs.xlsx). The 110 security requirements "
                            "= CMMC Level 2 (locked to Rev 2 by DoD class deviation)."),
            },
            "groups": [
                {"id": fam, "title": groups[fam]["title"], "controls": groups[fam]["controls"]}
                for fam in order
            ],
        }
    }
    return catalog, order, groups


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xlsx", default="/home/saydlette/Downloads/sp800-171r2-security-reqs.xlsx")
    a = ap.parse_args()
    catalog, order, groups = build(a.xlsx)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(catalog, indent=2) + "\n")
    total = sum(len(groups[f]["controls"]) for f in order)
    print(f"800-171 Rev2 OSCAL catalog: {len(order)} families, {total} requirements")
    print(f"  families: {[(f, groups[f]['title'][:24], len(groups[f]['controls'])) for f in order[:4]]} ...")
    print(f"wrote: {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
