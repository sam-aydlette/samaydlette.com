#!/usr/bin/env python3
# =============================================================================
# POLICY INDEX BUILDER  (CR26 CDS-CSO-IRP)
# =============================================================================
# CR26 CDS-CSO-IRP requires a machine-readable reference to every relevant policy
# and procedure, with seven fields each: name; file/page name; brief summary;
# word count; current version; date of last update; related FedRAMP Practices.
# This scans the repo's policy and procedure markdown and emits that index as
# JSON + human-readable markdown. Last-update dates come from git where available.
#
#   build-policy-index.py            # run from repo root
# =============================================================================

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Family/topic -> related FedRAMP Practices, keyed by filename stem.
RELATED = {
    "secure-configuration-guide": "SCG-CSO-*, SCG-ENH-*",
    "cm-policy": "CM family; SCN-*, MAS-*, KSI-CMT",
    "ir-policy": "IR family; IEC-CSO-*, VER-TFR-IRI, KSI-INR",
    "ra-policy": "RA family; VDR-*, VER-*, KSI-MLA",
    "sc-policy": "SC family; CMU-CSO-*, KSI-SVC",
    "sr-policy": "SR family; KSI-SCR",
    "continuous-monitoring-plan": "CCM-OCR-*, CCM-QTR-*",
    "incident-response": "IR family; IEC-CSO-*",
    "recovery-plan": "CP family; KSI-RPL",
    "security-review": "CA family; KSI-PIY",
    "supply-chain": "SR family; KSI-SCR",
    "privacy-threshold-analysis": "PT family",
    "rules-of-behavior": "PL-4, PS family",
}


def _last_updated(path):
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", str(path)],
                             cwd=REPO, capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _summary(text):
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("---") or s.startswith(">"):
            continue
        s = re.sub(r"[*`_\[\]]", "", s)
        return s[:240]
    return ""


def _name(text, stem):
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return stem.replace("-", " ").title()


def index_file(rel):
    path = REPO / rel
    text = path.read_text()
    stem = path.stem
    words = len(re.findall(r"\S+", text))
    related = RELATED.get(stem) or (f"{stem.split('-')[0].upper()} family"
                                    if stem.endswith("-policy") else "general")
    return {
        "name": _name(text, stem),
        "file": rel,
        "summary": _summary(text),
        "word_count": words,
        "version": "live (continuously maintained; regenerated each deploy)",
        "last_updated": _last_updated(path),
        "related_practices": related,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="policy-index.json")
    ap.add_argument("--md-output", default="policy-index.md")
    a = ap.parse_args()

    files = sorted(str(p.relative_to(REPO)) for p in (REPO / "docs" / "policies").glob("*.md")
                   if p.name != "README.md")
    for extra in ("docs/continuous-monitoring-plan.md", "docs/incident-response.md",
                  "docs/recovery-plan.md", "docs/security-review.md", "docs/supply-chain.md",
                  "docs/privacy-threshold-analysis.md", "docs/rules-of-behavior.md", "docs/poam.md"):
        if (REPO / extra).exists():
            files.append(extra)

    entries = [index_file(f) for f in files]
    index = {
        "index_type": "policy-and-procedure-index",
        "rule": "CDS-CSO-IRP",
        "count": len(entries),
        "entries": entries,
    }
    Path(a.output).write_text(json.dumps(index, indent=2) + "\n")
    if a.md_output:
        out = ["# Policy and Procedure Index", "",
               f"Machine- and human-readable index of {len(entries)} policies and procedures "
               "(CDS-CSO-IRP). Source of truth: the JSON alongside this file.", "",
               "| Policy | File | Words | Last updated | Related Practices |",
               "|---|---|---|---|---|"]
        for e in entries:
            out.append("| {n} | `{f}` | {w} | {u} | {r} |".format(
                n=e["name"], f=e["file"], w=e["word_count"],
                u=e["last_updated"] or "—", r=e["related_practices"]))
        Path(a.md_output).write_text("\n".join(out) + "\n")
    print(f"policy-index: {len(entries)} policies indexed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
