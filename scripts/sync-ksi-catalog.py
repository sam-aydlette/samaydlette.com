#!/usr/bin/env python3
"""Keep infrastructure/schemas/ksi-catalog.json equal to the pinned FedRAMP rules.

The catalog's KSI block (IDs, names, statements and KSI->control mappings) is
FedRAMP's, so it is derived from the vendored, hash-checked Consolidated Rules
(scripts/_rules.py), never edited by hand. FedRAMP revises mappings between
releases (for example on 2026-10-13); re-pinning the rules and re-running this
script carries the change, and tests/test_ksi_catalog_corpus.py fails while
the two disagree.

Control titles come from the vendored NIST SP 800-53 Rev5 catalog. The per-KSI impact flags are the catalog's
own (the corpus does not carry them) and are kept.

    sync-ksi-catalog.py            rewrite the catalog
    sync-ksi-catalog.py --check    exit 1 if it differs from the corpus
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _rules  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
NIST = REPO / "data" / "catalogs" / "NIST_SP-800-53_rev5_catalog.json"


def _fail(msg):
    raise SystemExit(f"::error::KSI catalog: {msg} (fail-closed)")


def _titles():
    out = {}

    def walk(group):
        for c in group.get("controls", []) or []:
            out[c["id"]] = c["title"]
            walk(c)
        for g in group.get("groups", []) or []:
            walk(g)
    walk(json.loads(NIST.read_text())["catalog"])
    return out


def derive(catalog, rules_dir=_rules.RULES_DIR):
    """The catalog with its KSI block rebuilt from the pinned corpus."""
    rules, _ = _rules.load_rules(rules_dir)
    titles = _titles()
    old_impact = {i["id"]: i.get("impact") for f in catalog.get("KSI", {}).values()
                  for i in f.get("indicators", [])}
    ksi = {}
    for fam_id, fam in rules["KSI"].items():
        indicators = []
        for kid, k in fam["indicators"].items():
            controls = []
            for c in k.get("controls", []) or []:
                cid = str(c).lower()
                if cid not in titles:
                    _fail(f"{kid} maps {cid}, which is not in the NIST SP 800-53 Rev5 catalog")
                controls.append({"control_id": cid, "title": titles[cid]})
            if kid not in old_impact:
                _fail(f"{kid} is new in the corpus; set its impact flags in the catalog first")
            # Class C's statement where the KSI varies by class (five do).
            statement = ((k.get("varies_by_class") or {}).get(_rules.CERT_CLASS) or k).get("statement")
            if not isinstance(statement, str):
                _fail(f"{kid} has no Class {_rules.CERT_CLASS.upper()} statement")
            indicators.append({"id": kid, "name": k["name"], "statement": statement,
                               "impact": old_impact[kid], "controls": controls})
        ksi[fam_id] = {"id": fam["id"], "name": fam["name"], "indicators": indicators}
    out = dict(catalog)
    out["KSI"] = ksi
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    current = json.loads(CATALOG.read_text())
    want = derive(current)
    if a.check:
        if want != current:
            print("::error::infrastructure/schemas/ksi-catalog.json differs from the pinned FedRAMP rules; "
                  "run scripts/sync-ksi-catalog.py and review the diff")
            return 1
        return 0
    CATALOG.write_text(json.dumps(want, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
