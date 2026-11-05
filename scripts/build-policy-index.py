#!/usr/bin/env python3
# =============================================================================
# POLICY INDEX BUILDER  (CR26 CDS-CSO-IRP)
# =============================================================================
# CR26 CDS-CSO-IRP requires a machine-readable reference to every relevant policy
# and procedure, with seven fields each: name; file/page name; brief summary;
# word count; current version; date of last update; related FedRAMP Practices.
# This scans the repo's policy and procedure markdown and emits that index as
# JSON + human-readable markdown, with every field in both, and (with
# --publish-dir) copies each document for publication under
# /.well-known/policies/. Related FedRAMP Practices are concrete rule and KSI IDs
# from the pinned rules and the KSI catalog, never free text. Each entry's last-update date and version are the last commit that changed
# it; the build refuses a shallow clone, where every file looks changed today.
#
#   build-policy-index.py            # run from repo root
# =============================================================================

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

SITE = "https://samaydlette.com/.well-known/policies/"
RULES_DIR = REPO / "infrastructure" / "schemas" / "fedramp-rules"
CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"

# Procedures indexed beside the policies (CDS-CSO-IRP: "policies and procedures").
PROCEDURES = ("docs/continuous-monitoring-plan.md", "docs/incident-response.md", "docs/recovery-plan.md",
              "docs/security-review.md", "docs/supply-chain.md", "docs/privacy-threshold-analysis.md",
              "docs/rules-of-behavior.md", "docs/verification.md", "docs/ksi-signal.md",
              "docs/silk-reeling-deploy.md", "docs/architecture-decisions.md")
PROCEDURE_DIRS = ("docs/procedures", "docs/runbooks")

# Related FedRAMP Practices, by document: prefixes of FedRAMP rule IDs and KSI
# IDs, expanded against the pinned rules and the KSI catalog (a prefix that
# matches nothing fails the build). An "<x>-policy" also gets every applicable
# rule and every KSI mapped to a control in its NIST family.
PRACTICES = {
    "secure-configuration-guide": ("SCG-",),
    "resource-tagging-standard": ("MAS-CSO-IIR", "MAS-CSO-FLO"),
    "cm-policy": ("SCN-", "KSI-CMT-"),
    "ir-policy": ("IEC-", "KSI-INR-"),
    "ra-policy": ("VDR-", "VER-"),
    "sc-policy": ("CMU-",),
    "ca-policy": ("IVV-", "CCM-"),
    "continuous-monitoring-plan": ("CCM-", "KSI-MLA-"),
    "incident-response": ("IEC-", "KSI-INR-"),
    "recovery-plan": ("KSI-RPL-",),
    "security-review": ("KSI-PIY-", "CCM-QTR-"),
    "supply-chain": ("KSI-SCR-", "MAS-CSO-TPR"),
    "privacy-threshold-analysis": ("MAS-CSO-MDI",),
    "rules-of-behavior": ("KSI-CED-",),
    "verification": ("IVV-CSO-STE", "CDS-TRC-PAC", "SDR-CSO-"),
    "ksi-signal": ("FRC-CSX-", "MAS-CSO-IIR"),
    "silk-reeling-deploy": ("KSI-CMT-",),
    "architecture-decisions": ("SCN-CSO-", "KSI-CMT-"),
    "agency-access": ("CDS-TRC-AAI", "CDS-TRC-SSM", "CDS-UTC-"),
    "information-sharing": ("CDS-CSO-RIS", "CDS-CSO-RPS"),
    "evidence-sla-alarm": ("KSI-MLA-", "CDS-CSO-AVR"),
    "vuln-gate-failure": ("VDR-", "KSI-SVC-VRI"),
}
ACCESS = ("Every policy and procedure listed here is served as Markdown at its url (no authentication), and its "
          "source is the file in the public repository. This index is published as JSON (policy-index.json, signed) "
          "and Markdown (policy-index.md) and listed in the trust manifest (trust-manifest.json).")


def practice_ids(rules_dir=RULES_DIR, catalog_path=CATALOG):
    """(sorted rule and KSI IDs, {NIST family: [IDs]}) from the pinned rules and the catalog."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _rules  # noqa: E402

    rules, _ = _rules.load_rules(rules_dir)
    applicable = _rules.applicable_provider_rules(rules_dir)
    by_family = {}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in applicable and isinstance(v, dict):
                    for c in v.get("controls") or []:
                        by_family.setdefault(c.split("-")[0], set()).add(k)
                walk(v)
    walk(rules.get("FRR", {}))
    catalog = json.loads(Path(catalog_path).read_text())
    ksis = set()
    for fam in catalog["KSI"].values():
        for ind in fam["indicators"]:
            ksis.add(ind["id"])
            for c in ind.get("controls", []):
                by_family.setdefault(c["control_id"].split("-")[0], set()).add(ind["id"])
    return sorted(set(applicable) | ksis), {f: sorted(v) for f, v in by_family.items()}


def related(stem, ids, by_family):
    out = set()
    for prefix in PRACTICES.get(stem, ()):
        hit = [i for i in ids if i.startswith(prefix)]
        if not hit:
            sys.exit(f"build-policy-index: {stem}: {prefix!r} matches no FedRAMP rule or KSI")
        out.update(hit)
    if stem.endswith("-policy"):
        out.update(by_family.get(stem.split("-")[0], []))
    return sorted(out)


def _is_shallow():
    out = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                         cwd=REPO, capture_output=True, text=True, timeout=10)
    if out.returncode != 0:
        sys.exit(f"build-policy-index: not a git checkout ({out.stderr.strip()}); refusing to guess dates")
    return out.stdout.strip() == "true"


def _last_change(path):
    """(date, commit) of the last commit that changed `path`. Fails closed: a
    date this index cannot read is never published as a guess or a blank. In a
    shallow clone every file looks last changed by the one commit fetched, which
    published the deploy date as every policy's date; main() refuses that."""
    out = subprocess.run(["git", "log", "-1", "--format=%cs %H", "--", str(path)],
                         cwd=REPO, capture_output=True, text=True, timeout=10)
    parts = out.stdout.split()
    if out.returncode != 0 or len(parts) != 2:
        sys.exit(f"build-policy-index: no git history for {path}")
    return parts[0], parts[1]


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


def index_file(rel, ids, by_family):
    path = REPO / rel
    text = path.read_text()
    stem = path.stem
    words = len(re.findall(r"\S+", text))
    date, commit = _last_change(path)
    return {
        "name": _name(text, stem),
        "kind": "policy" if rel.startswith("docs/policies/") else "procedure",
        "file": rel,
        "url": SITE + path.name,
        "summary": _summary(text),
        "word_count": words,
        "version": f"git:{commit[:12]}",
        "last_updated": date,
        "related_practices": related(stem, ids, by_family),
    }


def documents():
    files = sorted(str(p.relative_to(REPO)) for p in (REPO / "docs" / "policies").glob("*.md")
                   if p.name != "README.md")
    files += [f for f in PROCEDURES if (REPO / f).exists()]
    for d in PROCEDURE_DIRS:
        files += sorted(str(p.relative_to(REPO)) for p in (REPO / d).glob("*.md") if p.name != "README.md")
    names = [Path(f).name for f in files]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        sys.exit(f"build-policy-index: two documents would publish as {dup}")
    return files


def render_markdown(index):
    out = ["# Policy and Procedure Index", "",
           f"Machine- and human-readable index of {index['count']} policies and procedures "
           "(CDS-CSO-IRP). Source of truth: the JSON alongside this file.", "",
           f"**How to access them:** {index['access']}", ""]
    for e in index["entries"]:
        out += [f"## {e['name']}", "",
                f"- **Kind:** {e['kind']} | **File:** [`{e['file']}`]({e['url']}) | **Words:** {e['word_count']}",
                f"- **Version:** `{e['version']}` | **Last updated:** {e['last_updated']}",
                f"- **Summary:** {e['summary']}",
                f"- **Related FedRAMP Practices:** {', '.join(e['related_practices']) or 'none'}", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="policy-index.json")
    ap.add_argument("--md-output", default="policy-index.md")
    ap.add_argument("--publish-dir", default=None, help="copy every indexed document here for publication")
    a = ap.parse_args()

    if _is_shallow():
        sys.exit("build-policy-index: shallow clone; the last-update dates need full history "
                 "(actions/checkout fetch-depth: 0)")
    ids, by_family = practice_ids()
    entries = [index_file(f, ids, by_family) for f in documents()]
    index = {
        "index_type": "policy-and-procedure-index",
        "fedRampId": _offering.fedramp_id(),
        "rule": "CDS-CSO-IRP",
        "access": ACCESS,
        "count": len(entries),
        "entries": entries,
    }
    Path(a.output).write_text(json.dumps(index, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(index) + "\n")
    if a.publish_dir:
        # The documents themselves, served beside the index (CDS-CSO-IRP: supplied
        # in the certification data, not only in the repository).
        dest = Path(a.publish_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for e in entries:
            (dest / Path(e["file"]).name).write_bytes((REPO / e["file"]).read_bytes())
    print(f"policy-index: {len(entries)} policies indexed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
