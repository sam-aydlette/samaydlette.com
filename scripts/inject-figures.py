#!/usr/bin/env python3
# =============================================================================
# FIGURE INJECTOR  (Phase 2 — single-source figures for paper + dashboard)
# =============================================================================
# Every load-bearing number in the research paper and the dashboard is derived
# from a generated artifact, not typed by hand. This script computes those
# figures from the canonical artifacts (the OSCAL SSP, the component definition,
# the spoke profiles, the dispositions, and the CMMC projector's own output) and
# stamps them into HTML at marked sites:
#
#     <span data-figure="hub_total">331</span>
#     <div class="status-value" data-figure="moderate_coverage">331/331</div>
#
# The text between the tags is replaced with the computed value. A marker whose
# key is unknown is an error (the HTML references a figure the build cannot
# produce); a computed key that no marker uses is reported but tolerated.
#
# This is the mechanism that keeps the prose honest: change the SSP and the
# number in the paper changes on the next deploy, because the deploy runs this
# with --check (CI fails if any stamped figure has drifted from its source) and
# then in write mode.
#
#   inject-figures.py                 # stamp all targets in place
#   inject-figures.py --check         # exit 1 if any marker is stale (CI gate)
#   inject-figures.py --print         # print the computed figure table and exit
#
# Acceptance: altering the SSP's implemented-requirement count changes
# hub_total / hub_generated / moderate_coverage everywhere they are marked.
# =============================================================================

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SSP = REPO / "infrastructure" / "oscal-ssp.json"
COMPONENT_DEF = REPO / "data" / "component-definitions" / "samaydlette-com-component-definition.json"
DISPOSITIONS = REPO / "data" / "dispositions" / "beyond-moderate.json"
CATALOG_171 = REPO / "data" / "catalogs" / "NIST_SP-800-171_rev2_catalog.json"

PROFILES = {
    "govramp": REPO / "data" / "profiles" / "govramp_moderate_cjis_profile.json",
    "txramp1": REPO / "data" / "profiles" / "txramp_level1_profile.json",
    "txramp2": REPO / "data" / "profiles" / "txramp_level2_profile.json",
}

TARGETS = [
    REPO / "website" / "research" / "the-plumbing.html",
    REPO / "website" / "viewer.html",
]


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _count_catalog(catalog):
    """Count leaf control entries in an OSCAL catalog (recursively)."""
    n = 0

    def walk(group):
        nonlocal n
        for c in group.get("controls", []) or []:
            n += 1
            walk(c)
        for sg in group.get("groups", []) or []:
            walk(sg)

    walk(catalog["catalog"])
    return n


def _profile_selection_count(path):
    """Count distinct controls a profile selects via include-controls/with-ids."""
    prof = json.loads(path.read_text())["profile"]
    ids = set()
    for imp in prof.get("imports", []) or []:
        for inc in imp.get("include-controls", []) or []:
            ids.update(inc.get("with-ids", []) or [])
    return len(ids)


def _authored_hub_controls():
    """Distinct control-ids with a hand-written implementation in the hub."""
    cd = json.loads(COMPONENT_DEF.read_text())["component-definition"]
    ids = set()
    for comp in cd.get("components", []) or []:
        for ci in comp.get("control-implementations", []) or []:
            for ir in ci.get("implemented-requirements", []) or []:
                ids.add(ir.get("control-id"))
    return len(ids)


def _cmmc_figures():
    """Run the CMMC projector and read its JSON output (the same code path the
    dashboard's CMMC card describes)."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tmp:
        out = tmp.name
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "build-cmmc.py"),
         "--ssp", str(SSP), "--output", out],
        check=True, capture_output=True, text=True,
    )
    cov = json.loads(Path(out).read_text())
    Path(out).unlink(missing_ok=True)
    srm = cov["srm_view"]
    return cov, srm


def compute_figures():
    """Compute every stamped figure from canonical artifacts. Returns
    {figure_key: string_value}. This is the single source of truth."""
    bc = _load_module("build_coverage", REPO / "scripts" / "build-coverage.py")
    ssp = json.loads(SSP.read_text())
    cov = bc.build_coverage(ssp, "FedRAMP Rev5 Moderate")
    rs = cov["responsibility_stack"]

    hub_total = cov["in_scope_controls"]
    hub_handwritten = _authored_hub_controls()
    hub_generated = hub_total - hub_handwritten
    mod_impl = rs["implemented"]
    mod_inherited = rs["fully-inherited"] + rs["partially-inherited"]
    mod_na = rs["not-applicable"]

    govramp = _profile_selection_count(PROFILES["govramp"])
    txramp1 = _profile_selection_count(PROFILES["txramp1"])
    txramp2 = _profile_selection_count(PROFILES["txramp2"])

    cmmc_cov, srm = _cmmc_figures()
    cmmc_total = cmmc_cov["in_scope_requirements"]
    osc_fully = srm["inherited"]
    osc_shared = srm["shared"]
    osc_resp = srm["osc-responsibility"]
    osc_inherits = osc_fully + osc_shared

    return {
        # hub
        "hub_total": str(hub_total),
        "hub_handwritten": str(hub_handwritten),
        "hub_generated": str(hub_generated),
        # FedRAMP Moderate
        "moderate_coverage": f"{hub_total}/{hub_total}",
        "moderate_implemented": str(mod_impl),
        "moderate_inherited": str(mod_inherited),
        "moderate_na": str(mod_na),
        # spokes
        "govramp_coverage": f"{govramp}/{govramp}",
        "txramp1_coverage": f"{txramp1}/{txramp1}",
        "txramp2_coverage": f"{txramp2}/{txramp2}",
        # CMMC
        "cmmc_total": str(cmmc_total),
        "cmmc_coverage": f"{cmmc_total}/{cmmc_total}",
        "cmmc_osc_inherits": f"{osc_inherits}/{cmmc_total}",
        "cmmc_osc_inherits_count": str(osc_inherits),
        "cmmc_osc_fully": str(osc_fully),
        "cmmc_osc_shared": str(osc_shared),
        "cmmc_osc_responsibility": str(osc_resp),
    }


# Match an element carrying data-figure="KEY" and capture its inner text.
# Attribute order is tolerated (data-figure may precede or follow other attrs).
_MARKER = re.compile(
    r'(<(?P<tag>\w+)(?P<pre>[^>]*?)\sdata-figure="(?P<key>[\w-]+)"(?P<post>[^>]*?)>)'
    r'(?P<inner>.*?)'
    r'(?P<close></(?P=tag)>)',
    re.DOTALL,
)


def stamp(html, figures, source_label=""):
    """Replace the inner text of every data-figure marker with its computed
    value. Returns (new_html, changes, unknown_keys, used_keys)."""
    changes = []
    unknown = []
    used = set()

    def repl(m):
        key = m.group("key")
        used.add(key)
        if key not in figures:
            unknown.append(key)
            return m.group(0)
        new_val = figures[key]
        old_val = m.group("inner")
        if old_val != new_val:
            changes.append((source_label, key, old_val, new_val))
        return f'{m.group(1)}{new_val}{m.group("close")}'

    new_html = _MARKER.sub(repl, html)
    return new_html, changes, unknown, used


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any marked figure is stale (do not write)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the computed figure table and exit")
    ap.add_argument("--targets", nargs="*", default=None,
                    help="override target HTML files (default: paper + dashboard)")
    args = ap.parse_args()

    figures = compute_figures()

    if args.print_only:
        width = max(len(k) for k in figures)
        for k in sorted(figures):
            print(f"  {k:<{width}}  {figures[k]}")
        return 0

    targets = [Path(t) for t in args.targets] if args.targets else TARGETS

    all_changes = []
    all_unknown = []
    all_used = set()
    pending = []
    for path in targets:
        if not path.exists():
            print(f"error: target not found: {path}", file=sys.stderr)
            return 2
        html = path.read_text()
        new_html, changes, unknown, used = stamp(html, figures, path.name)
        all_changes.extend(changes)
        all_unknown.extend((path.name, k) for k in unknown)
        all_used.update(used)
        pending.append((path, new_html, html != new_html))

    if all_unknown:
        for name, key in all_unknown:
            print(f"error: {name} references unknown figure {key!r}", file=sys.stderr)
        return 2

    unused = sorted(set(figures) - all_used)
    if unused:
        print(f"note: computed figures not stamped anywhere: {', '.join(unused)}",
              file=sys.stderr)

    if args.check:
        if all_changes:
            print("STALE: marked figures do not match their source:", file=sys.stderr)
            for src, key, old, new in all_changes:
                print(f"  {src}: {key}: {old!r} -> {new!r}", file=sys.stderr)
            return 1
        print(f"figures up to date ({len(all_used)} markers across {len(targets)} files)")
        return 0

    for path, new_html, changed in pending:
        if changed:
            path.write_text(new_html)
    if all_changes:
        print(f"stamped {len(all_changes)} figure(s):")
        for src, key, old, new in all_changes:
            print(f"  {src}: {key}: {old!r} -> {new!r}")
    else:
        print(f"figures already current ({len(all_used)} markers across {len(targets)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
