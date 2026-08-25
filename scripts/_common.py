#!/usr/bin/env python3
# =============================================================================
# SHARED GENERATOR HELPERS
# =============================================================================
# The one place the artifact generators share code.
#
# Every generator here is deliberately standalone-runnable and stdlib-only: CI
# invokes them as plain scripts from varying working directories (the KSI signal
# builder runs as `python3 ../scripts/build-ksi-signal.py` from infrastructure/),
# and there is no package, no install step, and no PYTHONPATH to depend on. That
# constraint is worth keeping, so this module is imported the same way
# tools/essay/paths.py already is:
#
#     import os, sys
#     sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
#     from _common import classify, sha256_file
#
# The insert is __file__-relative, so it resolves from any cwd. Scripts under
# scripts/staged/ insert the parent directory instead.
#
# WHAT BELONGS HERE: only definitions that were already duplicated VERBATIM, and
# only where divergence between the copies would be a bug rather than a choice.
# The four copies of classify() were the case that mattered — it is a compliance
# semantic that the SCuBA bundle, the CMMC projection, the coverage figures and
# the framework spokes must all agree on, and nothing was keeping them in step.
#
# WHAT DOES NOT BELONG HERE: same-named functions that do different things.
# render_markdown() exists five times and renders five different artifacts;
# build_metadata() differs in signature and content between the SSP and the
# POA&M; build-oscal-poam.py's _prop() BUILDS a prop while the prop() below
# READS one. Merging any of those would be a behavior change wearing the costume
# of a cleanup.
# =============================================================================

import hashlib
import uuid

# =============================================================================
# OSCAL constants
# =============================================================================
# Pinned at the value the live generators currently emit. This is a published
# field: bumping it changes every consumer's view of the SSP and POA&M, so treat
# it as a reviewed artifact change, not a dependency refresh.
#
# scripts/staged/migrate_hub_to_component_def.py pins 1.2.2 instead. That
# divergence is real and predates this module; it is left explicit there rather
# than silently harmonised here, because the two would have to be reconciled
# deliberately when that migration is actually taken.
OSCAL_VERSION = "1.1.2"

FEDRAMP_NS = "https://fedramp.gov/ns/oscal"


# =============================================================================
# hashing
# =============================================================================
def sha256_file(path):
    """Streamed sha256 of a file, as hex.

    Chunked rather than read-all because the artifacts this hashes include the
    Lambda deployment zips.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sid(ns, *parts):
    """Deterministic UUIDv5 from a namespace and path segments.

    The namespace is an argument rather than a module constant on purpose: each
    generator owns its own NS, and those values are load-bearing — they decide
    the UUIDs in committed OSCAL documents. Sharing one namespace here would
    silently renumber every artifact that adopted it.
    """
    return str(uuid.uuid5(ns, ":".join(parts)))


# =============================================================================
# OSCAL prop access
# =============================================================================
def prop(obj, name):
    """Read a named prop's value off any OSCAL object, or None.

    OSCAL props are a list of {name, value} rather than a mapping, so every
    consumer needs this. Tolerates a missing or null `props` key.
    """
    for p in obj.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


# =============================================================================
# the inheritance rule
# =============================================================================
def classify(status, origination):
    """Project an SSP implemented-requirement onto the shared-responsibility
    vocabulary every downstream framework view uses.

    This is the compliance semantic four artifacts have to agree on — the SCuBA
    bundle (the executable CRM), the CMMC SRM projection, the published coverage
    figures, and the framework spokes. It lived as four verbatim copies, so a
    change to one would have silently split them apart while every gate stayed
    green: none of the invariants in reconcile.py compare these projections to
    each other.

    Status wins over origination: a control that is not applicable or still
    planned has no inheritance story to tell yet.
    """
    if status == "not-applicable":
        return "not-applicable"
    if status == "planned":
        return "planned"
    # implemented / partial / alternative
    if origination == "inherited":
        return "fully-inherited"
    if origination == "shared":
        return "partially-inherited"      # shared (system + AWS) == partially inherited
    if origination in ("customer-configured", "customer-provided"):
        return "customer-responsibility"
    return "implemented"                  # sp-system / sp-corporate (provider implements)


def load_hub(ssp_path):
    """Read the hub SSP's implemented-requirements into
    {control-id: (implementation-status, control-origination)}.

    The "hub" is the 800-53 Rev5 SSP that every framework spoke projects from —
    evidence is collected once there and re-projected, never re-collected.
    """
    import json
    from pathlib import Path

    irs = json.loads(Path(ssp_path).read_text())["system-security-plan"]["control-implementation"]["implemented-requirements"]
    return {ir["control-id"]: (prop(ir, "implementation-status"), prop(ir, "control-origination"))
            for ir in irs}
