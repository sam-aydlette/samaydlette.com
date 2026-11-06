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
# The insert is __file__-relative, so it resolves from any cwd.
#
# WHAT BELONGS HERE: only definitions that were already duplicated VERBATIM, and
# only where divergence between the copies would be a bug rather than a choice.
# The copies of classify() were the case that mattered — it is a compliance
# semantic the published coverage figures and the per-control views must agree
# on, and nothing was keeping them in step.
#
# WHAT DOES NOT BELONG HERE: same-named functions that do different things.
# render_markdown() exists several times and renders a different artifact each
# time. Merging those would be a behavior change wearing the costume of a
# cleanup.
# =============================================================================

import hashlib
import uuid

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
    """Project a control implemented-requirement onto the shared-responsibility
    vocabulary every downstream framework view uses.

    This is the compliance semantic the downstream views have to agree on —
    the trust center's Rev5 Moderate figures among them. It lived as four
    verbatim copies, so a
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


def load_hub(irs):
    """Map the control projection's implemented-requirements (scripts/_controls.py)
    to {control-id: (implementation-status, control-origination)}.

    The "hub" is the 800-53 Rev5 control projection that every framework spoke
    projects from — evidence is collected once there and re-projected, never
    re-collected.
    """
    return {ir["control-id"]: (prop(ir, "implementation-status"), prop(ir, "control-origination"))
            for ir in irs}
