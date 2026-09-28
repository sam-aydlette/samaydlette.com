#!/usr/bin/env python3
"""Export the live boundary map from a local RAMPART (TAP) instance to a static snapshot.

LOCAL-ONLY, like tools/essay: it needs a running TAP session with the samsite plugin's
boundary page, so it never runs in CI. What it does:

  1. Feeds docs/boundary/boundary-classification.json to the TAP instance (the operator
     owns the meaning; TAP owns what exists) and confirms TAP serves those exact bytes.
  2. Opens TAP's /samsite/boundary page in headless Chromium, waits for its layout to
     settle, and reads back the scene TAP drew: every node's position, group, zone and
     flags, the grid edges, and the data flows resolved against real nodes. The layout is
     TAP's; this script only reads it.
  3. Keeps what a public map needs (names, types, public classification tags, region) and
     drops everything else. It fails closed: if any ARN, 12-digit account ID or email
     address is left in the output, nothing is written.
  4. Writes website/assets/boundary-map/boundary-map.json plus the icons TAP drew with,
     so the static viewer loads nothing from a third-party origin.

Usage (from the repo root, with the TAP session up):

    python3 tools/boundary-map/export.py
    python3 tools/boundary-map/export.py --tap-session ~/tap-sessions/rampart --tap-url http://localhost:8220

Requires Playwright with Chromium (tools/boundary-map/requirements.txt). The TAP session's
dev admin credentials are read from its .dev-credentials file and never printed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
CLASSIFICATION = REPO / "docs" / "boundary" / "boundary-classification.json"
OUT_DIR = REPO / "website" / "assets" / "boundary-map"
SCHEMA = "rampart-boundary-map/1"

# Where the samsite plugin's boundary layout reads the classification from, inside the
# TAP session's editable plugin checkout, and the URL TAP serves it at.
PLUGIN_CLASSIFICATION = Path(
    "_dev-plugins/samsite/tap_plugin/samsite/static/samsite/rampart/boundary-classification.json"
)
SERVED_CLASSIFICATION = "/static/samsite/rampart/boundary-classification.json"

# Classification tags that are public by design (docs/policies/resource-tagging-standard.md).
# Owner / CostCenter and anything else stay out: the map has no use for them.
PUBLIC_TAGS = (
    "Archetype",
    "DataClassification",
    "DataSensitivity",
    "InternetReachable",
    "MissionCriticality",
    "Environment",
)

# Anything matching these in the output aborts the export.
REDACTION_CHECKS = {
    "ARN": re.compile(r"arn:aws[a-z-]*:"),
    # Bounded by non-alphanumerics, so a digit run inside a commit hash is not a hit.
    "AWS account ID": re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}

# Icons are published on the site's own origin, where an SVG opened directly is a
# document: refuse anything that could run script there.
ICON_NAME = re.compile(r"[a-z0-9-]+\.svg")
UNSAFE_SVG = re.compile(
    rb"<script|\son[a-z]+\s*=|javascript:|<foreignObject|<iframe|<embed|<object",
    re.IGNORECASE,
)

# The signed /.well-known/ files the map shows, by TAP type (and artifact kind).
ARTIFACT_FILES = {
    "fedramp_20x_ksi__ksi_signal": "ksi-signal.json",
    "fedramp_20x_ksi__vdr_report": "vdr-report.json",
    "oscal_ssp": "oscal-ssp.json",
    "oscal_poam": "oscal-poam.json",
    "iiw": "iiw.csv",
}

# Runs in the page once TAP's layout has settled. Reads the Cytoscape instance and the
# scene the samsite boundary layout recorded; returns plain data.
READ_SCENE_JS = """() => {
    const cy = [...document.querySelectorAll('*')].map((e) => e._cyreg && e._cyreg.cy).find(Boolean);
    if (!cy) return null;
    const scene = cy.scratch('_rampart_scene');
    if (!scene) return null;
    const badgeIcon = {};
    cy.nodes('[_is_badge]').forEach((b) => { badgeIcon[b.data('_badge_host')] = b.data('icon_url'); });
    const isHelper = (n) => ['_is_badge', '_is_shadow', '_is_stack_card', '_is_stack_chip', '_is_status_badge'].some((k) => n.data(k));
    const nodes = cy.nodes().filter((n) => !isHelper(n)).map((n) => {
        const bb = n.boundingBox({includeLabels: false});
        return {
            cy_id: n.id(), name: n.data('_rampart_name') || n.data('label'), entity_type: n.data('entity_type'),
            group: n.data('_rampart_group'), flags: n.data('_rampart_flags') || [], declared: n.data('_rampart_declared') || null,
            tags: n.data('tags') || {}, dimensions: n.data('dimensions') || {}, fields: n.data('fields') || {},
            x: n.position('x'), y: n.position('y'), w: bb.w, h: bb.h, icon_url: badgeIcon[n.id()] || null,
        };
    });
    const ids = new Set(nodes.map((n) => n.cy_id));
    const edges = cy.edges().filter((e) => !e.data('_rampart_flow') && ids.has(e.source().id()) && ids.has(e.target().id()))
        .map((e) => ({source: e.source().id(), target: e.target().id(), type: e.data('_rampart_type') || ''}));
    return {groups: scene.groups, flows: scene.flows, nodes, edges};
}"""

# Scope-box padding TAP draws around a group and a zone (rampart-boundary.js).
GROUP_PAD = 22
ZONE_PAD = 40


def sh(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        cmd, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dev_admin(session: Path) -> tuple[str, str]:
    creds = (session / ".dev-credentials").read_text()
    user = re.search(r"(?m)^DJANGO_SUPERUSER_USERNAME=(\S+)", creds)
    password = re.search(r"(?m)^DJANGO_SUPERUSER_PASSWORD=(\S+)", creds)
    if not password:
        sys.exit(
            f"export: no DJANGO_SUPERUSER_PASSWORD in {session / '.dev-credentials'}"
        )
    return (user.group(1) if user else "admin"), password.group(1)


def collector_runs(session: Path) -> dict[str, str]:
    """Last successful run of each collector, as ISO timestamps. A job's name is the
    collector's name followed by its enqueue timestamp."""
    code = (
        "import json, re\n"
        "from tap_cares.models import CollectionJob\n"
        "out = {}\n"
        "for j in CollectionJob.objects.filter(status='SUCCESSFUL').order_by('finished_at'):\n"
        "    key = re.sub(r' \\d{4}-\\d{2}-\\d{2}T\\S+$', '', j.name)\n"
        "    out[key] = j.finished_at.isoformat() if j.finished_at else None\n"
        "print('RAMPART-RUNS' + json.dumps(out))\n"
    )
    raw = sh(
        "scripts/dc",
        "exec",
        "-T",
        "web",
        "uv",
        "run",
        "python",
        "manage.py",
        "shell",
        "-c",
        code,
        cwd=session,
    )
    line = next((ln for ln in raw.splitlines() if ln.startswith("RAMPART-RUNS")), None)
    return json.loads(line[len("RAMPART-RUNS") :]) if line else {}


def stale_aws_entities(session: Path) -> list[str]:
    """Entity ids of AWS resources the latest successful AWS collection did not see.

    TAP's AWS collector upserts what it finds but never retires what has disappeared,
    so a deleted resource stays on the grid. Anything not refreshed since the latest
    successful run began is gone from the account and is left off the map.
    """
    code = (
        "import json\n"
        "from tap_cares.models import CollectionJob\n"
        "from tap_grid.models import Entity\n"
        "job = CollectionJob.objects.filter(status='SUCCESSFUL', name__startswith='AWS Core Collector').order_by('-finished_at').first()\n"
        "ids = [] if job is None else [str(e) for e in Entity.objects.filter(entity_type__startswith='aws_core__', deleted_at__isnull=True,"
        " updated_at__lt=job.started_at).exclude(entity_type__in=['aws_core__aws_region', 'aws_core__aws_az']).values_list('id', flat=True)]\n"
        "print('RAMPART-STALE' + json.dumps(ids))\n"
    )
    raw = sh(
        "scripts/dc",
        "exec",
        "-T",
        "web",
        "uv",
        "run",
        "python",
        "manage.py",
        "shell",
        "-c",
        code,
        cwd=session,
    )
    line = next((ln for ln in raw.splitlines() if ln.startswith("RAMPART-STALE")), None)
    if line is None:
        sys.exit("export: could not read collection freshness from TAP")
    return json.loads(line[len("RAMPART-STALE") :])


def short_type(entity_type: str) -> str:
    return entity_type.split("__", 1)[-1]


def display_name(n: dict[str, Any]) -> tuple[str, str | None]:
    """The map label, plus the /.well-known/ file for a signed artifact."""
    name, t = n["name"] or "", n["entity_type"]
    if t in ARTIFACT_FILES:
        return ARTIFACT_FILES[t], ARTIFACT_FILES[t]
    if t == "compliance_core__compliance_artifact":
        kind = name.split(" @ ", 1)[0].strip()
        f = ARTIFACT_FILES.get(kind)
        return (f or kind), f
    return name, None


def node_link(n: dict[str, Any], artifact_file: str | None) -> str | None:
    t, fields = n["entity_type"], n["fields"]
    if artifact_file:
        return f"/.well-known/{artifact_file}"
    if t.startswith("github_core__") and str(fields.get("html_url", "")).startswith(
        "https://github.com/"
    ):
        return fields["html_url"]
    m = re.fullmatch(r"Rekor #(\d+)", n["name"] or "")
    if t == "sigstore_core__rekor_log_entry" and m:
        return f"https://search.sigstore.dev/?logIndex={m.group(1)}"
    return None


def export_id(n: dict[str, Any]) -> str:
    """Stable across exports, so snapshot diffs show real changes, not renumbering."""
    if n["declared"]:
        return f"declared:{n['declared']['key']}"
    return "n" + sha256(f"{n['entity_type']}|{n['name']}".encode())[:10]


def bbox(
    boxes: list[tuple[float, float, float, float]], pad: float
) -> dict[str, float]:
    x1 = min(b[0] for b in boxes) - pad
    y1 = min(b[1] for b in boxes) - pad
    x2 = max(b[2] for b in boxes) + pad
    y2 = max(b[3] for b in boxes) + pad
    return {
        "x": round(x1, 1),
        "y": round(y1, 1),
        "w": round(x2 - x1, 1),
        "h": round(y2 - y1, 1),
    }


def build_snapshot(
    scene: dict[str, Any], classification: dict[str, Any], meta: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    groups = {g["key"]: g for g in scene["groups"]}
    zones = {z["key"]: z for z in classification["zones"]}
    flows_by_id = {f["id"]: f for f in classification.get("flows", [])}

    id_of: dict[str, str] = {}
    icons: dict[str, str] = {}
    nodes = []
    seen_ids: dict[str, int] = {}
    for n in sorted(scene["nodes"], key=lambda n: n["cy_id"]):
        eid = export_id(n)
        # Two resources can share a type and name (e.g. two certificates for one domain).
        seen_ids[eid] = seen_ids.get(eid, 0) + 1
        if seen_ids[eid] > 1:
            eid = f"{eid}-{seen_ids[eid]}"
        id_of[n["cy_id"]] = eid
        label, artifact_file = display_name(n)
        group = groups.get(n["group"], {})
        node: dict[str, Any] = {
            "id": eid,
            "name": label,
            "type": short_type(n["entity_type"]),
            "group": n["group"],
            "zone": group.get("zone"),
            "x": round(n["x"], 1),
            "y": round(n["y"], 1),
            "w": round(n["w"], 1),
            "h": round(n["h"], 1),
        }
        if n["declared"]:
            node["kind"] = n["declared"]["kind"]
            node["why"] = n["declared"].get("why")
        else:
            node["kind"] = "collected"
            tags = {k: str(v) for k, v in n["tags"].items() if k in PUBLIC_TAGS}
            if tags:
                node["tags"] = tags
            region = n["dimensions"].get("aws_region")
            if region:
                node["region"] = region
            if n["flags"]:
                node["flags"] = n["flags"]
        link = node_link(n, artifact_file)
        if link:
            node["link"] = link
        if n["icon_url"] and n["icon_url"].startswith("/static/"):
            icon_name = Path(n["icon_url"]).name
            if not ICON_NAME.fullmatch(icon_name):
                sys.exit(f"export: refusing icon with unexpected name {icon_name!r}")
            icons[icon_name] = n["icon_url"]
            node["icon"] = f"icons/{icon_name}"
        nodes.append(node)

    by_id = {n["id"]: n for n in nodes}

    def node_box(n: dict[str, Any]) -> tuple[float, float, float, float]:
        return (
            n["x"] - n["w"] / 2,
            n["y"] - n["h"] / 2,
            n["x"] + n["w"] / 2,
            n["y"] + n["h"] / 2,
        )

    out_groups = []
    for key, g in groups.items():
        members = [n for n in nodes if n["group"] == key]
        if members:
            out_groups.append(
                {
                    "key": key,
                    "label": g["label"],
                    "zone": g["zone"],
                    "box": bbox([node_box(n) for n in members], GROUP_PAD),
                }
            )
    out_zones = []
    for zkey, z in zones.items():
        members = [n for n in nodes if n["zone"] == zkey]
        if members:
            out_zones.append(
                {
                    "key": zkey,
                    "label": z["label"],
                    "boundary": bool(z.get("boundary")),
                    "box": bbox([node_box(n) for n in members], ZONE_PAD),
                }
            )

    out_flows = []
    for f in scene["flows"]:
        spec = flows_by_id[f["id"]]
        out_flows.append(
            {
                "id": f["id"],
                "label": spec["label"],
                "in_svg": spec.get("in_svg", True),
                "protocol": spec.get("protocol"),
                "auth": spec.get("auth"),
                "encryption": spec.get("encryption"),
                "data": spec.get("data"),
                "note": spec.get("note"),
                "hops": [
                    [id_of[a], id_of[b]]
                    for a, b in f["hops"]
                    if a in id_of and b in id_of
                ],
                "unmatched_endpoints": len(f["broken"]),
            }
        )

    edges = sorted(
        {
            (id_of[e["source"]], id_of[e["target"]], e["type"])
            for e in scene["edges"]
            if e["source"] in id_of and e["target"] in id_of
        }
    )
    flags = [f for n in nodes for f in n.get("flags", [])]
    health = {
        "unclassified": sum(1 for n in nodes if n["group"] == "unclassified"),
        "untagged": flags.count("untagged"),
        "certificates_not_issued": sum(1 for f in flags if f != "untagged"),
        "declared_not_collected": sum(1 for n in nodes if n["kind"] == "not_collected"),
        "flows_with_unmatched_endpoint": sum(
            1 for f in out_flows if f["unmatched_endpoints"]
        ),
    }
    snapshot = {
        "schema": SCHEMA,
        "attribution": {
            "text": "Mapped by RAMPART on TAP — The Analogy Platform",
            "tap_url": "https://github.com/unified-systems-com/tap",
            "plugin_url": "https://github.com/unified-systems-com/tap-plugin-samsite",
            "note": "Nodes, edges and positions were collected and laid out by a TAP instance; the zones, groups and data flows come from the operator-owned classification.",
        },
        **meta,
        "health": health,
        "zones": out_zones,
        "groups": out_groups,
        "nodes": sorted(
            nodes, key=lambda n: (str(n["zone"]), str(n["group"]), n["name"])
        ),
        "edges": [
            {"source": s, "target": t, "type": short_type(ty) if "__" in ty else ty}
            for s, t, ty in edges
        ],
        "flows": out_flows,
    }
    missing = [f["id"] for f in out_flows if not f["hops"]]
    if missing:
        sys.exit(
            f"export: flow(s) {missing} resolved to no hop — fix the classification before publishing"
        )
    assert all(a in by_id and b in by_id for f in out_flows for a, b in f["hops"])
    return snapshot, icons


def check_redaction(text: str) -> None:
    for label, pattern in REDACTION_CHECKS.items():
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 40)
            sys.exit(
                f"export: refusing to write — found an {label} in the snapshot near: …{text[start : m.end() + 10]}…"
            )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--tap-session", type=Path, default=Path.home() / "tap-sessions" / "rampart"
    )
    ap.add_argument("--tap-url", default="http://localhost:8220")
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    args = ap.parse_args()
    session: Path = args.tap_session.expanduser()

    from playwright.sync_api import sync_playwright  # local-only dependency

    # 1. Feed the classification to TAP and confirm it serves these exact bytes.
    classification_bytes = CLASSIFICATION.read_bytes()
    classification = json.loads(classification_bytes)
    target = session / PLUGIN_CLASSIFICATION
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CLASSIFICATION, target)

    meta = {
        "collected_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "source": {
            "tap_commit": sh("git", "rev-parse", "HEAD", cwd=session),
            "samsite_commit": sh(
                "git", "rev-parse", "HEAD", cwd=session / "_dev-plugins" / "samsite"
            ),
            "classification_sha256": sha256(classification_bytes),
        },
        "collector_runs": collector_runs(session),
    }

    user, password = dev_admin(session)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1800, "height": 1100})
        page.goto(f"{args.tap_url}/admin/login/?next=/admin/")
        page.fill("input[name=username]", user)
        page.fill("input[name=password]", password)
        page.click("input[type=submit]")
        page.wait_for_load_state("networkidle")

        served = page.request.get(f"{args.tap_url}{SERVED_CLASSIFICATION}").body()
        if sha256(served) != meta["source"]["classification_sha256"]:
            sys.exit(
                "export: TAP is not serving the classification just written (stale static cache?)"
            )

        # 2. Let TAP lay the map out, then read back what it drew.
        page.goto(f"{args.tap_url}/samsite/boundary")
        page.wait_for_function(
            "() => [...document.querySelectorAll('*')].some((e) => e._cyreg && e._cyreg.cy && e._cyreg.cy.scratch('_rampart_scene'))",
            timeout=60_000,
        )
        page.wait_for_timeout(1500)
        scene = page.evaluate(READ_SCENE_JS)
        if not scene:
            sys.exit(
                "export: the boundary page rendered no scene (is the samsite boundary layout installed?)"
            )
        stale = set(stale_aws_entities(session))
        gone = [n for n in scene["nodes"] if n["cy_id"] in stale]
        scene["nodes"] = [n for n in scene["nodes"] if n["cy_id"] not in stale]
        scene["flows"] = [
            {**f, "hops": [h for h in f["hops"] if not set(h) & stale]}
            for f in scene["flows"]
        ]
        meta["not_seen_in_latest_collection"] = sorted(
            ({"type": short_type(n["entity_type"]), "name": n["name"]} for n in gone),
            key=lambda g: (g["type"], g["name"]),
        )

        snapshot, icons = build_snapshot(scene, classification, meta)
        icon_bytes = {
            name: page.request.get(f"{args.tap_url}{url}").body()
            for name, url in sorted(icons.items())
        }
        browser.close()

    # 3. Fail closed on anything that should never be published from here.
    text = json.dumps(snapshot, indent=1, ensure_ascii=False) + "\n"
    check_redaction(text)

    # 4. Write the snapshot and the icons it references.
    out: Path = args.out
    (out / "icons").mkdir(parents=True, exist_ok=True)
    for name, data in icon_bytes.items():
        if not data.lstrip().startswith(b"<"):
            sys.exit(f"export: icon {name} is not an SVG document")
        if UNSAFE_SVG.search(data):
            sys.exit(
                f"export: icon {name} contains script-capable content; not publishing it"
            )
        (out / "icons" / name).write_bytes(data)
    (out / "boundary-map.json").write_text(text)
    h = snapshot["health"]
    print(
        f"export: {len(snapshot['nodes'])} nodes, {len(snapshot['flows'])} flows, {len(icon_bytes)} icons → {out.relative_to(REPO)}"
    )
    print(
        f"export: health — {h['unclassified']} unclassified, {h['untagged']} untagged, "
        f"{h['certificates_not_issued']} certificate(s) not issued, {h['flows_with_unmatched_endpoint']} flow(s) unmatched"
    )


if __name__ == "__main__":
    main()
