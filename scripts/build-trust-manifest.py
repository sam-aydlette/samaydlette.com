#!/usr/bin/env python3
"""The trust center's manifest: every piece of FedRAMP certification data, where
it is, how to fetch and verify it, and its human-readable forms (CDS-TRC-PAC,
CDS-TRC-HMR, CDS-CSO-UTC).

It is generated, never hand-kept: the artifact list is the governed freshness
config (every artifact published under /.well-known/ must have an entry there,
or tests/test_freshness_config.py fails), the policies and procedures come from
this build's policy index. Each artifact's complete view (`.view.md`) is the
one every workflow that publishes it puts beside it (scripts/_signers.py, which
tests/test_human_views_published.py holds to each publisher's publish step), so
an artifact only another workflow writes (the quarterly issue index, the
review index) lists its view too; and a view the deploy should have written
beside a file it built but did not fails the build. The curated summary
(`.md`) is listed when this build wrote one. So the manifest cannot omit a
published artifact or name a view that is not published.

    python3 scripts/build-trust-manifest.py --dir . --policy-index policy-index.json \
        --output trust-manifest.json --md-output trust-manifest.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
import _offering  # noqa: E402
import _signers  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SITE = "https://samaydlette.com"
ISSUER = _signers.ISSUER
# Every workflow that signs a published artifact (scripts/_signers.py, which
# tests/test_publishers.py holds equal to the workflows' publish steps).
SIGNERS = dict(_signers.IDENTITIES)
MEDIA = {".json": "application/json", ".md": "text/markdown; charset=utf-8", ".csv": "text/csv",
         ".jsonl": "application/x-ndjson", ".gz": "application/gzip"}
# Published by something other than the deploy, so not built here; shown
# human-readably on the trust page, which renders them from the live JSON.
LIVE_RENDERED = {"ksi-signal-runtime.json": "the runtime signal, published daily by the runtime Lambda",
                 "vdr-status.json": "the nightly evidence run's status beacon"}
EXTERNAL = [{
    "name": "Independent availability status (CDS-CSO-AVR)",
    "url": "https://raw.githubusercontent.com/sam-aydlette/samaydlette.com/availability-status/availability-status.json",
    "media_type": "application/json",
    "human_readable": ["https://github.com/sam-aydlette/samaydlette.com/blob/availability-status/availability-status.md"],
    "note": "Served by GitHub, independent of the offering's AWS hosting, so it stays available when the offering "
            "is not.",
}]
ACCESS = (
    "All certification data is public: no account, key or request is needed. Fetch any artifact with an HTTPS GET "
    "(CORS is open for read-only use from a browser). Verify a signed artifact with cosign against an identity "
    "named in `signed_by` (one passing is enough): `cosign verify-blob --bundle <signature> --certificate-identity <signed_by identity> "
    "--certificate-oidc-issuer https://token.actions.githubusercontent.com <artifact>`. Every JSON artifact has a "
    "complete human-readable view (`.view.md`) that this build checked reproduces the JSON exactly, and most have a "
    "curated Markdown summary (`.md`). The policies and procedures are served as Markdown. This manifest is itself "
    "signed, and is the programmatic index of everything listed. A step-by-step guide per rule is in "
    "assessor-guide.json.")


def _signer(name):
    return " or ".join(_signers.signers(name))


def _schema(path):
    if path.suffix != ".json" or not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    s = doc.get("$schema") if isinstance(doc, dict) else None
    return s if isinstance(s, str) and s.startswith("http") else None


def artifacts(fresh, d):
    out = []
    for a in fresh["artifacts"]:
        rel = a["path"]
        name = rel.rsplit("/", 1)[1]
        local = d / name
        suffix = Path(name).suffix
        entry = {"name": name, "url": f"{SITE}/{rel}", "media_type": MEDIA.get(suffix, "application/octet-stream"),
                 "cadence": a["cadence"], "max_age_hours": a["max_age_hours"], "signed": a["signed"]}
        if a.get("signature"):
            entry["signature"] = f"{SITE}/{a['signature']}"
            who = _signer(name)
            entry["signed_by"] = who
        schema = _schema(local)
        if name == "ksi-signal.json":
            schema = f"{SITE}/.well-known/ksi-signal.schema.json"
        if schema:
            entry["schema"] = schema
        human = []
        stem = name[:-len(suffix)] if suffix in (".json", ".csv") else None
        if stem and (d / f"{stem}.md").is_file():
            human.append(f"{SITE}/.well-known/{stem}.md")
        view = _signers.view(name)
        if view:
            if local.is_file() and not (d / view).is_file():
                raise SystemExit(f"::error::trust manifest: {name} was built here without its view {view}; every "
                                 "publisher puts both (fail-closed)")
            human.append(f"{SITE}/.well-known/{view}")
        if name in LIVE_RENDERED:
            human.append(f"{SITE}/trust/ (renders {LIVE_RENDERED[name]} from the live JSON)")
        entry["human_readable"] = human
        out.append(entry)
    return out


def build(fresh, d, policy_index, now, commit=None):
    arts = artifacts(fresh, d)
    policies = [{"name": e["name"], "kind": e["kind"], "url": e["url"], "media_type": MEDIA[".md"],
                 "version": e["version"], "last_updated": e["last_updated"]} for e in policy_index["entries"]]
    return {"manifest_type": "fedramp-certification-data-manifest", "schema_version": "1",
            "fedRampId": _offering.fedramp_id(),
            "generated_at": now.isoformat(), "commit": commit,
            "trust_center": f"{SITE}/trust/", "access": ACCESS,
            "signers": {**SIGNERS, "oidc_issuer": ISSUER},
            "summary": {"artifacts": len(arts), "policies_and_procedures": len(policies),
                        "with_human_readable_form": sum(1 for x in arts if x["human_readable"])},
            "artifacts": arts, "policies_and_procedures": policies, "external": EXTERNAL}


def render_markdown(m):
    out = ["# FedRAMP certification data: manifest", "",
           f"_Everything the trust center ({m['trust_center']}) shares, generated on every deploy. Source of truth: "
           "the signed `trust-manifest.json`._", "",
           f"- **Generated:** {m['generated_at']} | **Commit:** `{m['commit'] or 'local build'}`",
           f"- **Artifacts:** {m['summary']['artifacts']} | **Policies and procedures:** "
           f"{m['summary']['policies_and_procedures']}", "",
           "## Programmatic access", "", m["access"], "", "## Signing identities", ""]
    out += [f"- {k}: `{v}`" for k, v in m["signers"].items()]
    out += ["", "## Artifacts", "", "| Artifact | Media type | Cadence | Signature | Human-readable |",
            "|---|---|---|---|---|"]
    for a in m["artifacts"]:
        sig = f"[bundle]({a['signature']}) ({a['signed_by']})" if a.get("signature") else "unsigned"
        human = ", ".join(h if not h.startswith("http") else f"[{h.rsplit('/', 1)[1]}]({h})"
                          for h in a["human_readable"]) or "—"
        out.append(f"| [{a['name']}]({a['url']}) | {a['media_type']} | {a['cadence']}, {a['max_age_hours']}h | "
                   f"{sig} | {human} |")
    out += ["", "## Policies and procedures", "", "| Name | Kind | Version | Last updated |", "|---|---|---|---|"]
    out += [f"| [{p['name']}]({p['url']}) | {p['kind']} | `{p['version']}` | {p['last_updated']} |"
            for p in m["policies_and_procedures"]]
    out += ["", "## Elsewhere", ""]
    out += [f"- [{e['name']}]({e['url']}): {e['note']}" for e in m["external"]]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".")
    ap.add_argument("--policy-index", default="policy-index.json")
    ap.add_argument("--freshness", default=str(REPO / "infrastructure" / "schemas" / "freshness-config.json"))
    ap.add_argument("--commit", default=None)
    ap.add_argument("--output", default="trust-manifest.json")
    ap.add_argument("--md-output", default="trust-manifest.md")
    a = ap.parse_args(argv)
    fresh = _freshness.load_freshness_config(a.freshness)
    m = build(fresh, Path(a.dir), json.loads(Path(a.policy_index).read_text()), datetime.now(timezone.utc),
              a.commit)
    Path(a.output).write_text(json.dumps(m, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(m) + "\n")
    print(f"trust-manifest: {m['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
