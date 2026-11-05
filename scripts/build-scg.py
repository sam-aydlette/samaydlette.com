#!/usr/bin/env python3
"""The Secure Configuration Guide and the cryptographic module list.

Publishes /.well-known/secure-configuration-guide.json and .md from one source,
data/secure-configuration.json (SCG-CSO-RSC, SCG-CSO-PUB, SCG-CSO-AUP,
SCG-ENH-MRG, SCG-ENH-API, SCG-ENH-VRH), joined with the per-service
cryptographic module list in data/crypto-modules.json and the deploy's
inventory (CMU-CSO-CMD, CMU-CSO-UVM, CMU-CSO-CAT).

Fails closed, before anything is written, when:
  * the recommended defaults changed without a new version and a changelog
    entry carrying their new digest (SCG-ENH-VRH);
  * a setting names an unknown account, or cites a decision that is not in force;
  * the inventory holds a component type that is neither mapped to a
    cryptographic module nor declared as using no cryptography (CMU-CSO-CMD);
  * the guide names a retired mechanism (the old shared app credential, the
    deployer access key, Duo-enforced root MFA).

    build-scg.py --ksi-signal ksi-signal.json --output secure-configuration-guide.json \
        --md-output secure-configuration-guide.md
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "data" / "secure-configuration.json"
CRYPTO = REPO / "data" / "crypto-modules.json"
SITE = "https://samaydlette.com/.well-known/"
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
LEVELS = ("top-level", "privileged")
# Mechanisms this system no longer has. A guide that still describes one is
# wrong about the system, so the build stops (the 2026-11-05 assessment found
# the prose guide describing all three).
RETIRED = (
    (re.compile(r"basic[ -]auth", re.I), "the retired Silk Reeling shared (Basic Auth) credential"),
    (re.compile(r"deployer (IAM )?user|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY", re.I), "the retired deployer access key"),
    (re.compile(r"(enforced|MFA) via Duo", re.I), "Duo-enforced root MFA (root uses virtual TOTP, DEC-150)"),
)


def _fail(msg):
    raise SystemExit(f"::error::secure configuration guide: {msg} (fail-closed)")


def defaults_digest(src):
    """sha256 over what a release fixes: each setting's account, recommended
    value, check and accepted deviation. Wording changes don't move it."""
    body = sorted(({"id": s["id"], "account": s["account"], "recommended": s["recommended"],
                    "check": s["check"], "accepted_deviation": s.get("accepted_deviation")}
                   for s in src["settings"]), key=lambda s: s["id"])
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _semver(v, where):
    m = SEMVER.match(v or "")
    if not m:
        _fail(f"{where}: version {v!r} is not MAJOR.MINOR.PATCH")
    return tuple(int(x) for x in m.groups())


def validate_source(src, in_force_ids):
    if not isinstance(src, dict) or src.get("schema") != "secure-configuration/1":
        _fail("the source is not a secure-configuration/1 document")
    for k in ("title", "version", "obtain_and_use", "accounts", "settings", "changelog"):
        if not src.get(k):
            _fail(f"the source has no {k}")
    accounts = {}
    for a in src["accounts"]:
        for k in ("id", "level", "name", "how_named", "access", "configure", "operate", "decommission"):
            if not isinstance(a.get(k), str) or not a[k].strip():
                _fail(f"account {a.get('id')!r} has no {k}")
        if a["level"] not in LEVELS:
            _fail(f"account {a['id']}: level must be one of {LEVELS}")
        accounts[a["id"]] = a
    if not any(a["level"] == "top-level" for a in accounts.values()):
        _fail("no top-level administrative account is described")
    seen, checks = set(), set()
    for s in src["settings"]:
        sid = s.get("id")
        for k in ("id", "account", "operable_by", "setting", "implication", "read", "change", "check"):
            if not isinstance(s.get(k), str) or not s[k].strip():
                _fail(f"setting {sid!r} has no {k}")
        if "recommended" not in s:
            _fail(f"setting {sid} has no recommended value")
        if sid in seen:
            _fail(f"setting {sid} appears twice")
        seen.add(sid)
        if s["account"] not in accounts:
            _fail(f"setting {sid} names unknown account {s['account']!r}")
        if s["check"] == "attested":
            if s.get("attested_by") not in in_force_ids:
                _fail(f"setting {sid} is attested but cites no in-force decision")
        elif s["check"] in checks:
            _fail(f"check {s['check']} is used by two settings")
        checks.add(s["check"])
        dev = s.get("accepted_deviation")
        if dev is not None and dev not in in_force_ids:
            _fail(f"setting {sid} cites {dev!r} as its accepted deviation, which is not an in-force decision")
    # SCG-ENH-VRH: versioned, with a release history of the defaults.
    prev = None
    for entry in src["changelog"]:
        v = _semver(entry.get("version"), "changelog")
        if prev is not None and v <= prev:
            _fail("changelog versions must increase")
        if not entry.get("date") or not entry.get("changes"):
            _fail(f"changelog {entry.get('version')} has no date or changes")
        prev = v
    latest = src["changelog"][-1]
    if latest["version"] != src["version"]:
        _fail(f"version {src['version']} has no changelog entry (latest is {latest['version']})")
    digest = defaults_digest(src)
    if latest.get("defaults_sha256") != digest:
        _fail(f"the recommended defaults changed since version {src['version']} was released: bump the version "
              f"and add a changelog entry with defaults_sha256 {digest}")
    return src


def module_list(crypto, signal):
    """Per-service module list joined with the inventory's component types.
    Fails on a type that is neither mapped nor declared cryptography-free."""
    modules = crypto["modules"]
    by_type = {}
    for svc in crypto["services"]:
        if svc["module"] not in modules:
            _fail(f"{svc['service']}: unknown module {svc['module']!r}")
        for t in svc["types"]:
            if t in by_type:
                _fail(f"component type {t} is mapped twice")
            by_type[t] = svc
    none = set(crypto["no_cryptography"]["types"])
    if none & set(by_type):
        _fail(f"types both mapped and declared cryptography-free: {sorted(none & set(by_type))}")
    counts = {}
    for c in signal.get("components", []):
        counts[c.get("type")] = counts.get(c.get("type"), 0) + 1
    unmapped = sorted(t for t in counts if t not in by_type and t not in none)
    if unmapped:
        _fail(f"the inventory has component type(s) with no cryptographic module mapping: {', '.join(map(str, unmapped))}. "
              "Map each in data/crypto-modules.json (or declare it cryptography-free)")
    out = []
    for svc in crypto["services"]:
        m = modules[svc["module"]]
        out.append({"service": svc["service"], "protects": svc["protects"], "configuration": svc["configuration"],
                    "protects_customer_data": svc["customer_data"],
                    "agency_tenant_default": svc.get("tenant_default"),
                    "components": sum(counts.get(t, 0) for t in svc["types"]), "component_types": svc["types"],
                    "module": m["name"], "cmvp_certificate": m["cmvp_certificate"], "standard": m["standard"],
                    "level": m["level"], "validation_status": m["status"], "source": m["source"],
                    "validated": m["cmvp_certificate"] is not None})
    return out


def build(src, crypto, signal, now):
    doc = {
        "schema": "secure-configuration-guide/1",
        "title": src["title"],
        "version": src["version"],
        "emitted_at": now.isoformat(timespec="seconds"),
        "ksi_signal_id": signal.get("signal_id"),
        "source": "Generated by scripts/build-scg.py from data/secure-configuration.json and "
                  "data/crypto-modules.json, joined with this deploy's inventory.",
        "human_readable": SITE + "secure-configuration-guide.md",
        "machine_readable": SITE + "secure-configuration-guide.json",
        "comparison": SITE + "security-settings.json",
        "obtain_and_use": src["obtain_and_use"],
        "accounts": src["accounts"],
        "settings": src["settings"],
        "release_history": src["changelog"],
        "cryptographic_modules": {
            "checked_on": crypto["checked_on"],
            "services": module_list(crypto, signal),
            "no_cryptography": crypto["no_cryptography"],
        },
    }
    text = json.dumps(doc) + "\n" + render_markdown(doc)
    for pat, what in RETIRED:
        if pat.search(text):
            _fail(f"the guide names {what}")
    return doc


def _value(v):
    if isinstance(v, dict):
        return "; ".join(f"{k} {_value(x)}" for k, x in v.items())
    if isinstance(v, list):
        return ", ".join(map(str, v))
    if isinstance(v, bool):
        return "yes" if v else "no"
    if v is None:
        return "—"
    return str(v)


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(doc):
    out = [f"# {doc['title']}", "",
           f"- **Version:** {doc['version']} | **Generated:** {doc['emitted_at']}",
           f"- **Machine-readable:** {doc['machine_readable']}",
           f"- **Live comparison:** {doc['comparison']}",
           f"- **Source:** {doc['source']}", "", "## How to obtain and use this guide", ""]
    out += [f"- {line}" for line in doc["obtain_and_use"]]
    out += ["", "## Accounts", ""]
    for a in doc["accounts"]:
        out += [f"### {a['name']} (`{a['id']}`, {a['level']})", "",
                f"- **How it is named:** {a['how_named']}", f"- **Secure access:** {a['access']}",
                f"- **Configure:** {a['configure']}", f"- **Operate:** {a['operate']}",
                f"- **Decommission:** {a['decommission']}", ""]
    out += ["## Security settings", "",
            "| Setting | Account | Operable by | Recommended | Implication | Read | Change | Deviation |",
            "|---|---|---|---|---|---|---|---|"]
    for s in doc["settings"]:
        dev = s.get("accepted_deviation") or (f"attested ({s['attested_by']})" if s.get("attested_by") else "—")
        out.append(f"| `{s['id']}`: {_cell(s['setting'])} | {s['account']} | {_cell(s['operable_by'])} | "
                   f"{_cell(_value(s['recommended']))} | {_cell(s['implication'])} | {_cell(s['read'])} | "
                   f"{_cell(s['change'])} | {dev} |")
    cm = doc["cryptographic_modules"]
    out += ["", f"## Cryptographic modules per service (checked {cm['checked_on']})", "",
            "| Service | Components | Module | CMVP certificate | Status | Protects customer data | "
            "Agency-tenant default | Configuration |", "|---|---|---|---|---|---|---|---|"]
    for m in cm["services"]:
        cert = f"[#{m['cmvp_certificate']}]({m['source']})" if m["cmvp_certificate"] else "none"
        out.append(f"| {_cell(m['service'])} | {m['components']} | {_cell(m['module'])} | {cert} | "
                   f"{_cell(m['validation_status'])} | {_value(m['protects_customer_data'])} | "
                   f"{_cell(_value(m['agency_tenant_default']))} | {_cell(m['configuration'])} |")
    out += ["", f"Cryptography-free component types: {', '.join(cm['no_cryptography']['types'])}. "
            f"{cm['no_cryptography']['why']}", "", "## Release history", ""]
    for r in reversed(doc["release_history"]):
        out.append(f"### {r['version']} ({r['date']})")
        out += [f"- {c}" for c in r["changes"]]
        out.append(f"- Defaults digest: `{r['defaults_sha256']}`")
        out.append("")
    out += ["---", "_Source of truth: the signed `secure-configuration-guide.json`._"]
    return "\n".join(out)


def load(source=SOURCE, decisions_path=None):
    try:
        src = json.loads(Path(source).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {source}: {exc}")
    reg = _decisions.load(decisions_path)
    return validate_source(src, {r["id"] for r in _decisions.in_force(reg)})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", default=str(SOURCE))
    ap.add_argument("--crypto", default=str(CRYPTO))
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="secure-configuration-guide.json")
    ap.add_argument("--md-output", default="secure-configuration-guide.md")
    ap.add_argument("--print-digest", action="store_true", help="print the defaults digest and exit")
    a = ap.parse_args(argv)
    if a.print_digest:
        print(defaults_digest(json.loads(Path(a.source).read_text())))
        return 0
    src = load(a.source, a.decisions)
    try:
        crypto = json.loads(Path(a.crypto).read_text())
        signal = json.loads(Path(a.ksi_signal).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read an input: {exc}")
    doc = build(src, crypto, signal, datetime.now(timezone.utc))
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    Path(a.md_output).write_text(render_markdown(doc) + "\n")
    v = sum(1 for m in doc["cryptographic_modules"]["services"] if m["validated"])
    print(f"secure-configuration-guide {doc['version']}: {len(doc['settings'])} settings, "
          f"{len(doc['cryptographic_modules']['services'])} services ({v} on a CMVP-validated module)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
