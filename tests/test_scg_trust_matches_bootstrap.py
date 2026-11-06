"""The guide's recommended trust for each unattended role equals the bootstrap's.

The deploy compares the live trust policy with the guide's `recommended` list
(scripts/check-secure-config.py, exact set). The live policy is what the
bootstrap Terraform applies, so the two committed sources must agree, or the
first deploy after the bootstrap apply fails its comparison.
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO / "infrastructure" / "bootstrap"
GUIDE = REPO / "data" / "secure-configuration.json"

# guide setting id -> the bootstrap file that holds that role's trust policy
ROLE_FILES = {
    "ci-roles.incident-trust": "incident-reports.tf",
    "ci-roles.maintenance-trust": "package-maintenance.tf",
}

_VAR = re.compile(r'variable\s+"([a-z_]+)"\s*\{[^}]*?default\s*=\s*"([^"]*)"', re.S)
_SUB = re.compile(
    r'variable\s*=\s*"token\.actions\.githubusercontent\.com:sub"\s*values\s*=\s*\[(.*?)\]', re.S)


def _defaults():
    out = {}
    for tf in BOOTSTRAP.glob("*.tf"):
        out.update(dict(_VAR.findall(tf.read_text())))
    return out


def trusted_subjects(tf_text, defaults):
    m = _SUB.search(tf_text)
    assert m, "no OIDC subject condition"
    subs = re.findall(r'"([^"]*)"', m.group(1))
    return sorted(re.sub(r"\$\{var\.([a-z_]+)\}", lambda v: defaults[v.group(1)], s) for s in subs)


def mismatches(guide, tf_texts, defaults):
    settings = {s["id"]: s for s in guide["settings"]}
    bad = {}
    for sid, tf in ROLE_FILES.items():
        want = sorted(settings[sid]["recommended"])
        have = trusted_subjects(tf_texts[tf], defaults)
        if want != have:
            bad[sid] = {"guide": want, "bootstrap": have}
    return bad


def test_the_guide_recommends_exactly_the_trust_the_bootstrap_applies():
    texts = {f: (BOOTSTRAP / f).read_text() for f in ROLE_FILES.values()}
    assert mismatches(json.loads(GUIDE.read_text()), texts, _defaults()) == {}


def test_known_bad_a_guide_missing_a_bootstrap_subject_is_caught():
    guide = json.loads(GUIDE.read_text())
    for s in guide["settings"]:
        if s["id"] == "ci-roles.incident-trust":
            s["recommended"] = [r for r in s["recommended"] if not r.endswith(":environment:prod")]
    texts = {f: (BOOTSTRAP / f).read_text() for f in ROLE_FILES.values()}
    assert list(mismatches(guide, texts, _defaults())) == ["ci-roles.incident-trust"]
