"""The governance registry: roles, domains and KSI-family ownership.

Owners are role labels so ownership survives a change of person; the holder
section is the one place a person is named. Every KSI family in the catalog
has exactly one owning domain, and every domain has exactly one owning role.
"""
import json
from pathlib import Path

import jsonschema

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "docs" / "governance" / "domains.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "governance-domains.schema.json"
CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"

# Tool and vendor names a domain must not be named after: a domain has to
# survive swapping the tool that serves it today.
TOOL_NAMES = ("aws", "cloudfront", "route53", "cognito", "github", "sigstore", "cosign",
              "terraform", "opa", "checkov", "grype", "syft", "zap", "pa11y", "anthropic")


def _load(path):
    return json.loads(path.read_text())


def test_registry_validates_against_schema():
    jsonschema.validate(_load(REGISTRY), _load(SCHEMA))


def test_schema_rejects_a_person_as_owner():
    reg = _load(REGISTRY)
    reg["domains"][0]["owner_role"] = "Jane Doe"
    try:
        jsonschema.validate(reg, _load(SCHEMA))
    except jsonschema.ValidationError:
        return
    raise AssertionError("a personal name was accepted as an owner role")


def test_ids_are_unique():
    reg = _load(REGISTRY)
    roles = [r["id"] for r in reg["roles"]]
    domains = [d["id"] for d in reg["domains"]]
    assert len(roles) == len(set(roles))
    assert len(domains) == len(set(domains))


def test_every_domain_is_owned_by_a_declared_role():
    reg = _load(REGISTRY)
    roles = {r["id"] for r in reg["roles"]}
    for d in reg["domains"]:
        assert d["owner_role"] in roles, d["id"]


def test_every_role_owns_something():
    reg = _load(REGISTRY)
    owning = {d["owner_role"] for d in reg["domains"]}
    assert {r["id"] for r in reg["roles"]} == owning


def test_every_catalog_family_maps_to_exactly_one_declared_domain():
    reg = _load(REGISTRY)
    families = set(_load(CATALOG)["KSI"])
    assert set(reg["ksi_families"]) == families
    domains = {d["id"] for d in reg["domains"]}
    for family, domain in reg["ksi_families"].items():
        assert domain in domains, family


def test_domains_survive_a_tool_swap():
    for d in _load(REGISTRY)["domains"]:
        words = f"{d['id']} {d['name']}".lower().replace("-", " ").split()
        assert not set(words) & set(TOOL_NAMES), d["id"]


def test_no_contact_details_anywhere():
    assert "@" not in REGISTRY.read_text()


def test_holder_statement_says_one_person_holds_every_role():
    statement = _load(REGISTRY)["holder"]["statement"].lower()
    assert "one person" in statement and "every role" in statement
