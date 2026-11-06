"""Repository settings compared with the Secure Configuration Guide on every
deploy and every night (SCG-ENH-CMP; DEC-151 amended): workflow token
permissions and Dependabot updates from the files, rulesets and Dependabot
alerts from the API. The owner's two-factor setting and tokens are a one-time
configuration fact in DEC-151, with no recurring review."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BAD = REPO / "tests" / "fixtures" / "repo-settings" / "bad"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ms = _load("manual_settings_repo", REPO / "scripts" / "check-manual-settings.py")
chk = _load("check_secure_config_repo", REPO / "scripts" / "check-secure-config.py")
SOURCE = json.loads((REPO / "data" / "secure-configuration.json").read_text())
REPO_SETTINGS = [s for s in SOURCE["settings"] if s["check"] in chk.REPOSITORY_CHECKS]


def _compare(facts, errors=None):
    current = chk.read_repository({"facts": facts, "errors": errors or {}})
    return {r["id"]: r["result"] for r in chk.compare({"settings": REPO_SETTINGS}, current, set())}


def _committed_facts():
    return {"github-rulesets": {"rulesets": 0, "with_bypass": 0}, "github-dependabot-alerts": True,
            "github-workflow-permissions": ms.workflow_permissions(), "github-dependabot-updates": ms.dependabot_updates()}


def test_the_guide_covers_each_repository_setting():
    assert {s["check"] for s in REPO_SETTINGS} == set(chk.REPOSITORY_CHECKS)


def test_the_committed_workflows_and_dependabot_match_the_guide():
    assert set(_compare(_committed_facts()).values()) == {"matches"}


def test_known_bad_a_workflow_without_permissions_or_with_write_all_is_a_deviation():
    perms = ms.workflow_permissions(str(BAD))
    assert perms["undeclared"] == ["no-permissions.yml"] and perms["write_all"] == ["write-all.yml"]
    got = _compare({**_committed_facts(), "github-workflow-permissions": perms})
    assert got["github.workflow-token-permissions"] == "deviation"


def test_known_bad_dependabot_no_longer_watching_a_directory_is_a_deviation():
    got = _compare({**_committed_facts(), "github-dependabot-updates": ms.dependabot_updates(str(BAD))})
    assert got["github.dependabot-updates"] == "deviation"


def test_a_ruleset_with_bypass_actors_or_alerts_off_is_a_deviation():
    got = _compare({**_committed_facts(), "github-rulesets": {"rulesets": 1, "with_bypass": 1},
                    "github-dependabot-alerts": False})
    assert got["github.rulesets"] == got["github.dependabot-alerts"] == "deviation"


def test_an_unreadable_repository_setting_is_not_read_and_fails():
    facts = _committed_facts()
    del facts["github-dependabot-alerts"]
    got = _compare(facts, {"github-dependabot-alerts": "no token"})
    assert got["github.dependabot-alerts"] == "not-read"


def test_the_nightly_and_the_deploy_compare_the_repository_settings():
    wf = REPO / ".github" / "workflows"
    nightly = (wf / "evidence-nightly.yml").read_text()
    step = nightly[nightly.index("- name: Compare repository settings with the secure configuration guide"):]
    step = step[:step.index("\n    - name:", 10)] if "\n    - name:" in step[10:] else step
    assert "check-secure-config.py --account github-owner" in step and "DEPENDABOT_ALERTS_TOKEN" in step
    deploy = (wf / "deploy-with-opa.yml").read_text()
    step = deploy[deploy.index("- name: Compare live security settings with the secure configuration guide"):]
    assert "DEPENDABOT_ALERTS_TOKEN" in step[:600]


def test_the_owner_two_factor_setting_is_a_one_time_fact_with_no_recurring_review():
    s = next(x for x in SOURCE["settings"] if x["id"] == "github.owner-2fa")
    assert s["check"] == "attested" and s["attested_by"] == "DEC-151"
    dec = next(d for d in json.loads((REPO / "data" / "decisions.json").read_text())["decisions"]
               if d["id"] == "DEC-151")
    assert "no recurring review" in dec["justification"].lower()
