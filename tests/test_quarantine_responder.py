"""The quarantine responder (KSI-IAM-SUS) and its nightly drill, against a stubbed IAM client.

scripts/_quarantine.py attaches AWS's deny-all policy to the principal a
reportable audit-log finding names, reads it back and pages the operator; it
refuses the CI/CD trust root before any call. The audit-log review drills it
every night on a stand-in role. The stub records every call, so these tests
show it attaches and detaches only the deny-all policy and never touches a
trust-root role.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _quarantine as q  # noqa: E402
import _scheduled_review as sr  # noqa: E402

NOW = datetime(2026, 11, 6, 7, 0, tzinfo=timezone.utc)
NO_SLEEP = {"sleep": lambda s: None}


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


alr = _load("audit_log_review_q", "audit-log-review.py")


class StubIam:
    """An in-memory IAM: attachments per principal, every call recorded."""

    def __init__(self, sticky=False, fail_page=False):
        self.attached_to, self.calls, self.pages = {}, [], []
        self.sticky, self.fail_page = sticky, fail_page

    def attach(self, kind, name):
        self.calls.append(("attach", kind, name))
        self.attached_to.setdefault((kind, name), set()).add(q.QUARANTINE_POLICY_ARN)

    def detach(self, kind, name):
        self.calls.append(("detach", kind, name))
        if not self.sticky:
            self.attached_to.get((kind, name), set()).discard(q.QUARANTINE_POLICY_ARN)

    def attached(self, kind, name):
        self.calls.append(("list", kind, name))
        return sorted(self.attached_to.get((kind, name), set()))

    def page(self, subject, message):
        self.calls.append(("page",))
        if self.fail_page:
            raise q.IamError("aws sns publish: AuthorizationError")
        self.pages.append((subject, message))


def _event(kind="AssumedRole", name="some-app-role", event="CreateAccessKey"):
    ui = ({"type": "IAMUser", "userName": name} if kind == "IAMUser" else
          {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"type": "Role", "userName": name}}}
          if kind == "AssumedRole" else {"type": kind})
    return {"EventName": event, "EventSource": "iam.amazonaws.com", "EventTime": "2026-11-06T03:00:00Z",
            "region": "us-east-2", "userIdentity": ui}


# --- the responder ---------------------------------------------------------------------------

def test_a_role_named_by_a_reportable_event_is_quarantined_read_back_and_paged():
    iam = StubIam()
    rec = q.respond(_event(), iam, NOW, **NO_SLEEP)
    assert rec["action"] == "quarantined" and rec["handled"] and rec["paged"]
    assert iam.attached_to[("role", "some-app-role")] == {q.QUARANTINE_POLICY_ARN}
    assert iam.pages and "some-app-role" in iam.pages[0][0]


def test_a_user_is_quarantined_with_the_user_calls():
    iam = StubIam()
    assert q.respond(_event("IAMUser", "mallory-user"), iam, NOW, **NO_SLEEP)["action"] == "quarantined"
    assert ("attach", "user", "mallory-user") in iam.calls


def test_only_the_deny_all_policy_is_ever_attached():
    assert q.QUARANTINE_POLICY_ARN == "arn:aws:iam::aws:policy/AWSDenyAll"
    iam = StubIam()
    q.respond(_event(), iam, NOW, **NO_SLEEP)
    assert {p for ps in iam.attached_to.values() for p in ps} == {q.QUARANTINE_POLICY_ARN}


def test_every_trust_root_role_is_refused_with_no_iam_call():
    for role in sorted(q.TRUST_ROOT):
        rec = q.Recording(StubIam())
        assert q.quarantine(rec, "role", role, **NO_SLEEP)[0] == "refused"
        assert rec.calls == 0


def test_the_trust_root_matches_the_audit_log_reviews_ci_roles_and_the_opa_config():
    assert q.TRUST_ROOT == set(alr.CI_ROLES)
    cfg = json.loads((REPO / "infrastructure" / "policy" / "config" / "data.json").read_text())
    assert set(cfg["gate"]["iam"]["trust_root_roles"]) == q.TRUST_ROOT
    assert cfg["gate"]["iam"]["attachable_policies"] == [q.QUARANTINE_POLICY_ARN]


def test_a_refused_quarantine_still_pages():
    iam = StubIam()
    rec = q.respond(_event(name="github-actions-deploy-oidc"), iam, NOW, **NO_SLEEP)
    assert rec["action"] == "refused" and rec["paged"] and rec["handled"]
    assert not any(c[0] == "attach" for c in iam.calls)


def test_root_and_service_principals_are_not_iam_principals_but_page():
    iam = StubIam()
    rec = q.respond(_event("Root"), iam, NOW, **NO_SLEEP)
    assert rec["action"] == "not-applicable" and rec["paged"]
    assert q.target_of({"userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {
        "type": "Role", "userName": "x", "arn": "arn:aws:iam::1:role/aws-service-role/x"}}}})[0] is None


def test_known_bad_a_name_iam_would_not_issue_never_reaches_the_cli():
    iam = StubIam()
    rec = q.respond(_event(name="role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"), iam, NOW, **NO_SLEEP)
    assert rec["action"] == "not-applicable" and rec["paged"]
    assert not any(c[0] in ("attach", "detach", "list") for c in iam.calls)


def test_known_bad_a_quarantine_that_does_not_read_back_fails():
    class NoReadBack(StubIam):
        def attached(self, kind, name):
            return []
    rec = q.respond(_event(), NoReadBack(), NOW, **NO_SLEEP)
    assert rec["action"] == "failed" and not rec["handled"]


def test_known_bad_without_credentials_a_reportable_event_is_unanswered():
    rec = q.respond(_event(), None, NOW)
    assert rec["action"] == "failed" and not rec["handled"] and not rec["paged"]


def test_a_failed_page_leaves_the_event_unhandled():
    rec = q.respond(_event(), StubIam(fail_page=True), NOW, **NO_SLEEP)
    assert rec["action"] == "quarantined" and not rec["paged"] and not rec["handled"]


def test_the_cli_uses_the_responders_profile_never_the_nightly_environment(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "nightly")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "nightly")
    env = q._env(q.PROFILE)
    assert env["AWS_PROFILE"] == "quarantine-responder"
    assert "AWS_ACCESS_KEY_ID" not in env and "AWS_SESSION_TOKEN" not in env


# --- the drill -------------------------------------------------------------------------------

def test_the_drill_quarantines_and_releases_the_stand_in_and_refuses_the_forgery():
    iam = StubIam()
    d = q.drill(iam, alr.judge, alr.DRILL_EVENT, alr.DRILL_FORGED, NOW, **NO_SLEEP)
    assert d["result"] == "pass", d["checks"]
    assert [c["id"] for c in d["checks"]] == ["detected", "stand-in", "quarantined", "released", "trust-root-refused"]
    touched = {(c[1], c[2]) for c in iam.calls if c[0] in ("attach", "detach")}
    assert touched == {("role", q.TARGET_ROLE)}
    assert iam.attached_to[("role", q.TARGET_ROLE)] == set()
    assert not any(c[0] == "page" for c in iam.calls)


def test_known_bad_a_stuck_quarantine_fails_the_drill():
    d = q.drill(StubIam(sticky=True), alr.judge, alr.DRILL_EVENT, alr.DRILL_FORGED, NOW, **NO_SLEEP)
    assert d["result"] == "fail" and {c["id"]: c["result"] for c in d["checks"]}["released"] == "fail"


def test_known_bad_rules_that_miss_the_planted_event_fail_the_drill(monkeypatch):
    monkeypatch.setattr(alr, "REPORTABLE", {})
    iam = StubIam()
    d = q.drill(iam, alr.judge, alr.DRILL_EVENT, alr.DRILL_FORGED, NOW, **NO_SLEEP)
    assert {c["id"]: c["result"] for c in d["checks"]}["detected"] == "fail"
    assert not any(c[0] == "attach" for c in iam.calls)


def test_known_bad_a_responder_that_would_quarantine_the_trust_root_fails_the_drill(monkeypatch):
    """The planted bad input: if the refusal were removed, the forged request reaches IAM and the drill fails."""
    monkeypatch.setattr(q, "TRUST_ROOT", frozenset())
    d = q.drill(StubIam(), alr.judge, alr.DRILL_EVENT, alr.DRILL_FORGED, NOW, **NO_SLEEP)
    assert {c["id"]: c["result"] for c in d["checks"]}["trust-root-refused"] == "fail"


def test_known_bad_a_planted_event_naming_another_principal_is_never_quarantined():
    iam = StubIam()
    d = q.drill(iam, alr.judge, _event(name="some-real-role"), alr.DRILL_FORGED, NOW, **NO_SLEEP)
    assert {c["id"]: c["result"] for c in d["checks"]}["stand-in"] == "fail"
    assert not any(c[0] == "attach" for c in iam.calls)


def test_without_credentials_the_drill_fails():
    d = q.drill(None, alr.judge, alr.DRILL_EVENT, alr.DRILL_FORGED, NOW)
    assert d["result"] == "fail"


# --- in the audit-log review and its method --------------------------------------------------

def _review(events=(), iam=None):
    return alr.build(list(events), {"commits": [], "settings": []}, NOW, NOW, "FR-TEST", (), iam,
                     sleep=lambda s: None)


def test_the_review_publishes_the_drill_and_the_responses_without_names():
    doc = _review([_event(name="somebody-elses-role")], StubIam())
    qs = doc["quarantine"]
    assert qs["drill"]["result"] == "pass" and qs["responsesResult"] == "pass"
    assert qs["responses"][0]["action"] == "quarantined" and qs["responses"][0]["principalKind"] == "role"
    text = json.dumps(doc)
    for name in ("somebody-elses-role", q.TARGET_ROLE, "github-actions-deploy-oidc"):
        assert name not in text
    assert "(simulated)" in qs["drill"]["intruder"] and "Moon" in qs["drill"]["planted"]["from"]


def test_known_bad_a_failed_drill_fails_the_nightly_and_the_method():
    doc = _review(iam=None)
    assert doc["result"] == "pass" and doc["quarantine"]["drill"]["result"] == "fail"
    assert alr.enforce(doc) == 1
    ok, why = sr.method_status("quarantine-drill", doc, NOW)
    assert not ok and "drill" in why
    assert sr.method_status("audit-log-review", doc, NOW) == (True, None)


def test_known_bad_an_unanswered_real_event_fails_the_method():
    class NoReadBack(StubIam):
        def attached(self, kind, name):
            return [] if name != q.TARGET_ROLE else super().attached(kind, name)
    doc = _review([_event(name="some-app-role")], NoReadBack())
    assert doc["quarantine"]["responsesResult"] == "fail"
    assert sr.method_status("quarantine-drill", doc, NOW)[0] is False


def test_a_passing_drill_counts():
    doc = _review(iam=StubIam())
    assert sr.method_status("quarantine-drill", doc, NOW) == (True, None)
    assert alr.enforce(doc) == 0


def test_the_responders_own_writes_are_expected():
    ev = {"EventName": "AttachRolePolicy", "EventSource": "iam.amazonaws.com", "userIdentity": {
        "type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": q.RESPONDER_ROLE}}}}
    assert alr.principal(ev) == ("ci-role:quarantine-responder", True)
