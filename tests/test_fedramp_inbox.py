"""The SIMULATED FedRAMP Security Inbox (AFC-CSO-INB, TFG, RCV, CRA, EMR, IMA, ACK).

By the operator's decision the inbox is simulated for this proof of concept:
nothing real is received or sent. scripts/_fsi.py is the logic a real inbox
would run, and scripts/build-fsi-simulation.py runs it on every deploy over the
synthetic messages in data/fsi-simulation/messages.json, failing the deploy if
any outcome differs. These tests pin the logic and that deploy wiring:

  TFG  mail from @fedramp.gov / @gsa.gov is FedRAMP, whatever its spam verdict
       or authentication result; look-alike domains are not
  ACK  FedRAMP mail is acknowledged once, header-injection safe, never to an
       auto-reply and never to mail failing SPF/DKIM/DMARC
  EMR  every FedRAMP message pages, Emergency included
  CRA  Emergency / Emergency Test mail gets a deadline in the register
  IMA  Important mail cannot be triaged without its stated timeframe
"""

import copy
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _fedramp_schema  # noqa: E402
import _fsi  # noqa: E402


def _load(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

WORKFLOW = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
OFFERING = REPO / "data" / "cds" / "offering.json"
MESSAGES = REPO / "data" / "fsi-simulation" / "messages.json"
BAD = REPO / "tests" / "fixtures" / "fsi" / "simulation-wrong-expectation.json"
SIM = REPO / "scripts" / "build-fsi-simulation.py"
NOW = datetime(2026, 11, 9, 15, 0, tzinfo=timezone.utc)  # Monday 10:00 a.m. EST
PASS = {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
FAIL = {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"}
SIMULATED_RULES = ["AFC-CSO-INB", "AFC-CSO-TFG", "AFC-CSO-RCV", "AFC-CSO-CRA", "AFC-CSO-EMR",
                   "AFC-CSO-IMA", "AFC-CSO-ACK"]


def msg(frm="FedRAMP <fedramp_security@gsa.gov>", subject="Emergency: action required", envelope=None,
        headers=None, auth=PASS, message_id="m1", received_at="2026-11-09T15:00:00Z"):
    return {"from": frm, "envelope": envelope if envelope is not None else _fsi.parse_address(frm) or "",
            "subject": subject, "headers": headers or {}, "auth": auth, "message_id": message_id,
            "received_at": received_at}


# --- classification (AFC-CSO-TFG) ---------------------------------------------------

@pytest.mark.parametrize("frm", ["FedRAMP PMO <fedramp_security@gsa.gov>", "someone@FedRAMP.gov",
                                 "\"F20B Team\" <info@fedramp.gov>"])
def test_fedramp_senders_are_fedramp_even_when_unauthenticated(frm):
    c = _fsi.classify(msg(frm=frm, auth=FAIL))
    assert c["kind"] == "fedramp" and c["designation"] == "EMERGENCY"
    assert c["authenticated"] is False and c["loop"] == "unauthenticated"


@pytest.mark.parametrize("frm,envelope", [
    ("x <a@fedramp.gov.example.com>", "a@fedramp.gov.example.com"),
    ("x <a@notfedramp.gov>", "a@notfedramp.gov"),
    ("x <a@mail.gsa.gov>", "a@mail.gsa.gov"),
    ("\"fedramp_security@gsa.gov\" <attacker@example.com>", "attacker@example.com"),
    ("fedramp_security@gsa.gov <attacker@example.com>", "attacker@example.com"),
])
def test_look_alike_domains_and_display_name_spoofs_are_not_fedramp(frm, envelope):
    assert _fsi.classify(msg(frm=frm, envelope=envelope))["kind"] == "other"


def test_a_fedramp_envelope_sender_counts_even_if_the_from_header_is_unparseable():
    c = _fsi.classify(msg(frm="garbage <<>>", envelope="bounces@gsa.gov"))
    assert c["kind"] == "fedramp" and c["sender_domain"] == "gsa.gov"


@pytest.mark.parametrize("subject,want", [
    ("Emergency Test: confirm your FSI", "EMERGENCY_TEST"),
    ("[EMERGENCY-TEST] reply by Tuesday", "EMERGENCY_TEST"),
    ("EMERGENCY: CVE-2026-0001 in your boundary", "EMERGENCY"),
    ("Re: [Emergency] follow-up", "EMERGENCY"),
    ("Important: update your Marketplace listing", "IMPORTANT"),
    ("Monthly community update", "GENERAL"),
    ("Emergencyish newsletter", "GENERAL"),
])
def test_designators_follow_afc_frp_cds(subject, want):
    assert _fsi.designation_of(subject) == want


def test_an_emergency_from_an_address_other_than_fedramp_security_is_flagged_not_demoted():
    c = _fsi.classify(msg(frm="Someone <someone@gsa.gov>"))
    assert c["designation"] == "EMERGENCY" and c["emergency_sender_ok"] is False


# --- deadlines and register (AFC-CSO-CRA, AFC-CSO-IMA, AFC-FRP-ERT) ----------------------

@pytest.mark.parametrize("received,due", [
    ("2026-11-09T15:00:00Z", "2026-11-10T20:00:00Z"),  # Mon 10:00 EST -> Tue 15:00 EST
    ("2026-11-13T21:30:00Z", "2026-11-16T20:00:00Z"),  # Fri 16:30 EST -> Mon 15:00 EST
    ("2026-11-14T15:00:00Z", "2026-11-17T20:00:00Z"),  # Sat -> Tue (Mon is day 1)
    ("2026-10-30T14:00:00Z", "2026-11-02T20:00:00Z"),  # Fri 10:00 EDT -> Mon 15:00 EST (DST ends Sun)
    ("2026-11-10T04:30:00Z", "2026-11-10T20:00:00Z"),  # Mon 23:30 EST counts Monday as day 1
])
def test_class_c_default_deadline_is_3pm_eastern_on_the_second_business_day(received, due):
    assert _fsi.iso(_fsi.class_c_deadline(_fsi.parse_time(received))) == due


def test_emergency_records_carry_a_deadline_and_important_ones_ask_for_the_messages_own():
    e = _fsi.deadlines("EMERGENCY", NOW)
    assert e["respond_by"] == "2026-11-10T20:00:00Z" and "ERT" in e["deadline_basis"]
    assert e["triage_by"] == "2026-11-09T17:00:00Z"
    i = _fsi.deadlines("IMPORTANT", NOW)
    assert i["respond_by"] is None and "IMA" in i["deadline_basis"]


def record(**kw):
    r = _fsi.new_record("m", _fsi.classify(msg()), NOW)
    r.update(ack={"status": "sent"}, page={"status": "sent"})
    r.update(kw)
    return r


def test_overdue_counts_untriaged_unclosed_and_failed_legs():
    later = datetime(2026, 11, 9, 18, 0, tzinfo=timezone.utc)
    assert len(_fsi.overdue([record()], later)) == 1  # not triaged within 2 hours
    assert _fsi.overdue([record(status="triaged")], later) == []
    late = _fsi.overdue([record(status="triaged")], datetime(2026, 11, 11, tzinfo=timezone.utc))
    assert len(late) == 1 and "not closed" in late[0]
    failed = _fsi.overdue([record(status="triaged", ack={"status": "failed"})], later)
    assert failed and "ack failed" in failed[0]
    important = record(designation="IMPORTANT", status="triaged", respond_by=None)
    assert "timeframe" in _fsi.overdue([important], later)[0]


def test_an_important_message_cannot_be_triaged_without_its_stated_timeframe():
    r = _fsi.new_record("m", _fsi.classify(msg(subject="Important: do X")), NOW)
    with pytest.raises(ValueError, match="timeframe"):
        _fsi.triage(r, NOW)
    _fsi.triage(r, NOW, respond_by="2026-11-12T17:00:00-05:00")
    assert r["status"] == "triaged" and r["respond_by"] == "2026-11-12T22:00:00Z"
    _fsi.close(r, NOW, "done")
    with pytest.raises(ValueError):
        _fsi.triage(r, NOW)


# --- acknowledgement (AFC-CSO-ACK) ------------------------------------------------------

def ack(**kw):
    args = {"inbox": "fedramp-security@example.com", "to": "fedramp_security@gsa.gov", "subject": "Emergency: x",
            "rfc_message_id": "<m1@gsa.gov>", "received_at": "2026-11-09T15:00:00Z", "designation": "EMERGENCY",
            "ref": "abc", **kw}
    return _fsi.build_ack(**args)


def header_names(raw):
    return [line.split(":", 1)[0] for line in raw.split("\r\n\r\n", 1)[0].split("\r\n")]


def test_the_acknowledgement_marks_itself_automatic_and_threads_to_the_message():
    raw = ack()
    assert header_names(raw) == ["From", "To", "Subject", "Auto-Submitted", "X-Auto-Response-Suppress",
                                 "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "In-Reply-To",
                                 "References"]
    assert "Auto-Submitted: auto-replied" in raw and "In-Reply-To: <m1@gsa.gov>" in raw


@pytest.mark.parametrize("subject,msgid", [
    ("Emergency\r\nBcc: victim@example.com", "<m1@gsa.gov>"),
    ("ok", "<m1@gsa.gov>\r\nBcc: victim@example.com"),
    ("ok", "<a b@c>"),
    ("\u202eEmergency\u2066", "<x>\nTo: y@z"),
])
def test_nothing_from_the_inbound_message_can_inject_a_header(subject, msgid):
    names = header_names(ack(subject=subject, rfc_message_id=msgid))
    assert "Bcc" not in names and names.count("To") == 1 and len(names) in (8, 10)


def test_an_invalid_recipient_raises_rather_than_sending():
    with pytest.raises(ValueError):
        ack(to="victim@example.com\r\nBcc: x@y.z")


@pytest.mark.parametrize("headers,envelope,reason", [
    ({"Auto-Submitted": "auto-replied"}, "a@gsa.gov", "auto-submitted"),
    ({"Precedence": "bulk"}, "a@gsa.gov", "precedence"),
    ({}, "", "null-sender"),
    ({}, "<>", "null-sender"),
])
def test_no_acknowledgement_to_auto_replies_bulk_mail_or_bounces(headers, envelope, reason):
    c = _fsi.classify(msg(frm="a@gsa.gov", headers=headers, envelope=envelope))
    assert c["kind"] == "fedramp" and c["loop"] == reason


def run_receive(m, register, send_fails=False):
    sent, pages = [], []

    def send(to, raw):
        if send_fails:
            raise ConnectionError("simulated")
        sent.append((to, raw))
    out = _fsi.receive(m, register, inbox="fedramp-security@example.com", send=send, page=pages.append)
    return out, sent, pages


def test_a_redelivered_message_is_acknowledged_and_paged_once():
    register = {}
    _, sent, pages = run_receive(msg(), register)
    assert len(sent) == 1 and len(pages) == 1
    _, sent, pages = run_receive(msg(), register)
    assert sent == [] and pages == []


def test_a_failed_acknowledgement_is_recorded_retried_and_counted_overdue():
    register = {}
    out, _, _ = run_receive(msg(), register, send_fails=True)
    assert out["record"]["ack"] == {"status": "failed", "error": "ConnectionError"}
    assert any("ack failed" in p for p in _fsi.overdue(register.values(), NOW))
    _, sent, _ = run_receive(msg(), register)
    assert len(sent) == 1 and register["m1"]["ack"]["status"] == "sent"


def test_unauthenticated_fedramp_mail_is_registered_and_paged_but_not_acknowledged():
    out, sent, pages = run_receive(msg(auth=FAIL), {})
    assert sent == [] and len(pages) == 1
    assert out["record"]["ack"] == {"status": "suppressed", "reason": "unauthenticated"}


def test_other_mail_is_not_registered_acknowledged_or_paged():
    out, sent, pages = run_receive(msg(frm="a@example.com"), {})
    assert out["record"] is None and sent == [] and pages == []


def test_the_page_subject_is_ascii_and_names_the_domain_not_the_address():
    s = _fsi.page_subject(record())
    assert s == "[FSI] EMERGENCY FedRAMP message from gsa.gov" and "@" not in s


# --- the deploy's simulation step -----------------------------------------------------------

def simulate(tmp_path, messages=MESSAGES):
    out = tmp_path / "sim.json"
    p = subprocess.run([sys.executable, str(SIM), "--messages", str(messages), "--offering", str(OFFERING),
                        "--output", str(out)], capture_output=True, text=True)
    return p, out


def test_the_committed_synthetic_messages_cover_the_required_cases():
    cases = {m["case"]: m for m in json.loads(MESSAGES.read_text())["messages"]}
    assert {"emergency-test", "important", "general", "forged-gsa", "auto-reply"} <= set(cases)
    assert cases["emergency-test"]["expected"]["designation"] == "EMERGENCY_TEST"
    assert cases["forged-gsa"]["expected"]["ack"] == "suppressed:unauthenticated"
    assert cases["forged-gsa"]["expected"]["kind"] == "fedramp"
    assert cases["auto-reply"]["expected"]["ack"] == "suppressed:auto-submitted"


def test_the_simulation_passes_and_publishes_a_labelled_result_without_addresses(tmp_path):
    p, out = simulate(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    text = out.read_text()
    doc = json.loads(text)
    assert doc["simulation"] is True and doc["notice"].startswith("SIMULATION.")
    assert "no mail is received and none is sent" in doc["notice"]
    assert doc["result"] == "pass" and all(c["matches_expected"] for c in doc["cases"])
    assert doc["retry_pass"] == {"acknowledgements_sent_again": 1, "pages_sent_again": 0}
    checks = doc["register_check"]["checks"]
    assert len(checks) >= 10 and all(c["ok"] for c in checks)
    assert doc["contact"].endswith("Hit me up on LinkedIn: https://www.linkedin.com/in/sa2/")
    assert doc["emitted_at"] and doc["rules_exercised"] == SIMULATED_RULES
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text), "published result carries an address"


@pytest.mark.parametrize("case,needle", [
    ("display-name-spoof", '"kind": "other"'),
    ("envelope-only", '"ack": "suppressed:no-from-address"'),
    ("emergency-other-sender", '"emergency_sender_ok": false'),
    ("bulk", '"ack": "suppressed:precedence"'),
    ("bounce", '"ack": "suppressed:null-sender"'),
    ("ack-send-fails", '"ack": "failed"'),
])
def test_the_simulation_exercises_each_behaviour_the_records_claim(case, needle):
    m = next(m for m in json.loads(MESSAGES.read_text())["messages"] if m["case"] == case)
    assert needle in json.dumps(m["expected"]).replace(": False", ": false")


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d["register_check"].update(expected_retry={"acknowledgements_sent_again": 0, "pages_sent_again": 0}),
     "retry pass"),
    (lambda d: d["register_check"].update(later="2026-11-09T19:00:00Z"), "past its deadline"),
    (lambda d: d["register_check"]["expected_overdue"].remove("sim-ack-send-fails"), "items overdue"),
])
def test_each_register_check_fails_the_simulation_when_its_outcome_differs(tmp_path, mutate, needle):
    d = json.loads(MESSAGES.read_text())
    mutate(d)
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps(d))
    p, out = simulate(tmp_path, bad)
    assert p.returncode == 1 and not out.exists() and needle in p.stdout, p.stdout


def test_a_differing_outcome_fails_the_simulation_and_writes_nothing(tmp_path):
    """Known-bad fixture: the forged @gsa.gov message is expected to be acknowledged."""
    p, out = simulate(tmp_path, BAD)
    assert p.returncode == 1 and not out.exists()
    assert "forged-gsa: ack expected 'sent', observed 'suppressed:unauthenticated'" in p.stdout


def test_the_known_bad_fixture_differs_from_the_committed_messages_only_in_that_expectation():
    good, bad = json.loads(MESSAGES.read_text()), json.loads(BAD.read_text())
    fixed = copy.deepcopy(bad)
    next(m for m in fixed["messages"] if m["case"] == "forged-gsa")["expected"]["ack"] = "suppressed:unauthenticated"
    fixed["_note"] = good["_note"]
    assert fixed == good


def step(name):
    m = re.search(r"\n    - name: " + re.escape(name) + r"\n(.*?)(?=\n    - name: |\Z)", WORKFLOW, re.S)
    assert m, name
    return m.group(1)


def test_the_simulation_runs_on_every_deploy_before_the_sdr_build():
    name = "FedRAMP Security Inbox simulation (synthetic messages; nothing received or sent)"
    body = step(name)
    assert "build-fsi-simulation.py" in body and "--output fedramp-inbox-simulation.json" in body
    assert "continue-on-error" not in body and "|| true" not in body
    assert WORKFLOW.index("- name: " + name) < WORKFLOW.index("- name: Build Security Decision Record")


def test_the_simulation_result_is_signed_gated_published_verified_and_freshness_governed():
    assert ("cosign sign-blob --yes --new-bundle-format --bundle fedramp-inbox-simulation.bundle "
            "fedramp-inbox-simulation.json") in WORKFLOW
    assert "fedramp-inbox-simulation.json" in step("Publication redaction gate (no AWS account ID)")
    publish = step("Publish all signed artifacts to /.well-known/")
    for f in ("fedramp-inbox-simulation.json", "fedramp-inbox-simulation.bundle"):
        assert f'aws s3 cp {f} "s3://$BUCKET_NAME/.well-known/{f}"' in publish
    assert "check fedramp-inbox-simulation.json .well-known/fedramp-inbox-simulation.json" in WORKFLOW
    cfg = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    entries = [a for a in cfg["artifacts"] if a["path"] == ".well-known/fedramp-inbox-simulation.json"]
    assert len(entries) == 1 and entries[0]["signed"] is True and entries[0]["cadence"] == "deploy"
    assert entries[0]["timestamp"] == {"source": "json", "field": "emitted_at"}
    assert entries[0]["note"].startswith("SIMULATION")


# --- what is published and recorded ------------------------------------------------------------

def _cpo_doc():
    """The CPO as the deploy builds it, in FedRAMP's schema (the same inputs
    tests/test_cpo_trust_fields.py uses)."""
    import tempfile
    from datetime import datetime, timezone
    import _assessor
    import _ccm
    import _offering
    cpo = _load("build_cpo_fsi", REPO / "scripts" / "build-cpo.py")
    with tempfile.TemporaryDirectory() as d:
        s = Path(d) / "simulated-assessment.json"
        s.write_text((REPO / "tests" / "fixtures" / "assessor" / "simulated-set.json").read_text())
        assessment = _assessor.load_assessment(s, s, verifier=lambda *_a: True)
    now = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
    doc = cpo.build(_offering.load(), json.loads((REPO / "data" / "system-profile.json").read_text()),
                    json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text()),
                    _ccm.load(_ccm.CALENDAR_PATH, now.date()), {}, now, cpo.boundary_groups(), assessment)
    assert _fedramp_schema.validate(doc, "cpo") == []
    return doc, cpo.render_markdown(doc)


def test_the_cpo_publishes_the_simulated_contact_not_an_email_address():
    doc, md = _cpo_doc()
    fsi = doc["providerExtensions"]["fedrampSecurityInbox"]
    off = json.loads(OFFERING.read_text())["fedramp_security_inbox"]
    assert fsi["simulated"] is True and fsi["contact"] == off["contact"]
    assert "Hit me up on LinkedIn: https://www.linkedin.com/in/sa2/" in fsi["contact"] and "@" not in fsi["contact"]
    assert fsi["simulation"] == "https://samaydlette.com/.well-known/fedramp-inbox-simulation.json"
    assert off["contact"] in md


def test_every_afc_record_is_implemented_and_discloses_the_simulation():
    recs = {r["frr_id"]: r for r in json.loads((REPO / "data" / "frr-records.json").read_text())["records"]}
    afc = [rid for rid in recs if rid.startswith("AFC-")]
    assert sorted(afc) == sorted(SIMULATED_RULES + ["AFC-CSO-NOC"])
    for rid in afc:
        r = recs[rid]
        assert r["status"] == "Implemented" and "gap" not in r and "closes_with" not in r, rid
        text = r["implementation"]
        assert text.startswith("SIMULATED FOR THIS PROOF OF CONCEPT"), rid
        assert "no mail is received or sent" in text and "https://www.linkedin.com/in/sa2/" in text, rid
    for rid in SIMULATED_RULES:
        r = recs[rid]
        assert r["simulated"]["counterparty"] == "mail", rid
        refs = [e["ref"] for e in r["evidence"]]
        assert ".well-known/fedramp-inbox-simulation.json" in refs, rid
        assert any(ref.startswith("deploy-with-opa.yml#FedRAMP Security Inbox simulation") for ref in refs), rid
