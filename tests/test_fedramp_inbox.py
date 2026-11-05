"""The FedRAMP Security Inbox (AFC-CSO-INB, TFG, RCV, CRA, EMR, IMA, ACK).

infrastructure/fedramp-inbox/ is the function SES hands each message to, and
infrastructure/fedramp-inbox.tf is the receiving configuration. These tests pin
the behaviour each rule asks for:

  TFG  mail from @fedramp.gov / @gsa.gov is FedRAMP, whatever its spam verdict
       or authentication result; look-alike domains are not
  ACK  FedRAMP mail is acknowledged automatically, once, without letting the
       inbound message inject a header, and never in reply to an auto-reply
  EMR  Emergency-designated mail pages the senior security official
  CRA  Emergency / Emergency Test mail gets a deadline in the register
  IMA  Important mail gets a tracked item that stays overdue until its
       timeframe is recorded
  RCV  nothing in the receipt rule can drop or refuse mail, and the hourly
       check pages on a configuration that would

The logic runs directly in node; the handler runs against stand-in AWS SDK
packages in a temporary directory, so the shipped wiring is exercised too.
"""

import base64
import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INBOX = REPO / "infrastructure" / "fedramp-inbox"
TF = REPO / "infrastructure" / "fedramp-inbox.tf"
OFFERING = REPO / "data" / "cds" / "offering.json"
NOW = "2026-11-09T15:00:00Z"  # Monday 10:00 a.m. ET (EST)

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def fsi_address():
    return json.loads(OFFERING.read_text())["fedramp_security_inbox"]["address"]


def node(script, cwd):
    out = subprocess.run(["node", "--input-type=module", "-e", script],
                         cwd=cwd, capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def logic(expr, **values):
    """Evaluate a JS expression with logic.mjs's exports in scope as L."""
    bindings = "".join(f"const {k} = {json.dumps(v)};\n" for k, v in values.items())
    script = f"import * as L from '{INBOX / 'logic.mjs'}';\n{bindings}console.log(JSON.stringify({expr}));"
    return node(script, REPO)


def ses_record(frm="FedRAMP <fedramp_security@gsa.gov>", subject="Emergency: action required",
               source=None, headers=None, spam="PASS", virus="PASS", spf="PASS", dkim="PASS", dmarc="PASS",
               message_id="abc123msgid", timestamp=NOW):
    addr = re.search(r"<([^>]+)>", frm)
    return {
        "mail": {
            "messageId": message_id,
            "source": source if source is not None else (addr.group(1) if addr else frm),
            "timestamp": timestamp,
            "headers": headers if headers is not None else [{"name": "Message-ID", "value": "<m1@gsa.gov>"}],
            "commonHeaders": {"from": [frm], "subject": subject},
        },
        "receipt": {
            "timestamp": timestamp,
            "spamVerdict": {"status": spam}, "virusVerdict": {"status": virus},
            "spfVerdict": {"status": spf}, "dkimVerdict": {"status": dkim}, "dmarcVerdict": {"status": dmarc},
        },
    }


# --- classification (AFC-CSO-TFG) ---------------------------------------------------

@pytest.mark.parametrize("frm", [
    "FedRAMP PMO <fedramp_security@gsa.gov>",
    "someone@FedRAMP.gov",
    "\"F20B Team\" <info@fedramp.gov>",
])
def test_fedramp_senders_are_fedramp_even_when_flagged_as_spam_or_unauthenticated(frm):
    c = logic("L.classify(r)", r=ses_record(frm=frm, spam="FAIL", virus="FAIL", spf="FAIL", dkim="FAIL", dmarc="FAIL"))
    assert c["kind"] == "fedramp"
    assert c["designation"] == "EMERGENCY"
    assert c["authenticated"] is False  # shown to the operator, never used to demote


@pytest.mark.parametrize("frm,source", [
    ("x <a@fedramp.gov.example.com>", "a@fedramp.gov.example.com"),
    ("x <a@notfedramp.gov>", "a@notfedramp.gov"),
    ("x <a@mail.gsa.gov>", "a@mail.gsa.gov"),
    ("\"fedramp_security@gsa.gov\" <attacker@example.com>", "attacker@example.com"),
    ("fedramp_security@gsa.gov <attacker@example.com>", "attacker@example.com"),
])
def test_look_alike_domains_and_display_name_spoofs_are_not_fedramp(frm, source):
    c = logic("L.classify(r)", r=ses_record(frm=frm, source=source))
    assert c["kind"] == "other"


def test_a_fedramp_envelope_sender_counts_even_if_the_from_header_is_unparseable():
    c = logic("L.classify(r)", r=ses_record(frm="garbage <<>>", source="bounces@gsa.gov"))
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
    assert logic("L.designationOf(s)", s=subject) == want


def test_an_emergency_from_an_address_other_than_fedramp_security_is_flagged_not_demoted():
    c = logic("L.classify(r)", r=ses_record(frm="Someone <someone@gsa.gov>", subject="Emergency: do X"))
    assert c["designation"] == "EMERGENCY" and c["emergency_sender_ok"] is False


# --- deadlines (AFC-CSO-CRA, AFC-FRP-ERT) --------------------------------------------

@pytest.mark.parametrize("received,due", [
    ("2026-11-09T15:00:00Z", "2026-11-10T20:00:00.000Z"),  # Mon 10:00 EST -> Tue 15:00 EST
    ("2026-11-13T21:30:00Z", "2026-11-16T20:00:00.000Z"),  # Fri 16:30 EST -> Mon 15:00 EST
    ("2026-11-14T15:00:00Z", "2026-11-17T20:00:00.000Z"),  # Sat -> Tue (Mon is day 1)
    ("2026-10-30T14:00:00Z", "2026-11-02T20:00:00.000Z"),  # Fri 10:00 EDT -> Mon 15:00 EST (DST ends Sun)
    ("2026-11-10T04:30:00Z", "2026-11-10T20:00:00.000Z"),  # Mon 23:30 EST counts Monday as day 1
])
def test_class_c_default_deadline_is_3pm_eastern_on_the_second_business_day(received, due):
    assert logic("new Date(L.classCDeadline(Date.parse(t))).toISOString()", t=received) == due


def test_emergency_records_carry_a_deadline_and_important_ones_ask_for_the_messages_own():
    e = logic("L.deadlines('EMERGENCY', Date.parse(t))", t=NOW)
    assert e["respond_by"] == "2026-11-10T20:00:00.000Z" and "ERT" in e["deadline_basis"]
    assert e["triage_by"] == "2026-11-09T17:00:00.000Z"
    i = logic("L.deadlines('IMPORTANT', Date.parse(t))", t=NOW)
    assert i["respond_by"] is None and "IMA" in i["deadline_basis"]


def test_overdue_counts_untriaged_unclosed_unacknowledged_and_unpaged_items():
    base = {"id": "m", "designation": "EMERGENCY", "status": "open", "triage_by": "2026-11-09T10:00:00Z",
            "respond_by": "2026-11-10T20:00:00Z", "ack": {"status": "sent"}, "page": {"status": "sent"}}
    now = "2026-11-09T12:00:00Z"
    assert len(logic("L.overdue(r, Date.parse(t))", r=[base], t=now)) == 1  # not triaged
    assert logic("L.overdue(r, Date.parse(t))", r=[{**base, "status": "triaged"}], t=now) == []
    late = logic("L.overdue(r, Date.parse(t))", r=[{**base, "status": "triaged"}], t="2026-11-11T00:00:00Z")
    assert len(late) == 1 and "not closed" in late[0]
    failed = {**base, "status": "triaged", "ack": {"status": "failed", "error": "MessageRejected"}}
    assert "acknowledgement failed" in logic("L.overdue(r, Date.parse(t))", r=[failed], t=now)[0]
    important = {**base, "designation": "IMPORTANT", "status": "triaged", "respond_by": None}
    assert "timeframe" in logic("L.overdue(r, Date.parse(t))", r=[important], t=now)[0]


# --- acknowledgement (AFC-CSO-ACK) ------------------------------------------------------

def ack(**kw):
    args = {"fsiAddress": "fedramp-security@example.com", "to": "fedramp_security@gsa.gov",
            "subject": "Emergency: x", "rfcMessageId": "<m1@gsa.gov>", "receivedAt": NOW,
            "designation": "EMERGENCY", "ref": "abc", "exercise": False, **kw}
    return logic("L.buildAck(a)", a=args)


def header_lines(raw):
    head = raw.split("\r\n\r\n", 1)[0]
    return [line.split(":", 1)[0] for line in head.split("\r\n")]


def test_the_acknowledgement_marks_itself_automatic_and_threads_to_the_message():
    raw = ack()
    names = header_lines(raw)
    assert names == ["From", "To", "Subject", "Auto-Submitted", "X-Auto-Response-Suppress", "MIME-Version",
                     "Content-Type", "Content-Transfer-Encoding", "In-Reply-To", "References"]
    assert "Auto-Submitted: auto-replied" in raw and "In-Reply-To: <m1@gsa.gov>" in raw


@pytest.mark.parametrize("subject,msgid", [
    ("Emergency\r\nBcc: victim@example.com", "<m1@gsa.gov>"),
    ("ok", "<m1@gsa.gov>\r\nBcc: victim@example.com"),
    ("ok", "<a b@c>"),
    ("\u202eEmergency\u2066", "<x>\nTo: y@z"),
])
def test_nothing_from_the_inbound_message_can_inject_a_header(subject, msgid):
    raw = ack(subject=subject, rfcMessageId=msgid)
    names = header_lines(raw)
    assert "Bcc" not in names and names.count("To") == 1
    assert len(names) in (8, 10)


def test_an_invalid_recipient_raises_rather_than_sending():
    with pytest.raises(subprocess.CalledProcessError):
        ack(to="victim@example.com\r\nBcc: x@y.z")


@pytest.mark.parametrize("headers,source,reason", [
    ([{"name": "Auto-Submitted", "value": "auto-replied"}], "a@gsa.gov", "auto-submitted"),
    ([{"name": "Precedence", "value": "bulk"}], "a@gsa.gov", "precedence"),
    ([], "", "null-sender"),
    ([], "<>", "null-sender"),
])
def test_no_acknowledgement_to_auto_replies_bulk_mail_or_bounces(headers, source, reason):
    c = logic("L.classify(r)", r=ses_record(frm="a@gsa.gov", headers=headers, source=source))
    assert c["kind"] == "fedramp" and c["loop"] == reason


# --- configuration check (AFC-CSO-RCV, TFG automated validation) --------------------------

EXPECTED = {"ruleSet": "set", "rule": "fsi", "address": "fedramp-security@example.com", "bucket": "b",
            "prefix": "inbound/", "functionArn": "arn:aws:lambda:us-east-2:1:function:f", "mx": "inbound-smtp.us-east-2.amazonaws.com"}


def good_live():
    return {
        "ruleSet": {"Metadata": {"Name": "set"}, "Rules": [{
            "Name": "fsi", "Enabled": True, "Recipients": ["fedramp-security@example.com"], "ScanEnabled": True,
            "TlsPolicy": "Optional", "Actions": [
                {"S3Action": {"BucketName": "b", "ObjectKeyPrefix": "inbound/"}},
                {"LambdaAction": {"FunctionArn": "arn:aws:lambda:us-east-2:1:function:f", "InvocationType": "Event"}}]}]},
        "identity": {"VerifiedForSendingStatus": True, "DkimAttributes": {"Status": "SUCCESS"},
                     "MailFromAttributes": {"MailFromDomainStatus": "SUCCESS"}},
        "account": {"ProductionAccessEnabled": True, "SendingEnabled": True},
        "mx": ["10 inbound-smtp.us-east-2.amazonaws.com."],
    }


def problems(live):
    return logic("L.configProblems(e, l)", e=EXPECTED, l=live)


def test_the_declared_configuration_has_no_problems():
    assert problems(good_live()) == []


def mutate(path, value):
    live = good_live()
    node_ = live
    *parents, leaf = path
    for p in parents:
        node_ = node_[p]
    node_[leaf] = value
    return live


@pytest.mark.parametrize("path,value,needle", [
    (["ruleSet"], None, "no receipt rule set"),
    (["ruleSet", "Metadata", "Name"], "other", "active rule set is other"),
    (["ruleSet", "Rules", 0, "Enabled"], False, "disabled"),
    (["ruleSet", "Rules", 0, "Recipients"], ["example.com"], "exactly"),
    (["ruleSet", "Rules", 0, "TlsPolicy"], "Require", "Require"),
    (["ruleSet", "Rules", 0, "ScanEnabled"], False, "scanning"),
    (["ruleSet", "Rules", 0, "Actions"], [{"BounceAction": {}}], "first action"),
    (["account", "ProductionAccessEnabled"], False, "sandbox"),
    (["identity", "DkimAttributes", "Status"], "FAILED", "DKIM"),
    (["mx"], [], "MX"),
])
def test_each_drift_that_could_lose_or_delay_fedramp_mail_is_a_problem(path, value, needle):
    out = problems(mutate(path, value))
    assert any(needle in p for p in out), out


def test_a_rule_ahead_of_the_inbox_rule_that_matches_every_address_is_a_problem():
    live = good_live()
    live["ruleSet"]["Rules"].insert(0, {"Name": "catch-all", "Enabled": True, "Recipients": [],
                                        "Actions": [{"StopAction": {"Scope": "RuleSet"}}]})
    assert any("catch-all" in p for p in problems(live))


# --- the handler, against stand-in SDK packages ---------------------------------------------

SDK = {
    "client-s3": ("S3Client", ["GetObjectCommand", "PutObjectCommand", "ListObjectsV2Command"]),
    "client-sns": ("SNSClient", ["PublishCommand"]),
    "client-sesv2": ("SESv2Client", ["SendEmailCommand", "GetEmailIdentityCommand", "GetAccountCommand"]),
    "client-ses": ("SESClient", ["DescribeActiveReceiptRuleSetCommand"]),
    "client-route-53": ("Route53Client", ["ListResourceRecordSetsCommand"]),
    "client-cloudwatch": ("CloudWatchClient", ["PutMetricDataCommand"]),
}


def fake_sdk(tmp_path):
    for f in ("index.mjs", "logic.mjs"):
        shutil.copy(INBOX / f, tmp_path / f)
    for pkg, (client, commands) in SDK.items():
        d = tmp_path / "node_modules" / "@aws-sdk" / pkg
        d.mkdir(parents=True)
        (d / "package.json").write_text('{"type": "module", "main": "index.js"}')
        cmds = "\n".join(f"export class {c} {{ constructor(input) {{ this.input = input; }} }}" for c in commands)
        (d / "index.js").write_text(cmds + textwrap.dedent(f"""
            export class {client} {{
              async send(cmd) {{
                const name = cmd.constructor.name;
                const input = cmd.input.Content ? {{ ...cmd.input, Content: {{ Raw: {{ Data: Buffer.from(cmd.input.Content.Raw.Data).toString('utf8') }} }} }} : cmd.input;
                globalThis.__calls.push({{ name, input }});
                const r = globalThis.__respond(name, cmd.input);
                if (r && r.__throw) {{ const e = new Error(r.__throw); e.name = r.__throw; throw e; }}
                return r ?? {{}};
              }}
            }}
        """))


ENV = {
    "FSI_ADDRESS": "fedramp-security@example.com", "MAIL_BUCKET": "fsi-bucket", "MAIL_PREFIX": "inbound/",
    "ALERT_TOPIC_ARN": "arn:aws:sns:us-east-2:1:alerts", "METRIC_NAMESPACE": "Samaydlette/Evidence",
    "RULE_SET": "set", "RULE_NAME": "fsi", "DOMAIN": "example.com", "ZONE_ID": "Z1",
    "MX_TARGET": "inbound-smtp.us-east-2.amazonaws.com", "RUNBOOK_URL": "https://example.com/runbook",
}


def run_handler(tmp_path, event, objects=None, fail=None, responses=None):
    """Run the shipped handler. objects: {key: record} in the bucket. fail:
    {command name: error name}. responses: {command name: response}."""
    fake_sdk(tmp_path)
    script = textwrap.dedent(f"""
        Object.assign(process.env, {json.dumps(ENV)});
        globalThis.__calls = [];
        const objects = {json.dumps(objects or {})};
        const fail = {json.dumps(fail or {})};
        const responses = {json.dumps(responses or {})};
        globalThis.__respond = (name, input) => {{
          if (fail[name]) return {{ __throw: fail[name] }};
          if (name === 'GetObjectCommand') {{
            if (!(input.Key in objects)) return {{ __throw: 'NoSuchKey' }};
            const body = JSON.stringify(objects[input.Key]);
            return {{ Body: {{ transformToString: async () => body }} }};
          }}
          if (name === 'ListObjectsV2Command') return {{ Contents: Object.keys(objects).filter((k) => k.startsWith(input.Prefix)).map((Key) => ({{ Key }})) }};
          if (name === 'PublishCommand') return {{ MessageId: 'sns-1' }};
          if (name === 'SendEmailCommand') return {{ MessageId: 'ses-1' }};
          return responses[name];
        }};
        const logs = [];
        console.log = (...a) => logs.push(a.join(' '));
        console.warn = console.log;
        const {{ handler }} = await import('./index.mjs');
        let out = null, error = null;
        try {{
          out = await handler({json.dumps(event)}, {{ invokedFunctionArn: 'arn:aws:lambda:us-east-2:1:function:f' }},
                              {{ now: Date.parse('{NOW}') }});
        }} catch (e) {{ error = e.message; }}
        process.stdout.write(JSON.stringify({{ out, error, calls: globalThis.__calls, logs }}) + '\\n');
    """)
    return node(script, tmp_path)


def ses_event(**kw):
    return {"Records": [{"eventSource": "aws:ses", "eventVersion": "1.0", "ses": ses_record(**kw)}]}


def calls(r, name):
    return [c["input"] for c in r["calls"] if c["name"] == name]


def test_an_emergency_is_registered_acknowledged_and_pages_the_security_official(tmp_path):
    r = run_handler(tmp_path, ses_event(subject="EMERGENCY: rotate keys within 12 hours"))
    assert r["error"] is None
    (send,) = calls(r, "SendEmailCommand")
    assert send["FromEmailAddress"] == ENV["FSI_ADDRESS"]
    assert send["Destination"] == {"ToAddresses": ["fedramp_security@gsa.gov"]}
    (page,) = calls(r, "PublishCommand")
    assert page["TopicArn"] == ENV["ALERT_TOPIC_ARN"] and "EMERGENCY" in page["Subject"]
    assert "2026-11-10T20:00:00.000Z" in page["Message"]
    (put,) = calls(r, "PutObjectCommand")
    assert put["Key"] == "register/open/abc123msgid.json"
    rec = json.loads(put["Body"])
    assert rec["designation"] == "EMERGENCY" and rec["respond_by"] == "2026-11-10T20:00:00.000Z"
    assert rec["ack"]["status"] == "sent" and rec["page"]["status"] == "sent"
    assert rec["object_key"] == "inbound/abc123msgid"


def test_an_important_message_pages_and_opens_a_tracked_item(tmp_path):
    r = run_handler(tmp_path, ses_event(subject="Important: update contacts"))
    (page,) = calls(r, "PublishCommand")
    assert "IMPORTANT" in page["Subject"]
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["designation"] == "IMPORTANT" and rec["status"] == "open"


def test_other_mail_is_left_where_ses_stored_it_and_neither_acknowledged_nor_paged(tmp_path):
    r = run_handler(tmp_path, ses_event(frm="Spammer <x@example.net>", subject="EMERGENCY: buy now"))
    names = {c["name"] for c in r["calls"]}
    assert names == set()  # no ack, no page, no register write, no read of the message
    assert r["out"]["handled"] == [{"id": "abc123msgid", "kind": "other"}]


def test_the_function_never_reads_the_message_body(tmp_path):
    r = run_handler(tmp_path, ses_event())
    assert all(c["input"]["Key"].startswith("register/") for c in r["calls"] if c["name"] == "GetObjectCommand")


def test_logs_carry_outcomes_not_subjects_or_addresses(tmp_path):
    r = run_handler(tmp_path, ses_event(subject="EMERGENCY: secret-subject-text"))
    text = "\n".join(r["logs"])
    assert "secret-subject-text" not in text and "@" not in text


def test_a_retry_does_not_acknowledge_twice(tmp_path):
    existing = {"register/open/abc123msgid.json": {
        "schema": "fsi-register/1", "id": "abc123msgid", "exercise": False, "received_at": NOW, "kind": "fedramp",
        "from": "fedramp_security@gsa.gov", "sender_domain": "gsa.gov", "subject": "Emergency: x",
        "designation": "EMERGENCY", "auth": {}, "authenticated": True, "status": "open",
        "triage_by": NOW, "respond_by": NOW, "deadline_basis": "x",
        "ack": {"status": "sent"}, "page": {"status": "failed", "error": "Throttled"}, "history": []}}
    r = run_handler(tmp_path, ses_event(), objects=existing)
    assert calls(r, "SendEmailCommand") == []
    assert len(calls(r, "PublishCommand")) == 1


def test_a_page_that_fails_is_recorded_and_raised_so_ses_retries(tmp_path):
    r = run_handler(tmp_path, ses_event(), fail={"PublishCommand": "KMSAccessDeniedException"})
    assert r["error"] and "page failed" in r["error"]
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["page"]["status"] == "failed" and rec["ack"]["status"] == "sent"


def test_a_sandbox_rejection_of_the_acknowledgement_is_recorded_not_hidden(tmp_path):
    r = run_handler(tmp_path, ses_event(), fail={"SendEmailCommand": "MessageRejected"})
    assert r["error"] is None
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["ack"] == {"status": "failed", "at": rec["ack"]["at"], "error": "MessageRejected"}
    assert len(calls(r, "PublishCommand")) == 1


def test_unauthenticated_fedramp_mail_is_paged_but_not_acknowledged(tmp_path):
    """A forged @gsa.gov From must not make the inbox mail attacker-chosen text
    to a government address; genuine FedRAMP mail passes DMARC (AFC-FRP-VRE)."""
    r = run_handler(tmp_path, ses_event(spf="FAIL", dkim="FAIL", dmarc="FAIL"))
    assert calls(r, "SendEmailCommand") == []
    (page,) = calls(r, "PublishCommand")
    assert "NOT AUTHENTICATED" in page["Message"]
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["kind"] == "fedramp" and rec["ack"] == {"status": "suppressed", "reason": "unauthenticated"}


def test_an_auto_reply_from_fedramp_is_registered_and_paged_but_not_acknowledged(tmp_path):
    r = run_handler(tmp_path, ses_event(headers=[{"name": "Auto-Submitted", "value": "auto-replied"}]))
    assert calls(r, "SendEmailCommand") == []
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["ack"] == {"status": "suppressed", "reason": "auto-submitted"}


def schedule_responses(**over):
    live = good_live()
    live["ruleSet"]["Metadata"]["Name"] = "set"
    resp = {
        "DescribeActiveReceiptRuleSetCommand": live["ruleSet"],
        "GetEmailIdentityCommand": live["identity"],
        "GetAccountCommand": live["account"],
        "ListResourceRecordSetsCommand": {"ResourceRecordSets": [
            {"Name": "example.com.", "Type": "MX", "ResourceRecords": [{"Value": "10 inbound-smtp.us-east-2.amazonaws.com"}]}]},
    }
    resp["DescribeActiveReceiptRuleSetCommand"]["Rules"][0]["Recipients"] = [ENV["FSI_ADDRESS"]]
    resp["DescribeActiveReceiptRuleSetCommand"]["Rules"][0]["Actions"] = [
        {"S3Action": {"BucketName": "fsi-bucket", "ObjectKeyPrefix": "inbound/"}},
        {"LambdaAction": {"FunctionArn": "arn:aws:lambda:us-east-2:1:function:f", "InvocationType": "Event"}}]
    resp.update(over)
    return resp


def metric(r, name):
    (put,) = calls(r, "PutMetricDataCommand")
    return {d["MetricName"]: d["Value"] for d in put["MetricData"]}[name]


def test_the_hourly_check_reports_a_clean_inbox_as_zero_problems(tmp_path):
    r = run_handler(tmp_path, {"source": "aws.events"}, responses=schedule_responses())
    assert r["error"] is None, r
    assert metric(r, "InboxConfigProblems") == 0 and metric(r, "InboxOverdue") == 0


def test_the_hourly_check_counts_drift_and_unreadable_settings(tmp_path):
    resp = schedule_responses(GetAccountCommand={"ProductionAccessEnabled": False, "SendingEnabled": True})
    r = run_handler(tmp_path, {"source": "aws.events"}, responses=resp, fail={"GetEmailIdentityCommand": "AccessDenied"})
    assert metric(r, "InboxConfigProblems") >= 2
    assert any("sandbox" in p for p in r["out"]["config_problems"])
    assert any("identity unreadable" in p for p in r["out"]["config_problems"])


def test_the_hourly_check_counts_overdue_register_items(tmp_path):
    late = {"register/open/m1.json": {"id": "m1", "designation": "EMERGENCY", "status": "open",
                                      "triage_by": "2026-11-09T10:00:00Z", "respond_by": "2026-11-09T11:00:00Z",
                                      "ack": {"status": "sent"}, "page": {"status": "sent"}}}
    r = run_handler(tmp_path, {"source": "aws.events"}, objects=late, responses=schedule_responses())
    assert metric(r, "InboxOverdue") == 2


def test_the_exercise_runs_the_real_classifier_and_acknowledges_the_operator(tmp_path):
    r = run_handler(tmp_path, {"exercise": {"nonce": "2026-11-09-abcd", "reply_to": "operator@example.org",
                                            "designation": "EMERGENCY_TEST"}})
    assert r["error"] is None, r
    (send,) = calls(r, "SendEmailCommand")
    assert send["Destination"] == {"ToAddresses": ["operator@example.org"]}
    raw = send["Content"]["Raw"]["Data"]
    subject = re.search(r"^Subject: =\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=", raw, re.M).group(1)
    assert base64.b64decode(subject).decode().startswith("[EXERCISE]")
    body = base64.b64decode("".join(raw.split("\r\n\r\n", 1)[1].split())).decode()
    assert body.startswith("THIS IS AN EXERCISE")
    (page,) = calls(r, "PublishCommand")
    assert page["Subject"].startswith("[FSI EXERCISE] EMERGENCY TEST")
    rec = json.loads(calls(r, "PutObjectCommand")[0]["Body"])
    assert rec["exercise"] is True and rec["id"] == "exercise-2026-11-09-abcd"


def test_an_exercise_with_a_malformed_nonce_is_refused(tmp_path):
    r = run_handler(tmp_path, {"exercise": {"nonce": "../../x", "reply_to": "operator@example.org"}})
    assert r["error"] and r["calls"] == []


# --- the receiving configuration (infrastructure/fedramp-inbox.tf) ----------------------------

def block(text, header):
    start = text.index(header)
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[start:j + 1]
    raise AssertionError(f"unterminated block {header}")


def test_the_receipt_rule_stores_then_hands_off_and_has_nothing_that_drops_mail():
    rule = block(TF.read_text(), 'resource "aws_ses_receipt_rule" "fsi"')
    actions = re.findall(r"^\s*(\w+_action)\s*\{", rule, re.M)
    assert actions == ["s3_action", "lambda_action"]
    assert re.search(r'tls_policy\s*=\s*"Optional"', rule)
    assert re.search(r"scan_enabled\s*=\s*true", rule)
    assert re.search(r'invocation_type\s*=\s*"Event"', rule)
    assert "local.fsi_address" in rule


def test_the_inbox_address_has_one_source_of_truth():
    address = fsi_address()
    assert re.fullmatch(r"[a-z0-9._-]+@samaydlette\.com", address)
    hits = []
    for root in ("infrastructure", "scripts", ".github"):
        for p in (REPO / root).rglob("*"):
            if p.is_file() and p.suffix in {".tf", ".mjs", ".js", ".py", ".yml", ".yaml", ".json", ".sh"} \
                    and ".terraform" not in p.parts and "node_modules" not in p.parts:
                if address in p.read_text(errors="ignore"):
                    hits.append(str(p.relative_to(REPO)))
    assert hits == [], f"the address is restated outside data/cds/offering.json: {hits}"
    assert 'jsondecode(file("${path.module}/../data/cds/offering.json")).fedramp_security_inbox' in TF.read_text()


def test_the_mail_bucket_is_cmk_encrypted_private_and_tls_only():
    tf = TF.read_text()
    sse = block(tf, 'resource "aws_s3_bucket_server_side_encryption_configuration" "fsi_mail"')
    assert '"aws:kms"' in sse and "aws_kms_key.at_rest.arn" in sse and "bucket_key_enabled = true" in sse
    pab = block(tf, 'resource "aws_s3_bucket_public_access_block" "fsi_mail"')
    assert len(re.findall(r"= true", pab)) == 4
    pol = block(tf, 'resource "aws_s3_bucket_policy" "fsi_mail"')
    assert '"aws:SecureTransport" = "false"' in pol and "ses.amazonaws.com" in pol


def test_the_function_role_grants_no_wildcard_action_and_sends_only_as_the_inbox():
    pol = block(TF.read_text(), 'resource "aws_iam_role_policy" "fedramp_inbox"')
    assert not re.search(r'"[a-z0-9-]+:\*"', pol)
    statements = {m.group(1): m.group(2) for m in re.finditer(r'Sid\s*=\s*"(\w+)"(.*?)(?=Sid\s*=|\Z)', pol, re.S)}
    send = statements["AcknowledgeAsTheInboxOnly"]
    assert "ses:SendRawEmail" in send and '"ses:FromAddress" = local.fsi_address' in send
    register = statements["ReadWriteRegister"]
    assert "/register/*" in register and "inbound" not in register
    assert not any("inbound" in body for body in statements.values())


# --- the inventory (the inbox is in the boundary, classified as Terraform tags it) -----------

def _ksi():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ksi_for_fsi", REPO / "scripts" / "build-ksi-signal.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _inbox_components():
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_ses_receipt_rule_set", "name": "fsi", "index": 0, "address": "aws_ses_receipt_rule_set.fsi[0]",
         "values": {"id": "samaydlette-com-fsi", "arn": "arn:aws:ses:us-east-2:1:receipt-rule-set/samaydlette-com-fsi"}},
        {"type": "aws_ses_receipt_rule", "name": "fsi", "index": 0, "values": {"name": "fedramp-security-inbox", "tls_policy": "Optional"}},
        {"type": "aws_sesv2_email_identity", "name": "fsi", "index": 0, "values": {"email_identity": "samaydlette.com"}},
        {"type": "aws_lambda_function", "name": "fedramp_inbox", "index": 0,
         "values": {"function_name": "samaydlette-com-fedramp-inbox", "arn": "arn:aws:lambda:us-east-2:1:function:samaydlette-com-fedramp-inbox"}},
        {"type": "aws_s3_bucket", "name": "fsi_mail", "index": 0,
         "values": {"bucket": "samaydlette-com-fsi-mail", "arn": "arn:aws:s3:::samaydlette-com-fsi-mail"}},
    ]}}}
    return {(c["type"], c["attributes"]["tf_name"]): c for c in _ksi().build_cloud_components(state, {})}


def _tf_profile(text):
    return dict(re.findall(r'(\w+) = "([^"]*)"', text))


def test_the_receiving_interface_is_an_inventoried_internet_facing_component():
    comps = _inbox_components()
    rx = comps[("mail_receiver", "fsi")]
    assert rx["component_id"] == "aws::mail_receiver::fsi"
    assert rx["resource_type"] == "AWS::SES::ReceiptRuleSet"
    assert rx["attributes"]["classification"]["internet_reachable"] is True
    assert {"aws_ses_receipt_rule", "aws_sesv2_email_identity"} <= set(rx["attributes"]["config"])
    schema = json.loads((REPO / "infrastructure" / "schemas" / "ksi-signal.schema.json").read_text())
    assert "mail_receiver" in json.dumps(schema)


@pytest.mark.parametrize("key,tf_resource,profile", [
    (("function", "fedramp_inbox"), 'resource "aws_lambda_function" "fedramp_inbox"', "local.fsi_cls"),
    (("object_store", "fsi_mail"), 'resource "aws_s3_bucket" "fsi_mail"', "local.cls.security_tooling_internal"),
])
def test_inventory_classification_matches_the_terraform_tags(key, tf_resource, profile):
    """Reconciliation invariant (i) compares live tags with the inventory; they
    must agree or the first deploy that creates the inbox fails the gate."""
    tf = TF.read_text()
    assert f"tags = merge({profile}," in block(tf, tf_resource)
    if profile == "local.fsi_cls":
        expected = _tf_profile(re.search(r"fsi_cls = \{([^}]*)\}", tf).group(1))
    else:
        main = (REPO / "infrastructure" / "main.tf").read_text()
        expected = _tf_profile(re.search(r"security_tooling_internal = \{([^}]*)\}", main).group(1))
    cls = _inbox_components()[key]["attributes"]["classification"]
    assert cls["internet_reachable"] is (expected["InternetReachable"] == "true")
    assert cls["archetype"] == expected["Archetype"]
    assert cls["data_sensitivity"] == expected["DataSensitivity"]
    assert cls["mission_criticality"] == expected["MissionCriticality"]


def test_every_inbox_component_has_a_place_in_the_boundary_map():
    import fnmatch
    groups = json.loads((REPO / "docs" / "boundary" / "boundary-classification.json").read_text())["groups"]
    ids = [c["component_id"] for c in _inbox_components().values()]
    ids += ["aws::metric_alarm::fsi[fsi-config]", "aws::log_group::fedramp_inbox", "aws::iam_role::fedramp_inbox",
            "aws::iam_policy::fedramp_inbox", "aws::event_schedule::fedramp_inbox"]
    for cid in ids:
        first = next(g["key"] for g in groups if any(fnmatch.fnmatch(cid, m) for m in g["match"]))
        assert first == "fsi", (cid, first)


def test_the_cpo_publishes_the_inbox_address_from_its_one_source(tmp_path):
    out = tmp_path / "cpo.json"
    subprocess.run(["python3", str(REPO / "scripts" / "build-cpo.py"), "--offering", str(OFFERING),
                    "--profile", str(REPO / "data" / "system-profile.json"), "--overview", str(tmp_path / "none"),
                    "--ksi-signal", str(tmp_path / "none"), "--output", str(out), "--md-output", ""],
                   check=True, capture_output=True)
    fsi = json.loads(out.read_text())["certification_data"]["fedramp_security_inbox"]
    assert fsi == {"address": fsi_address(), "rule": "AFC-CSO-INB",
                   "runbook": json.loads(OFFERING.read_text())["fedramp_security_inbox"]["runbook"]}
