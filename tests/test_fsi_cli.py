"""scripts/fsi.py, the operator's FedRAMP Security Inbox tool, treats every
message as untrusted: text only, nothing rendered or opened, no control or
bidirectional-override characters, register IDs validated before they become
S3 keys."""

import importlib.util
from email.message import EmailMessage
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("fsi_cli", REPO / "scripts" / "fsi.py")
fsi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fsi)


def raw(build):
    m = EmailMessage()
    m["From"] = "FedRAMP <fedramp_security@gsa.gov>"
    m["To"] = "inbox@example.com"
    m["Subject"] = "Emergency: test"
    build(m)
    return m.as_bytes()


def test_plain_text_is_shown_without_control_or_bidi_characters():
    out = fsi.message_text(raw(lambda m: m.set_content("Do X by Tuesday.\x1b[31m‮evil")))
    assert "Do X by Tuesday." in out
    assert "\x1b" not in out and "‮" not in out


def test_html_only_mail_is_reduced_to_text_and_its_scripts_dropped():
    def build(m):
        m.set_content("<p>Act now</p><script>alert(1)</script><img src='https://tracker.example/x.png'>", subtype="html")
    out = fsi.message_text(raw(build))
    assert "HTML-only message" in out and "Act now" in out
    assert "alert(1)" not in out and "tracker.example" not in out


def test_attachments_are_listed_not_opened():
    def build(m):
        m.set_content("see attached")
        m.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="run‮me.exe")
    out = fsi.message_text(raw(build))
    assert "[attachment not opened: runme.exe, application/octet-stream, 4 bytes]" in out


@pytest.mark.parametrize("value", ["../closed/x", "a/b", "", "x" * 200, "id with space"])
def test_register_ids_are_validated_before_they_become_keys(value):
    with pytest.raises(SystemExit):
        fsi.record_id(value)


def test_the_exercise_refuses_a_malformed_reply_address():
    with pytest.raises(SystemExit):
        fsi.main(["exercise", "--reply-to", "not an address"])


def test_important_messages_cannot_be_triaged_without_their_timeframe(monkeypatch):
    rec = {"id": "m1", "designation": "IMPORTANT", "status": "open"}
    monkeypatch.setattr(fsi, "find", lambda rid: ("register/open/m1.json", dict(rec)))
    monkeypatch.setattr(fsi, "put_json", lambda key, doc: pytest.fail("must not write"))
    with pytest.raises(SystemExit, match="AFC-CSO-IMA"):
        fsi.main(["triage", "m1"])


def test_triage_records_the_messages_own_deadline(monkeypatch):
    written = {}
    monkeypatch.setattr(fsi, "find", lambda rid: ("register/open/m1.json", {"id": "m1", "designation": "EMERGENCY", "status": "open"}))
    monkeypatch.setattr(fsi, "put_json", lambda key, doc: written.update(key=key, doc=doc))
    assert fsi.main(["triage", "m1", "--respond-by", "2026-11-10T12:00-05:00"]) == 0
    assert written["doc"]["respond_by"] == "2026-11-10T17:00:00+00:00"
    assert written["doc"]["status"] == "triaged"
