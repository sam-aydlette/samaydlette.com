"""FedRAMP Security Inbox logic, as pure functions (no I/O, no network).

The FedRAMP Security Inbox is SIMULATED for this proof of concept, by the
operator's decision: no mail is received and none is sent. This module is the
logic a real inbox would run, and scripts/build-fsi-simulation.py runs it on
every deploy over committed synthetic messages (data/fsi-simulation/), failing
the deploy if any outcome differs from what the message file expects.

Rules the logic implements (FedRAMP Consolidated Rules 2026, AFC family):
  AFC-CSO-TFG  mail from @fedramp.gov or @gsa.gov (exact domains) is FedRAMP
               by default, whatever its spam or authentication verdict
  AFC-CSO-EMR  Emergency-designated mail pages the senior security official
  AFC-CSO-CRA  Emergency / Emergency Test mail gets a tracked deadline
  AFC-CSO-IMA  Important mail gets a tracked item, triaged with its timeframe
  AFC-CSO-ACK  FedRAMP mail is acknowledged automatically, once
with the designators from AFC-FRP-CDS, the Emergency senders from AFC-FRP-UFS
and the default Class C timeframe from AFC-FRP-ERT.

Every string taken from a message is untrusted: it is length-capped and
stripped of control and bidirectional-override characters before it is stored
or used, and nothing from a message reaches an outbound header except as a
validated address, a validated Message-ID, or base64.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

FEDRAMP_DOMAINS = ("fedramp.gov", "gsa.gov")
EMERGENCY_SENDERS = ("fedramp_security@gsa.gov", "fedramp_security@fedramp.gov")
DESIGNATIONS = ("EMERGENCY", "EMERGENCY_TEST", "IMPORTANT", "GENERAL")
TRIAGE_HOURS = {"EMERGENCY": 2, "EMERGENCY_TEST": 2, "IMPORTANT": 24, "GENERAL": 72}
CLASS_C_BUSINESS_DAYS = 2
CLASS_C_HOUR_ET = 15
VERDICTS = ("PASS", "FAIL", "GRAY", "PROCESSING_FAILED")
MAX_SUBJECT = 200
MAX_ADDRESS = 254
ET = ZoneInfo("America/New_York")

CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
ADDR_SPEC = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")
RFC_MESSAGE_ID = re.compile(r"^<[\x21-\x3b\x3d\x3f-\x7e]{1,250}>$")
ANGLED = re.compile(r"<([^<>\s]+)>")
LABEL = {"EMERGENCY": "EMERGENCY", "EMERGENCY_TEST": "EMERGENCY TEST", "IMPORTANT": "IMPORTANT", "GENERAL": "General"}


def clean_text(value, limit: int = MAX_SUBJECT) -> str:
    """One safe line: no control or bidi characters, whitespace collapsed, capped."""
    s = CONTROL.sub(" ", "" if value is None else str(value))
    return " ".join(s.split())[:limit]


def parse_address(value) -> str | None:
    """The addr-spec in a From-style value, lower-cased, or None."""
    s = clean_text(value, 1000)
    if not s:
        return None
    angled = ANGLED.findall(s)
    candidate = (angled[-1] if angled else s).lower()
    if len(candidate) > MAX_ADDRESS or not ADDR_SPEC.match(candidate):
        return None
    return candidate


def domain_of(address: str | None) -> str | None:
    return address.rsplit("@", 1)[1] if address else None


def is_fedramp_address(address: str | None) -> bool:
    """AFC-CSO-TFG: exact domains only. Subdomains and look-alikes are not FedRAMP."""
    return domain_of(address) in FEDRAMP_DOMAINS


def designation_of(subject) -> str:
    """AFC-FRP-CDS designator anywhere in the subject, any case. Broad on purpose:
    a false Emergency costs a page; a missed one costs the deadline."""
    s = clean_text(subject, 1000).lower()
    if re.search(r"\bemergency[\s_-]*test\b", s):
        return "EMERGENCY_TEST"
    if re.search(r"\bemergency\b", s):
        return "EMERGENCY"
    if re.search(r"\bimportant\b", s):
        return "IMPORTANT"
    return "GENERAL"


def _header(headers, name: str) -> str | None:
    want = name.lower()
    for k, v in (headers or {}).items():
        if isinstance(k, str) and k.lower() == want:
            return clean_text(v, 1000)
    return None


def _verdict(v) -> str:
    s = v.upper() if isinstance(v, str) else "MISSING"
    return s if s in VERDICTS else "MISSING"


def authenticated(auth: dict) -> bool:
    """AFC-FRP-VRE: FedRAMP sends with SPF, DKIM and DMARC configured."""
    return auth["dmarc"] == "PASS" or (auth["dkim"] == "PASS" and auth["spf"] == "PASS")


def loop_reason(headers, source, sender: str | None) -> str | None:
    """Why an automatic reply must not be sent to this message, or None."""
    auto = _header(headers, "auto-submitted")
    if auto and auto.lower() != "no":
        return "auto-submitted"
    if (_header(headers, "precedence") or "").lower() in ("bulk", "junk", "list", "auto_reply"):
        return "precedence"
    src = str(source or "").strip()
    if not src or src == "<>":
        return "null-sender"
    if sender and sender.split("@", 1)[0] in ("mailer-daemon", "postmaster"):
        return "daemon"
    if not sender:
        return "no-from-address"
    return None


def classify(msg: dict) -> dict:
    """Classify one message: {from, envelope, subject, headers, auth}.

    FedRAMP if the From address or the envelope sender is at an exact FedRAMP
    domain. Spam and authentication verdicts are recorded and never change the
    classification. They do stop the acknowledgement: FedRAMP's own mail passes
    SPF/DKIM/DMARC, so suppressing the reply to unauthenticated mail loses
    nothing genuine and stops a forged @gsa.gov From from turning the inbox into
    a reflector that mails attacker-chosen text to any government address.
    """
    sender = parse_address(msg.get("from"))
    envelope = parse_address(msg.get("envelope"))
    subject = clean_text(msg.get("subject"))
    fedramp = is_fedramp_address(sender) or is_fedramp_address(envelope)
    designation = designation_of(subject) if fedramp else "GENERAL"
    raw_auth = msg.get("auth") or {}
    auth = {k: _verdict(raw_auth.get(k)) for k in ("spf", "dkim", "dmarc")}
    authed = authenticated(auth)
    emergency = designation in ("EMERGENCY", "EMERGENCY_TEST")
    mid = _header(msg.get("headers"), "message-id")
    return {
        "kind": "fedramp" if fedramp else "other",
        "from": sender,
        "sender_domain": domain_of(sender if is_fedramp_address(sender) else (envelope or sender)),
        "subject": subject,
        "designation": designation,
        "auth": auth,
        "authenticated": authed,
        "emergency_sender_ok": (sender in EMERGENCY_SENDERS) if emergency else None,
        "rfc_message_id": mid if mid and RFC_MESSAGE_ID.match(mid) else None,
        "loop": loop_reason(msg.get("headers"), msg.get("envelope"), sender) or (None if authed else "unauthenticated"),
    }


# --- deadlines ----------------------------------------------------------------

def parse_time(value: str) -> datetime:
    t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError(f"timestamp without a zone: {value!r}")
    return t.astimezone(timezone.utc)


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def class_c_deadline(received: datetime, business_days: int = CLASS_C_BUSINESS_DAYS,
                     hour_et: int = CLASS_C_HOUR_ET) -> datetime:
    """3:00 p.m. ET on the Nth business day, counting the day of receipt as day 1
    when it is a weekday. That reading of "the 2nd business day" gives the
    earlier of the two possible deadlines, and federal holidays are not skipped,
    which can only make it earlier still. Both err toward acting sooner."""
    day = received.astimezone(ET).date()
    counted = 0
    for _ in range(14):
        if day.weekday() < 5:
            counted += 1
        if counted == business_days:
            return datetime(day.year, day.month, day.day, hour_et, tzinfo=ET).astimezone(timezone.utc)
        day += timedelta(days=1)
    raise RuntimeError("business-day search did not terminate")


def deadlines(designation: str, received: datetime) -> dict:
    triage_by = iso(received + timedelta(hours=TRIAGE_HOURS[designation]))
    if designation in ("EMERGENCY", "EMERGENCY_TEST"):
        return {"triage_by": triage_by, "respond_by": iso(class_c_deadline(received)),
                "deadline_basis": "AFC-FRP-ERT Class C default (3:00 p.m. ET, 2nd business day); "
                                  "replace with the timeframe stated in the message"}
    if designation == "IMPORTANT":
        return {"triage_by": triage_by, "respond_by": None,
                "deadline_basis": "Record the timeframe stated in the message (AFC-CSO-IMA) when triaging"}
    return {"triage_by": triage_by, "respond_by": None,
            "deadline_basis": "General communication: no elevated timeframe (AFC-FRP-CDS)"}


# --- register -------------------------------------------------------------------

def new_record(rid: str, c: dict, received: datetime) -> dict:
    return {"id": rid, "received_at": iso(received), "kind": c["kind"], "sender_domain": c["sender_domain"],
            "subject": c["subject"], "designation": c["designation"], "auth": c["auth"],
            "authenticated": c["authenticated"], "emergency_sender_ok": c["emergency_sender_ok"],
            "status": "open", **deadlines(c["designation"], received),
            "ack": {"status": "pending"}, "page": {"status": "pending"}, "history": []}


def triage(record: dict, at: datetime, respond_by: str | None = None) -> dict:
    """Mark a record triaged. An Important message cannot be triaged without the
    timeframe stated in it (AFC-CSO-IMA); a stated timeframe replaces the default."""
    if record["status"] == "closed":
        raise ValueError(f"{record['id']} is closed")
    if respond_by:
        record["respond_by"] = iso(parse_time(respond_by))
        record["deadline_basis"] = "Timeframe stated in the message, recorded at triage"
    if record["designation"] == "IMPORTANT" and not record.get("respond_by"):
        raise ValueError(f"{record['id']}: an Important message needs the timeframe it states (respond_by)")
    record["status"] = "triaged"
    record["history"].append({"at": iso(at), "event": "triaged"})
    return record


def close(record: dict, at: datetime, outcome: str) -> dict:
    if not clean_text(outcome):
        raise ValueError("closing needs an outcome")
    record["status"] = "closed"
    record["closed_at"] = iso(at)
    record["history"].append({"at": iso(at), "event": "closed", "outcome": clean_text(outcome)})
    return record


def overdue(records, now: datetime) -> list[str]:
    """Problems that should page: untriaged past triage_by, not closed past
    respond_by, Important triaged without its timeframe, ack or page failed."""
    problems = []
    for r in records:
        tag = f"{r['id']} ({r['designation']})"
        if r["status"] == "open" and r.get("triage_by") and now > parse_time(r["triage_by"]):
            problems.append(f"{tag}: not triaged by {r['triage_by']}")
        if r["status"] != "closed" and r.get("respond_by") and now > parse_time(r["respond_by"]):
            problems.append(f"{tag}: required actions not closed by {r['respond_by']}")
        if r["designation"] == "IMPORTANT" and r["status"] != "open" and not r.get("respond_by"):
            problems.append(f"{tag}: triaged without recording the message's timeframe")
        for leg in ("ack", "page"):
            if (r.get(leg) or {}).get("status") == "failed":
                problems.append(f"{tag}: {leg} failed")
    return problems


# --- outbound text ------------------------------------------------------------------

def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def build_ack(*, inbox: str, to: str, subject: str, rfc_message_id: str | None,
              received_at: str, designation: str, ref: str) -> str:
    """The raw acknowledgement (RFC 5322). Every header value is a constant, a
    validated address, a validated Message-ID, or base64, so nothing from the
    inbound message can inject a header."""
    frm, rcpt = parse_address(inbox), parse_address(to)
    if not frm or not rcpt:
        raise ValueError("acknowledgement needs valid From and To addresses")
    subj = clean_text(subject) or "(no subject)"
    lines = [f"From: FedRAMP Security Inbox <{frm}>", f"To: <{rcpt}>",
             f"Subject: =?UTF-8?B?{_b64('Received: ' + subj)}?=",
             "Auto-Submitted: auto-replied", "X-Auto-Response-Suppress: All", "MIME-Version: 1.0",
             "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64"]
    if rfc_message_id and RFC_MESSAGE_ID.match(rfc_message_id):
        lines += [f"In-Reply-To: {rfc_message_id}", f"References: {rfc_message_id}"]
    body = "\n".join([
        f"This is an automatic acknowledgement from the FedRAMP Security Inbox ({frm}).", "",
        f"Your message was received at {clean_text(received_at, 40)}.",
        f"Designation recognised from the subject line: {LABEL.get(designation, 'General')}.",
        f"Reference: {clean_text(ref, 80)}", "",
        "The security official has been notified. This reply is automatic; a person will respond separately."])
    b64 = _b64(body)
    wrapped = "\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    return "\r\n".join(lines) + "\r\n\r\n" + wrapped + "\r\n"


def page_subject(record: dict) -> str:
    """The page's subject: ASCII, at most 100 characters, sender domain only."""
    s = f"[FSI] {LABEL.get(record['designation'], 'General')} FedRAMP message from {record['sender_domain'] or 'unknown'}"
    return re.sub(r"[^\x20-\x7e]", "?", s)[:100]


# --- one message through the inbox ------------------------------------------------------

def receive(msg: dict, register: dict, *, inbox: str, send, page) -> dict:
    """Handle one message the way the inbox would. `send(to, raw)` and
    `page(subject)` are the outbound legs (in the simulation, recorders that
    send nothing). Idempotent: a message already in the register only retries
    the legs that did not complete, so a sender is acknowledged once."""
    c = classify(msg)
    if c["kind"] != "fedramp":
        return {"classification": c, "record": None}
    rid = clean_text(msg.get("message_id"), 128)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", rid):
        raise ValueError("message_id must be a safe register identifier")
    received = parse_time(msg["received_at"])
    record = register.get(rid) or new_record(rid, c, received)
    register[rid] = record
    if record["ack"]["status"] in ("pending", "failed"):
        if c["loop"]:
            record["ack"] = {"status": "suppressed", "reason": c["loop"]}
        else:
            try:
                send(c["from"], build_ack(inbox=inbox, to=c["from"], subject=c["subject"],
                                          rfc_message_id=c["rfc_message_id"], received_at=record["received_at"],
                                          designation=c["designation"], ref=rid))
                record["ack"] = {"status": "sent"}
            except Exception as e:  # noqa: BLE001 - a failed leg is recorded and paged by overdue()
                record["ack"] = {"status": "failed", "error": type(e).__name__}
    if record["page"]["status"] != "sent":
        page(page_subject(record))
        record["page"] = {"status": "sent"}
    return {"classification": c, "record": record}
