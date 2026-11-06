"""The phishing drill (KSI-CED-RAT): a lure, a responder and a real scorer.

Monthly, from the evidence nightly (scripts/hold-drill.py). The Prince of
Compliance (simulated) sends "URGENT: your FedRAMP ID has expired". Nothing is
sent anywhere: the lure is a record, the sender's domain is under the reserved
.example top-level domain, and the message never leaves this file.

  lure        the message, built here, with the indicators a trainee should see
  indicators  detect(): the rules that find each indicator in a message, run on
              the lure and on a benign control message (which must show none)
  responder   Pat Placeholder (simulated) reports the lure, except every
              CLICK_EVERY-th drill, when Pat clicks (the scripts/_training.py
              MISS_EVERY pattern), so the scorer has something to grade
  scorer      grade(): a report passes; a click fails and assigns the remedial
              lesson, which is a core lesson of the training packet
              (scripts/_training.py CORE), so the next packet carries it

A planted click is graded on every run and must fail with the remedial lesson
assigned, or the drill fails. Stdlib only.
"""

import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _scheduled_review as sr  # noqa: E402
import _training  # noqa: E402

TRUSTED_DOMAINS = ("samaydlette.com", "fedramp.gov", "gsa.gov")
CLICK_EVERY = 4
REMEDIAL_AREA = "phishing"
INDICATORS = {
    "impersonated-authority": "Claims to be FedRAMP, from a domain that is not FedRAMP's",
    "lookalike-sender": "The sender's domain imitates a trusted one",
    "reply-to-mismatch": "Replies go to a different domain than the sender's",
    "link-mismatch": "The link text shows one address and goes to another",
    "urgency": "Manufactured urgency or a deadline",
    "credential-request": "Asks for a password, an MFA code or credentials",
    "generic-greeting": "A greeting that does not name the recipient",
}
PASS_MARK = 5   # indicators the rules must find in the lure


def lure():
    return {"from": {"display": f"FedRAMP PMO Renewals ({sr.CAST['phisher']})",
                     "domain": "fedramp-renewals.example"},
            "replyToDomain": "prince-of-compliance.example",
            "subject": "URGENT: your FedRAMP ID has expired",
            "greeting": "Dear Valued Cloud Service Provider,",
            "body": "Your FedRAMP ID expired at midnight. To avoid immediate removal from the FedRAMP Marketplace, "
                    "confirm your password and MFA code within 24 hours using the secure link below. "
                    "Regally yours, the Prince of Compliance.",
            "link": {"text": "https://fedramp.gov/renew", "href": "https://fedramp-renewals.example/renew"}}


def control():
    """A benign message, from the system itself, that must show no indicator."""
    return {"from": {"display": "samaydlette.com evidence nightly", "domain": "samaydlette.com"},
            "replyToDomain": "samaydlette.com", "subject": "Nightly evidence refresh completed",
            "greeting": "Hello Sam,", "body": "The evidence nightly finished. Nothing needs your attention.",
            "link": {"text": "https://samaydlette.com/trust/", "href": "https://samaydlette.com/trust/"}}


def _host(url):
    return (urlsplit(url).hostname or "").lower()


def _trusted(domain):
    d = (domain or "").lower()
    return any(d == t or d.endswith("." + t) for t in TRUSTED_DOMAINS)


def detect(msg):
    """The indicator ids found in a message, by rule."""
    sender = msg["from"]["domain"].lower()
    text = " ".join([msg["subject"], msg["greeting"], msg["body"], msg["from"]["display"]])
    found = []
    if re.search(r"\bFedRAMP\b", msg["from"]["display"]) and not _trusted(sender):
        found.append("impersonated-authority")
    if not _trusted(sender) and any(t.split(".")[0] in sender for t in TRUSTED_DOMAINS):
        found.append("lookalike-sender")
    if (msg.get("replyToDomain") or sender).lower() != sender:
        found.append("reply-to-mismatch")
    if _host(msg["link"]["text"]) and _host(msg["link"]["text"]) != _host(msg["link"]["href"]):
        found.append("link-mismatch")
    if re.search(r"\b(urgent|immediate(ly)?|within \d+ hours|expire[ds]?|final notice)\b", text, re.I):
        found.append("urgency")
    if re.search(r"\b(password|MFA code|credentials?|one-time code)\b", text, re.I):
        found.append("credential-request")
    if re.search(r"^dear (valued|customer|user|sir|madam|cloud service provider)", msg["greeting"].strip(), re.I):
        found.append("generic-greeting")
    return found


def respond(n):
    """Pat Placeholder's response to drill number n (1-based)."""
    return "clicked" if n % CLICK_EVERY == 0 else "reported"


def remedial_lesson():
    """The core training lesson a click assigns (scripts/_training.py CORE)."""
    for i, (area, question, answer) in enumerate(_training.CORE):
        if area == REMEDIAL_AREA:
            return {"covers": f"core:{i}", "question": question, "answer": answer}
    return None


def grade(response, indicators):
    if response == "reported":
        return {"grade": "pass", "remedial": None, "remark": "Reported without clicking. The Prince is disappointed."}
    return {"grade": "fail", "remedial": remedial_lesson(),
            "remark": f"Clicked, despite {len(indicators)} indicator(s). Remedial lesson assigned; the next "
                      "training packet carries it."}


def drill(n):
    """(checks, record) for drill number n."""
    msg, ok_msg = lure(), control()
    found, false_pos = detect(msg), detect(ok_msg)
    response = respond(n)
    result = grade(response, found)
    planted = grade("clicked", found)
    lesson = remedial_lesson()

    def chk(cid, title, ok, detail):
        return {"id": cid, "title": title, "result": "pass" if ok else "fail", "detail": detail}

    checks = [
        chk("indicators", "The rules find the lure's indicators and none in the benign control message",
            len(found) >= PASS_MARK and not false_pos,
            f"{len(found)} of {len(INDICATORS)} indicator(s) found ({', '.join(found)}); control message: "
            f"{', '.join(false_pos) or 'none'}"),
        chk("graded", "The trainee's response is graded, and a click assigns the remedial lesson into the training "
                      "packet (KSI-CED-RAT)",
            result["grade"] in ("pass", "fail") and (response == "reported" or result["remedial"] is not None),
            f"{_training.TRAINEE} {response}: {result['grade']}"
            + (f"; remedial lesson {result['remedial']['covers']}" if result["remedial"] else "")),
        chk("planted-click", "The planted click is graded a fail with the remedial lesson assigned",
            planted["grade"] == "fail" and lesson is not None and planted["remedial"] == lesson,
            "planted click: " + planted["grade"] + (f", remedial {lesson['covers']}" if lesson else
                                                   ", no remedial lesson in the training packet")),
    ]
    record = {"phisher": sr.CAST["phisher"], "trainee": _training.TRAINEE, "drillNumber": n,
              "lure": msg, "indicators": {k: INDICATORS[k] for k in found}, "controlMessage": ok_msg,
              "response": response, "grade": result, "clickEvery": CLICK_EVERY,
              "planted": {"response": "clicked", "grade": planted},
              "deliveredTo": "nobody: the lure is a record in this file; no message was sent"}
    return checks, record
