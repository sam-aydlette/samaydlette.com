#!/usr/bin/env python3
"""Run the SIMULATED FedRAMP Security Inbox over committed synthetic messages.

The FedRAMP Security Inbox is simulated for this proof of concept, by the
operator's decision: nothing real is received or sent. This script feeds the
synthetic messages in data/fsi-simulation/messages.json through the inbox logic
(scripts/_fsi.py) with outbound legs that only record what they would have
sent, then checks every observed outcome against the file's "expected" block:

  - classification (AFC-CSO-TFG: exact @fedramp.gov / @gsa.gov, never filtered)
  - designation, Emergency sender, and the default deadlines (AFC-CSO-CRA/EMR/IMA)
  - the acknowledgement (AFC-CSO-ACK): built and header-injection safe when
    sent; suppressed for auto-replies and for mail failing SPF/DKIM/DMARC
  - every FedRAMP message is registered and paged (AFC-CSO-RCV)
  - a failed acknowledgement is recorded and reported, and a retry pass over
    the same messages sends it once and sends nothing twice
  - the triage register: overdue items; an Important message refused triage
    until its stated timeframe is recorded; an Emergency past its deadline
    reported until closed

Any difference exits 1 and writes nothing, which fails the deploy. On success it
writes fedramp-inbox-simulation.json, labelled as a simulation, with sender
domains only (no addresses, no subjects), for the deploy to sign and publish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _offering  # noqa: E402
import _fsi  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ACK_HEADERS = {"from", "to", "subject", "auto-submitted", "x-auto-response-suppress", "mime-version",
               "content-type", "content-transfer-encoding", "in-reply-to", "references"}
NOTICE = ("SIMULATION. The FedRAMP Security Inbox is simulated for this proof of concept, by the operator's "
          "decision: no mail is received and none is sent. Nothing arrived, nothing was acknowledged, and no FedRAMP "
          "staff were paged, emailed or otherwise inconvenienced. These results come from running the inbox logic over "
          "committed synthetic messages on every deploy; a deploy whose results differ from the expected ones fails. "
          "To reach the operator, see 'contact' (spoiler: it is LinkedIn).")
RULES = ["AFC-CSO-INB", "AFC-CSO-TFG", "AFC-CSO-RCV", "AFC-CSO-CRA", "AFC-CSO-EMR", "AFC-CSO-IMA", "AFC-CSO-ACK"]


def ack_problems(raw: str, to: str, subject: str) -> list[str]:
    """Why a built acknowledgement is unsafe or wrong, or []."""
    out = []
    head = raw.split("\r\n\r\n", 1)[0]
    for line in head.split("\r\n"):
        if "\n" in line or "\r" in line or ":" not in line:
            out.append("a header line is malformed")
    msg = Parser(policy=policy.default).parsestr(raw)
    names = [k.lower() for k in msg.keys()]
    if set(names) - ACK_HEADERS:
        out.append(f"unexpected headers {sorted(set(names) - ACK_HEADERS)}")
    if len(names) != len(set(names)):
        out.append("a header appears twice")
    if [ln for ln in head.split("\r\n") if ln.lower().startswith("to:")] != [f"To: <{to}>"]:
        out.append("To is not exactly the sender")
    if str(msg["subject"]) != "Received: " + (subject or "(no subject)"):
        out.append("the subject does not round-trip")
    if msg["auto-submitted"] != "auto-replied":
        out.append("Auto-Submitted: auto-replied is missing")
    return out


def run(doc: dict) -> tuple[list[dict], dict, dict, list[str]]:
    inbox = doc["inbox"]
    register: dict = {}
    sent: list[tuple[str, str]] = []
    pages: list[str] = []
    fail_once = {m["message_id"] for m in doc["messages"] if m.get("simulate_send_failure")}
    current = {"id": None}

    def send(to, raw):  # records only; nothing is sent
        if current["id"] in fail_once:
            fail_once.discard(current["id"])
            raise ConnectionError("simulated send failure")
        sent.append((to, raw))

    page = pages.append
    failures: list[str] = []
    cases = []
    for m in doc["messages"]:
        n_sent, n_pages = len(sent), len(pages)
        current["id"] = m["message_id"]
        res = _fsi.receive(m, register, inbox=inbox, send=send, page=page)
        c, r = res["classification"], res["record"]
        ack = "none"
        in_reply_to = None
        if r:
            ack = r["ack"]["status"] + (f":{r['ack']['reason']}" if r["ack"].get("reason") else "")
        if len(sent) > n_sent:
            to, raw = sent[-1]
            for p in ack_problems(raw, c["from"], c["subject"]):
                failures.append(f"{m['case']}: acknowledgement {p}")
            in_reply_to = "\r\nIn-Reply-To: " in raw
        observed = {"kind": c["kind"], "designation": c["designation"], "sender_domain": c["sender_domain"],
                    "authenticated": c["authenticated"], "emergency_sender_ok": c["emergency_sender_ok"],
                    "ack": ack, "in_reply_to": in_reply_to, "page": len(pages) > n_pages,
                    "triage_by": r["triage_by"] if r else None, "respond_by": r["respond_by"] if r else None}
        # AFC-CSO-RCV: nothing FedRAMP is dropped: every FedRAMP message is
        # registered and paged, whatever its verdicts.
        if c["kind"] == "fedramp" and not (r and observed["page"]):
            failures.append(f"{m['case']}: a FedRAMP message was not registered and paged")
        diffs = sorted(k for k, v in m["expected"].items() if observed.get(k) != v)
        diffs += sorted(set(observed) - set(m["expected"]))
        for k in diffs:
            failures.append(f"{m['case']}: {k} expected {m['expected'].get(k)!r}, observed {observed.get(k)!r}")
        cases.append({"case": m["case"], "description": m["description"], "received_at": m["received_at"],
                      "auth": c["auth"], "observed": observed, "matches_expected": not diffs})

    rc = doc["register_check"]
    checks: list[dict] = []

    def check(name, expected, observed):
        checks.append({"check": name, "expected": expected, "observed": observed, "ok": expected == observed})
        if expected != observed:
            failures.append(f"register: {name}: expected {expected!r}, observed {observed!r}")

    def overdue_ids(at):
        return sorted({p.split(" ", 1)[0] for p in _fsi.overdue(register.values(), at)})

    def reported(rid, at, needle):
        return any(p.startswith(rid + " ") and needle in p for p in _fsi.overdue(register.values(), at))

    now = _fsi.parse_time(rc["now"])
    check(f"items overdue at {rc['now']} (untriaged Emergencies, a failed acknowledgement)",
          sorted(rc["expected_overdue"]), overdue_ids(now))

    # Retry: the same messages again (a redelivery or a retried invocation).
    before = (len(sent), len(pages))
    for m in doc["messages"]:
        current["id"] = m["message_id"]
        _fsi.receive(m, register, inbox=inbox, send=send, page=page)
    retry = {"acknowledgements_sent_again": len(sent) - before[0], "pages_sent_again": len(pages) - before[1]}
    check("retry pass: only the failed acknowledgement is sent again, nothing twice", rc["expected_retry"], retry)
    failed_ids = [m["message_id"] for m in doc["messages"] if m.get("simulate_send_failure")]
    check("failed acknowledgements are sent on the retry",
          ["sent"] * len(failed_ids), [register[i]["ack"]["status"] for i in failed_ids])
    check("a failed acknowledgement, once sent, is no longer overdue",
          False, any(reported(i, now, "ack failed") for i in failed_ids))

    # AFC-CSO-IMA: an Important message cannot be triaged without its timeframe.
    imp = register[rc["important_case"]]
    try:
        _fsi.triage(imp, now)
        refused = False
    except ValueError:
        refused = True
    check("Important triage without the message's timeframe is refused", True, refused)
    _fsi.triage(imp, now, respond_by=rc["important_respond_by"])
    check("Important triage records the message's timeframe", rc["important_respond_by"], imp["respond_by"])
    later = _fsi.parse_time(rc["later"])
    check("an Important message untriaged after 24 hours is reported", True,
          reported(rc["untriaged_important_case"], later, "not triaged"))
    forced = dict(imp, id="sim-forced-state", status="triaged", respond_by=None, history=[])
    check("an Important item triaged without a timeframe is reported", True,
          any("timeframe" in p for p in _fsi.overdue([forced], now)))

    # AFC-CSO-CRA: an Emergency past its deadline and not closed is reported;
    # closing it clears the report.
    em = register[rc["emergency_case"]]
    _fsi.triage(em, now)
    check("a triaged Emergency is no longer reported as untriaged", False, reported(em["id"], now, "not triaged"))
    check("an Emergency past its deadline and not closed is reported", True,
          reported(em["id"], later, "not closed"))
    _fsi.close(em, later, "required actions completed (simulated)")
    check("closing the Emergency clears the report", False, reported(em["id"], later, "not closed"))

    register_check = {"now": rc["now"], "later": rc["later"], "checks": checks}
    return cases, retry, register_check, failures


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--messages", type=Path, default=REPO / "data" / "fsi-simulation" / "messages.json")
    ap.add_argument("--offering", type=Path, default=REPO / "data" / "cds" / "offering.json")
    ap.add_argument("--output", type=Path, default=Path("fedramp-inbox-simulation.json"))
    a = ap.parse_args(argv)
    raw = a.messages.read_bytes()
    doc = json.loads(raw)
    cases, retry, register_check, failures = run(doc)
    for f in failures:
        print(f"::error::FedRAMP Security Inbox simulation: {f}")
    if failures:
        print(f"FedRAMP Security Inbox simulation: {len(failures)} outcome(s) differ from expected; nothing written")
        return 1
    contact = ((json.loads(a.offering.read_text()).get("fedramp_security_inbox") or {}).get("contact"))
    sha = os.environ.get("GITHUB_SHA", "")
    report = {
        "report_type": "fedramp-inbox-simulation",
        "simulation": True,
        "notice": NOTICE,
        "engagement": _engagement.STATEMENT,
        "contact": contact,
        "emitted_at": datetime.now(timezone.utc).isoformat(),
        "commit": sha if len(sha) == 40 and all(ch in "0123456789abcdef" for ch in sha) else None,
        "logic": "scripts/_fsi.py",
        "input": "data/fsi-simulation/messages.json",
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "rules_exercised": RULES,
        "result": "pass",
        "cases": cases,
        "retry_pass": retry,
        "register_check": register_check,
    }
    report = _offering.stamp_fedramp_id(report, a.offering)  # CDS-CSO-FID
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"FedRAMP Security Inbox simulation: {len(cases)} synthetic messages, all outcomes as expected; "
          f"wrote {a.output} (SIMULATION: nothing received or sent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
