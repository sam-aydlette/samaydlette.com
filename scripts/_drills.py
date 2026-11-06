"""The drills: four reviews a person would run, built as checks over the
system's own data and run on their dates against a plainly simulated cast
(DEC-194, DEC-195). Each would work unchanged with real people or real events;
each feeds a planted bad case through the same check on every run, and a drill
whose planted case is not caught fails.

  board-meeting     The Board of Sam (quorum: 1), quarterly (KSI-PIY-RES):
                    minutes generated from the quarter's decisions. Every in-force
                    risk acceptance must be endorsed at a meeting held on or after
                    the day it was decided; the board refuses one past its review
                    date. Planted: an acceptance left off the agenda.
  cfo-review        The CFO (also Sam), quarterly (KSI-PIY-RIS): every mechanism in
                    infrastructure/schemas/ksi-methods.json is funded by a line of
                    data/recurring-costs.json (its `funds`), and the known total is
                    within the stated ceiling. Planted: an unfunded mechanism.
  tabletop          Choose-Your-Own-Disaster, monthly (KSI-INR-RIR, KSI-RPL-ARP,
                    KSI-INR-AAR): every card in the deck maps each required step to
                    a section of docs/incident-response.md or docs/recovery-plan.md,
                    and the plan states its recovery objectives. Dee Saster injects,
                    Bea Kupp commands. The after-action report's lessons go through
                    the register's lessons check (scripts/_incidents.py). Planted:
                    "Alien Invasion of us-east-1", which no runbook covers, and its
                    orphan lesson.
  disclosure-drill  Ima Finder files a report through the documented intake
                    (KSI-PIY-RVD); the intake parses it like a real report, opens a
                    finding and starts the acknowledgement clock. Planted: a report
                    with no reproduction steps, triaged to "needs info".

The phishing drill (KSI-CED-RAT) is scripts/_phishing.py. scripts/hold-drill.py
runs them all from the evidence nightly. Stdlib only.
"""

import re
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bizdays  # noqa: E402
import _incidents  # noqa: E402
import _scheduled_review as sr  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def check(cid, title, ok, detail):
    return {"id": cid, "title": title, "result": "pass" if ok else "fail", "detail": detail}


# --- The Board of Sam (KSI-PIY-RES) -----------------------------------------------------

ACCEPTANCES = ("accepted", "risk-accepted")
FORGOTTEN = {"id": "DEC-PLANTED-BOARD", "title": "Accept that the office coffee machine is a single point of "
                                                 "failure (planted, simulated)", "disposition": "risk-accepted"}


def acceptances(in_force):
    """The in-force risk acceptances: [{id, title, decided_on, review_by}]."""
    return [{k: r.get(k) for k in ("id", "title", "decided_on", "review_by")}
            for r in sorted(in_force, key=lambda r: r["id"]) if r.get("disposition") in ACCEPTANCES]


def _key(a):
    return f"{a['id']}@{a['decided_on']}"


def endorse(accepts, meeting, endorsed):
    """The board's vote: each acceptance decided on or before `meeting` and not
    yet endorsed (by id and decision date) is endorsed, unless it is past its
    review date, which the board refuses. Returns (endorsements, refusals)."""
    new, refused = [], []
    for a in accepts:
        if str(a["decided_on"]) > meeting.isoformat() or _key(a) in endorsed:
            continue
        if str(a.get("review_by") or "") < meeting.isoformat():
            refused.append({"decision": a["id"], "reason": f"past its review date {a.get('review_by')}"})
        else:
            new.append({"decision": a["id"], "decidedOn": a["decided_on"], "endorsedAt": meeting.isoformat(),
                        "by": sr.CAST["board"]})
    return new, refused


def endorsement_gaps(accepts, endorsements, meeting):
    """IDs of the acceptances decided on or before `meeting` with no endorsement
    at a meeting held on or after the day they were decided."""
    ok = {f"{e['decision']}@{e['decidedOn']}" for e in endorsements if str(e["endorsedAt"]) >= str(e["decidedOn"])}
    return [a["id"] for a in accepts if str(a["decided_on"]) <= meeting.isoformat() and _key(a) not in ok]


def board_meeting(due, in_force, decisions, previous_endorsements, since):
    """(checks, record) for one meeting. `decisions` is every record (for the
    minutes); `since` the previous meeting's date (or None)."""
    accepts = acceptances(in_force)
    carried = {f"{e['decision']}@{e['decidedOn']}" for e in previous_endorsements}
    new, refused = endorse(accepts, due, carried)
    every = list(previous_endorsements) + new
    gaps = endorsement_gaps(accepts, every, due)
    planted = dict(FORGOTTEN, decided_on=(due - timedelta(days=1)).isoformat(),
                   review_by=(due + timedelta(days=365)).isoformat())
    caught = endorsement_gaps([planted], every, due) == [planted["id"]]
    quarter = [r for r in decisions if (since is None or str(r.get("decided_on")) > since.isoformat())
               and str(r.get("decided_on")) <= due.isoformat()]
    board = sr.CAST["board"]
    minutes = [{"speaker": board, "line": "The Board of Sam is called to order. Quorum is one. Quorum is present."},
               {"speaker": board, "line": f"{len(quarter)} decision(s) were recorded since the last meeting; the "
                                          f"board has read all of them, which took one of us no time at all."}]
    for e in new:
        minutes.append({"speaker": board, "line": f"Moved, seconded (by the same person) and carried: {e['decision']} "
                                                  "is endorsed. Executive support is hereby demonstrated."})
    for r in refused:
        minutes.append({"speaker": board, "line": f"{r['decision']} is not endorsed: {r['reason']}. Renew it in "
                                                  "a pull request."})
    minutes.append({"speaker": board, "line": "There being no other business, and no other members, the meeting "
                                              "is adjourned."})
    checks = [
        check("endorsements", "Every in-force risk acceptance was endorsed at a meeting held on or after the day it "
                              "was decided (KSI-PIY-RES)", not gaps and not refused,
              f"{len(accepts)} in-force acceptance(s); endorsed this meeting: {len(new)}"
              + (f"; not endorsed: {', '.join(gaps)}" if gaps else "")
              + (f"; refused: {', '.join(r['decision'] for r in refused)}" if refused else "")),
        check("planted-forgotten-acceptance", "The planted acceptance left off the agenda is found unendorsed",
              caught, f"{planted['id']} ({planted['title']}) {'flagged' if caught else 'MISSED'}"),
    ]
    record = {"board": board, "quorum": 1, "decisionsThisQuarter": [r["id"] for r in quarter],
              "acceptances": accepts, "endorsed": new, "refused": refused, "minutes": minutes,
              "planted": {"acceptance": planted, "caught": caught}}
    return checks, record, every


# --- The CFO (KSI-PIY-RIS) -------------------------------------------------------------

UNFUNDED = {"key": "quantum-vibe-check", "mechanism": "Quantum Vibe Check (planted, simulated): a mechanism nobody "
                                                     "budgeted for"}


def funding(methods, costs):
    """{method key: [cost line ids that fund it]} and the unfunded keys."""
    funded = {}
    for line in costs["lines"]:
        for k in line.get("funds") or []:
            funded.setdefault(k, []).append(line["id"])
    keys = [m["key"] for m in methods]
    return {k: sorted(funded.get(k, [])) for k in keys}, [k for k in keys if not funded.get(k)]


def cfo_review(methods_doc, costs):
    ceiling = costs.get("ceiling") or {}
    limit = ceiling.get("usd_per_year")
    by_method, unfunded = funding(methods_doc["methods"], costs)
    _, planted = funding([*methods_doc["methods"], UNFUNDED], costs)
    caught = planted == [*unfunded, UNFUNDED["key"]]
    known = [x for x in costs["lines"] if x["estimate_usd_per_year"] is not None]
    total = round(sum(x["estimate_usd_per_year"] for x in known), 2)
    unpriced = sorted({lid for ids in by_method.values() for lid in ids
                       for x in costs["lines"] if x["id"] == lid and x["estimate_usd_per_year"] is None})
    within = isinstance(limit, (int, float)) and not isinstance(limit, bool) and total <= limit
    cfo = sr.CAST["cfo"]
    checks = [
        check("funded", "Every automated method in infrastructure/schemas/ksi-methods.json is funded by a line of "
                        "data/recurring-costs.json (KSI-PIY-RIS)", not unfunded,
              f"{len(by_method)} method(s); unfunded: {', '.join(unfunded) or 'none'}"
              + (f"; funded by a line with no figure yet: {', '.join(unpriced)}" if unpriced else "")),
        check("ceiling", "The known recurring cost is within the stated ceiling", within,
              f"${total}/year over {len(known)} priced line(s) against a ceiling of "
              + (f"${limit}/year" if limit is not None else "none stated")),
        check("planted-unfunded", "The planted unfunded mechanism is refused", caught,
              f"{UNFUNDED['key']} {'refused' if caught else 'MISSED'}"),
    ]
    record = {"cfo": cfo, "fundedBy": by_method, "unpricedLines": unpriced, "knownUsdPerYear": total,
              "ceiling": ceiling, "costsStatus": costs.get("status"),
              "remarks": [{"speaker": cfo, "line": "Every mechanism has a line. Most of them say zero dollars, which "
                                                  "is my favourite number." if not unfunded else
                           "Some mechanisms have no budget line. Denied, pending a pull request."},
                          {"speaker": cfo, "line": f"I also reviewed {UNFUNDED['mechanism']}. Denied."}],
              "planted": {"mechanism": UNFUNDED, "caught": caught}}
    return checks, record


# --- Choose-Your-Own-Disaster tabletop (KSI-INR-RIR, KSI-RPL-ARP, KSI-INR-AAR) ----------

IR_DOC = "docs/incident-response.md"
PLAN_DOC = "docs/recovery-plan.md"
# The deck: each card names the runbook entry that must cover it. Incident cards
# are covered by a containment entry of the incident response runbook; loss cards
# by a loss scenario of the recovery plan with its recovery stated.
DECK = [
    {"card": "Credential compromise (AWS)", "kind": "incident", "covered_by": "Credential compromise (AWS)"},
    {"card": "Credential compromise (GitHub)", "kind": "incident", "covered_by": "Credential compromise (GitHub)"},
    {"card": "Content compromise", "kind": "incident", "covered_by": "Content compromise"},
    {"card": "Supply-chain compromise", "kind": "incident", "covered_by": "Supply-chain compromise"},
    {"card": sr.SCENARIOS["big-one"], "kind": "incident", "covered_by": "Content compromise"},
    {"card": "Total loss of the AWS account", "kind": "loss", "covered_by": "Total loss of the AWS account"},
    {"card": "Loss of the S3 bucket only", "kind": "loss", "covered_by": "Loss of the S3 bucket only"},
    {"card": "Loss of the GitHub repository", "kind": "loss", "covered_by": "Loss of the GitHub repository"},
    {"card": "Loss of the deployer credentials", "kind": "loss", "covered_by": "Loss of the deployer credentials"},
    {"card": "Loss of the domain", "kind": "loss", "covered_by": "Loss of the domain"},
]
ALIEN = {"card": "Alien Invasion of us-east-1 (planted, simulated)", "kind": "loss",
         "covered_by": "Loss of us-east-1 to extraterrestrials"}
ALIEN_LESSON = {"lesson": "Write a runbook for extraterrestrial loss of a region (planted orphan lesson)",
                "link": "DEC-000"}
AAR_TEST = "tests/test_drills.py::test_every_real_tabletop_card_maps_each_step_to_a_runbook_section"


def _section(text, heading):
    i = text.find(heading)
    if i < 0:
        return ""
    j = text.find("\n## ", i + 1)
    return text[i:j if j > 0 else None]


def plan_scenarios(plan_text):
    """{scenario: stated recovery} from the plan's in-scope loss scenarios."""
    m = re.search(r"In-scope loss scenarios:\s*\n((?:\s*- .+\n?)+)", plan_text)
    out = {}
    for line in (m.group(1).splitlines() if m else []):
        what, _, how = line.strip()[2:].partition(" — ")
        out[what.strip()] = how.strip()
    return out


def containment_entries(ir_text):
    """The labels of the runbook's containment entries ("- **<label>:** ...")."""
    sec = ir_text[ir_text.find("**Contain.**"):ir_text.find("**Eradicate.**")] if "**Contain.**" in ir_text else ""
    return set(re.findall(r"^\s*- \*\*(.+?):\*\*", sec, re.M))


def map_steps(card, ir_text, plan_text):
    """[{step, section}] for one card; section None where no runbook covers the step."""
    def where(ok, ref):
        return ref if ok else None
    if card["kind"] == "incident":
        steps = [("detect", where(bool(_section(ir_text, "## Detection")), f"{IR_DOC}#detection")),
                 ("evaluate reportability", where("Record and evaluate FedRAMP reportability" in ir_text,
                                                  f"{IR_DOC}#triage-and-response-procedures")),
                 ("contain", where(card["covered_by"] in containment_entries(ir_text),
                                   f"{IR_DOC}#triage-and-response-procedures ({card['covered_by']})")),
                 ("recover", where("**Recover.**" in ir_text, f"{IR_DOC}#triage-and-response-procedures")),
                 ("after-action", where(bool(_section(ir_text, "## After-action reports")),
                                        f"{IR_DOC}#after-action-reports-ksi-inr-aar"))]
    else:
        stated = plan_scenarios(plan_text).get(card["covered_by"])
        steps = [("recover", where(bool(stated), f"{PLAN_DOC}#scope ({card['covered_by']}: {stated})")),
                 ("procedure", where(bool(_section(plan_text, "## Recovery procedure")),
                                     f"{PLAN_DOC}#recovery-procedure")),
                 ("objectives", where("Recovery Time Objective" in plan_text and "Recovery Point Objective"
                                      in plan_text, f"{PLAN_DOC} (RTO and RPO)"))]
    return [{"step": s, "section": ref} for s, ref in steps]


def draw(due, deck=DECK):
    """The featured card: Dee Saster draws in order, one a month."""
    return deck[(due.year * 12 + due.month) % len(deck)]


def tabletop(due, ir_text, plan_text, decisions, repo=REPO):
    walked = [{"card": c["card"], "kind": c["kind"], "steps": map_steps(c, ir_text, plan_text)} for c in DECK]
    gaps = [f"{w['card']}: {s['step']}" for w in walked for s in w["steps"] if s["section"] is None]
    alien = map_steps(ALIEN, ir_text, plan_text)
    alien_caught = any(s["section"] is None for s in alien)
    featured = draw(due)
    aar = {"scenario": featured["card"], "lessons": [
        {"lesson": f"{featured['card']} is covered by '{featured['covered_by']}' and each of its steps maps to a "
                   "runbook section; the tabletop walks it again next month.", "link": AAR_TEST}]}
    aar_problems = _incidents.lesson_problems(aar["lessons"], decisions, repo)
    orphan = _incidents.lesson_problems([ALIEN_LESSON], decisions, repo)
    ic, inj = sr.CAST["incident-commander"], sr.CAST["scenario-injector"]
    transcript = [
        {"speaker": ic, "line": "Welcome to Choose-Your-Own-Disaster. You are the on-call engineer. You are also the "
                                "only engineer."},
        {"speaker": inj, "line": f"This month's card: {featured['card']}. If you open the runbook, turn to "
                                 f"'{featured['covered_by']}'. If you panic, turn to page 404."},
    ]
    for s in next(w for w in walked if w["card"] == featured["card"])["steps"]:
        transcript.append({"speaker": ic, "line": f"Step '{s['step']}': " + (f"see {s['section']}." if s["section"]
                                                                            else "the runbook does not say.")})
    transcript += [
        {"speaker": inj, "line": f"Plot twist: {ALIEN['card']}. They have read the Terraform."},
        {"speaker": ic, "line": "No runbook covers that. Minuted as a gap, as it is every month, on purpose."},
        {"speaker": ic, "line": f"The rest of the deck ({len(DECK) - 1} card(s)) was walked as well. Adjourned."},
    ]
    checks = [
        check("deck", "Every card in the deck maps each required step to a section of the incident response runbook "
                      "or the recovery plan, and the plan states its recovery objectives (KSI-INR-RIR, KSI-RPL-ARP)",
              not gaps, f"{len(DECK)} card(s) walked" + (f"; unmapped: {', '.join(gaps)}" if gaps else "")),
        check("after-action", "The after-action report's lessons each link to a decision, commit or test that "
                              "exists (KSI-INR-AAR, the register's lessons check)", not aar_problems,
              f"{len(aar['lessons'])} lesson(s)" + (f"; {'; '.join(aar_problems)}" if aar_problems else "")),
        check("planted-alien", "The planted card no runbook covers is flagged, and its orphan lesson caught",
              alien_caught and len(orphan) == 1,
              f"{ALIEN['card']}: {'flagged' if alien_caught else 'MISSED'}; orphan lesson "
              f"{'caught' if len(orphan) == 1 else 'MISSED'}"),
    ]
    record = {"participants": [ic, inj], "featured": featured, "deck": walked, "afterAction": aar,
              "transcript": transcript,
              "planted": {"card": ALIEN, "steps": alien, "caught": alien_caught, "orphanLesson": ALIEN_LESSON,
                          "orphanCaught": len(orphan) == 1}}
    return checks, record


# --- The disclosure drill (KSI-PIY-RVD) -------------------------------------------------

INTAKE_FIELDS = ("Summary", "Affected", "Steps to reproduce", "Impact")
OPTIONAL_FIELDS = ("Reporter",)
ACK_BUSINESS_DAYS = 3
IN_SCOPE_HOST = "samaydlette.com"
_FIELD_RE = re.compile(r"^(" + "|".join(re.escape(f) for f in (*INTAKE_FIELDS, *OPTIONAL_FIELDS)) + r")\s*:\s*(.*)$",
                       re.I)


def ima_report():
    r = sr.CAST["researcher"]
    return (f"Summary: The favicon is insufficiently threatening.\n"
            f"Affected: https://samaydlette.com/favicon.ico\n"
            f"Steps to reproduce:\n1. Open https://samaydlette.com/ in any browser.\n2. Look at the tab.\n"
            f"3. Feel no fear whatsoever.\n"
            f"Impact: Adversaries may fail to take the site seriously. So may everyone else.\n"
            f"Reporter: {r}\n")


def planted_report():
    """The planted incomplete report: no reproduction steps."""
    return (f"Summary: Something about the footer feels exploitable.\n"
            f"Affected: https://samaydlette.com/\n"
            f"Impact: Unclear, but vibes-based.\n"
            f"Reporter: {sr.CAST['researcher']} (planted)\n")


def parse_report(text):
    """{field: value} from a report in the intake format ("Field: value", a
    field's value running on until the next field)."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = _FIELD_RE.match(line.strip())
        if m:
            cur = next(f for f in (*INTAKE_FIELDS, *OPTIONAL_FIELDS) if f.lower() == m.group(1).lower())
            out[cur] = m.group(2).strip()
        elif cur and line.strip():
            out[cur] = (out[cur] + "\n" + line.strip()).strip()
    return out


def intake(text, received, seq):
    """Triage one report: accepted (a finding opened, its acknowledgement clock
    started), needs-info (fields missing) or out-of-scope."""
    rep = parse_report(text)
    missing = [f for f in INTAKE_FIELDS if not rep.get(f)]
    ack_by = _bizdays.add_business_days(received.date(), ACK_BUSINESS_DAYS)
    out = {"receivedAt": received.isoformat(), "report": rep, "missing": missing,
           "acknowledgeBy": ack_by.isoformat()}
    if missing:
        return {**out, "triage": "needs-info", "finding": None,
                "reply": f"Thank you. Before triage we need: {', '.join(missing)}."}
    host = re.match(r"^https://([^/\s]+)", rep["Affected"])
    if not host or host.group(1).lower() != IN_SCOPE_HOST:
        return {**out, "triage": "out-of-scope", "finding": None,
                "reply": "Thank you. The affected resource is not part of this system."}
    tid = f"DISC-{received.date().isoformat()}-{seq}"
    finding = {"tracking_id": tid, "source": "disclosure", "title": rep["Summary"], "resource": rep["Affected"],
               "detected_at": received.isoformat(), "acknowledgeBy": ack_by.isoformat(), "status": "open"}
    return {**out, "triage": "accepted", "finding": finding,
            "reply": f"Thank you. Your report is {tid}; we will acknowledge it by {ack_by.isoformat()}."}


def disclosure_drill(now, security_txt, ir_text):
    received = now
    ima = intake(ima_report(), received, 1)
    planted = intake(planted_report(), received, 2)
    acked_at = received + timedelta(minutes=5)
    acked = ima["finding"] is not None and acked_at.date() <= date.fromisoformat(ima["acknowledgeBy"])
    if ima["finding"]:
        ima["finding"].update(acknowledgedAt=acked_at.isoformat(), status="closed",
                              resolution="Won't fix: the favicon remains unthreatening by design (simulated).")
    fields = dict(re.findall(r"^([A-Za-z-]+):\s*(\S.*)$", security_txt or "", re.M))
    documented = "## Vulnerability disclosure intake" in ir_text and all(f in ir_text for f in INTAKE_FIELDS)
    checks = [
        check("intake", "A complete report is parsed, triaged accepted, opens a finding and is acknowledged inside its "
                        f"{ACK_BUSINESS_DAYS}-business-day clock (KSI-PIY-RVD)", ima["triage"] == "accepted" and acked,
              f"{sr.CAST['researcher']}'s report: {ima['triage']}"
              + (f", {ima['finding']['tracking_id']} acknowledged by {ima['acknowledgeBy']}" if ima["finding"] else "")),
        check("documented", "The intake format and clock are documented, and security.txt points reporters to a "
                            "contact and the policy", documented and bool(fields.get("Contact"))
              and bool(fields.get("Policy")),
              f"{IR_DOC} documents the intake: {documented}; security.txt Contact and Policy: "
              f"{bool(fields.get('Contact'))} and {bool(fields.get('Policy'))}"),
        check("planted-incomplete", "The planted report with no reproduction steps is triaged to needs-info and opens "
                                    "no finding", planted["triage"] == "needs-info" and planted["finding"] is None
              and "Steps to reproduce" in planted["missing"],
              f"planted report: {planted['triage']}, missing {', '.join(planted['missing']) or 'nothing'}"),
    ]
    record = {"researcher": sr.CAST["researcher"], "intakeFields": list(INTAKE_FIELDS),
              "acknowledgementBusinessDays": ACK_BUSINESS_DAYS, "reports": [ima], "planted": planted,
              "deliveredTo": "nobody: the reporter is simulated; replies are recorded here, never sent"}
    return checks, record
