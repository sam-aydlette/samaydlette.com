"""Security training, automated and completed by a simulated trainee (KSI-CED-RAT).

The operator does not sit an annual training course for this proof of concept,
and no record commits him to one. What a real program needs is built here as
code that would work with a real person, and it is exercised on every build of
the Security Decision Record against a plainly simulated trainee:

  packet      the training packet, generated from the system's own data: a
              lesson for every decision made in the last 12 months, every
              incident and exercise, the applicable FedRAMP rules and KSIs, and
              a fixed core (general security, the privileged roles, secure
              delivery, incident response and recovery: docs/training-log.md's
              areas, plus the phishing drill's remedial lesson). Each lesson
              carries a question.
  quiz        four choices per question, the distractors drawn from the other
              lessons, in a deterministic order.
  trainee     "Pat Placeholder (simulated)" takes the quiz whenever the packet
              changes, and misses the questions its script tells it to.
  history     every completion (packet sha256, date, score), carried forward in
              the Security Decision Record from one build to the next.

Two automated methods verify and validate KSI-CED-RAT (FRC-CSX-VVK):

  1. currency     the latest completed packet covers everything the current data
                  requires (checked by required_items(), independently of the packet
                  builder): no decision of the last 12 months, incident or
                  rule count is left out;
  2. completion   the trainee completed the current packet by its due date with
                  a passing score, and the effectiveness trend (score over the
                  history) does not fall below the pass mark.

Either failing is reported with its reason and not counted.
"""

import hashlib
import json
from datetime import date, timedelta

TRAINEE = "Pat Placeholder (simulated)"
PASS = 0.8
DUE_DAYS = 30                  # a changed packet is completed within 30 days
WINDOW_DAYS = 365              # decisions from the last 12 months are taught
# Every Nth question is missed on purpose, so the score means something.
MISS_EVERY = 9
CORE = [
    ("general", "What does the deploy do when a published artifact would carry an AWS account ID?",
     "It fails before publishing (the publication redaction gate)."),
    ("privileged", "How does CI reach AWS?",
     "Through GitHub OIDC roles with short-lived credentials; no access key exists."),
    ("privileged", "What stands between a merged change and terraform apply?",
     "A required human reviewer on the prod environment."),
    ("delivery", "What happens to a newly disclosed CVE that no decision covers?",
     "The vulnerability gate fails until it is fixed or dispositioned."),
    ("delivery", "Where is every human decision about a finding recorded?",
     "In the decision register, data/decisions.json, once, by its DEC ID."),
    ("response", "Who receives FedRAMP incident reports for this system?",
     "A simulated recipient: the report is a published log entry and nothing is sent (DEC-194)."),
    ("recovery", "Where does the site's content live if the bucket is lost?",
     "In git: the site and every artifact are rebuilt from any clone by the pipeline."),
    # The phishing drill's remedial lesson (scripts/_phishing.py): a click assigns it.
    ("phishing", "An email says your FedRAMP ID has expired and asks for your password through a link. What do you do?",
     "Report it and do not click: check the sender's domain and where the link really goes; nobody legitimate asks "
     "for a password by email."),
]


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _day(v):
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def required_items(decisions, incidents, n_rules, n_ksis, today):
    """What the packet must cover, from the data (not from the packet builder)."""
    since = today - timedelta(days=WINDOW_DAYS)
    items = {f"decision:{r['id']}" for r in (decisions or {}).get("decisions", [])
             if (_day(r.get("decided_on")) or date.min) >= since}
    items |= {f"incident:{i['id']}" for i in (incidents or {}).get("incidents", [])}
    items |= {f"rules:{n_rules}", f"ksis:{n_ksis}"}
    items |= {f"core:{n}" for n in range(len(CORE))}
    return items


def packet(decisions, incidents, n_rules, n_ksis, today):
    """The training packet for the data as it is today."""
    since = today - timedelta(days=WINDOW_DAYS)
    lessons = [{"covers": f"core:{n}", "area": area, "question": q, "answer": a}
               for n, (area, q, a) in enumerate(CORE)]
    for r in sorted((decisions or {}).get("decisions", []), key=lambda r: r["id"]):
        if (_day(r.get("decided_on")) or date.min) < since:
            continue
        status = "closed, replaced" if r.get("disposition") == "superseded" else (
            "closed" if r.get("status") == "closed" else r.get("disposition"))
        lessons.append({"covers": f"decision:{r['id']}", "area": "decisions",
                        "question": f"What did {r['id']} decide ({status})?", "answer": r["title"]})
    for i in sorted((incidents or {}).get("incidents", []), key=lambda i: i["id"]):
        kind = "exercise" if i.get("exercise") else "incident"
        lessons.append({"covers": f"incident:{i['id']}", "area": "response",
                        "question": f"What was {i['id']} ({kind}) about?", "answer": str(i.get("title") or i["id"])})
    lessons.append({"covers": f"rules:{n_rules}", "area": "general",
                    "question": "How many FedRAMP 20x Class C rule records does the system keep?", "answer": str(n_rules)})
    lessons.append({"covers": f"ksis:{n_ksis}", "area": "general",
                    "question": "How many Key Security Indicators does the system report on?", "answer": str(n_ksis)})
    body = {"lessons": lessons}
    return {"generatedOn": today.isoformat(), "lessons": lessons, "sha256": _sha(body)}


def quiz(pkt):
    """[{question, choices, answer}]: the right answer and three others, ordered by hash."""
    answers = [x["answer"] for x in pkt["lessons"]]
    out = []
    for n, x in enumerate(pkt["lessons"]):
        others = sorted({a for a in answers if a != x["answer"]},
                        key=lambda a: hashlib.sha256(f"{n}:{a}".encode()).hexdigest())[:3]
        choices = sorted([x["answer"], *others], key=lambda a: hashlib.sha256(f"{x['question']}:{a}".encode()).hexdigest())
        out.append({"question": x["question"], "choices": choices, "answer": x["answer"]})
    return out


def take(questions):
    """The simulated trainee's attempt: right, except every MISS_EVERY-th question."""
    picked = []
    for n, q in enumerate(questions, 1):
        wrong = [c for c in q["choices"] if c != q["answer"]]
        picked.append(wrong[0] if (n % MISS_EVERY == 0 and wrong) else q["answer"])
    right = sum(1 for q, p in zip(questions, picked, strict=True) if p == q["answer"])
    misses = [{"question": q["question"], "picked": p, "remark": "Answered with total confidence."}
              for q, p in zip(questions, picked, strict=True) if p != q["answer"]]
    return {"questions": len(questions), "correct": right, "score": round(right / len(questions), 4),
            "misses": misses}


def cycle(previous, pkt, now):
    """The training history: the previous one carried forward, plus a completion
    by the simulated trainee when the packet changed since the last one."""
    history = [dict(h) for h in (previous or {}).get("history", []) if isinstance(h, dict)]
    if not history or history[-1].get("packetSha256") != pkt["sha256"]:
        due = (now.date() + timedelta(days=DUE_DAYS)).isoformat()
        result = take(quiz(pkt))
        history.append({"packetSha256": pkt["sha256"], "packetGeneratedOn": pkt["generatedOn"],
                        "covers": sorted(x["covers"] for x in pkt["lessons"]), "due": due,
                        "completedOn": now.date().isoformat(), "trainee": TRAINEE, **result,
                        "passed": result["score"] >= PASS})
    return history[-24:]


def currency(history, required):
    """Method 1: (ok, reason). The latest completed packet covers what the data requires."""
    if not history:
        return False, "no training packet has been completed"
    gap = sorted(required - set(history[-1].get("covers") or []))
    if gap:
        return False, f"the latest completed packet does not cover {len(gap)} item(s) the data requires ({gap[0]})"
    return True, None


def completion(history, today, packet_sha256):
    """Method 2: (ok, reason). The current packet was completed by its due date,
    with a passing score, and the score trend stays at or above the pass mark."""
    if not history:
        return False, "no completion recorded"
    last = history[-1]
    if last.get("packetSha256") != packet_sha256:
        return False, "the current packet has not been completed"
    done, due = _day(last.get("completedOn")), _day(last.get("due"))
    if done is None or due is None or done > due or done > today:
        return False, "the current packet was not completed by its due date"
    if not last.get("passed"):
        return False, f"the latest score {last.get('score')} is below the pass mark {PASS}"
    if any(float(h.get("score", 0)) < PASS for h in history[-4:]):
        return False, "the effectiveness trend fell below the pass mark in the last four completions"
    return True, None


def summary(pkt, history, methods):
    """What the Security Decision Record publishes under providerExtensions.training."""
    return {"simulated": True, "trainee": TRAINEE,
            "statement": "Training is generated from the system's own data and completed by a simulated trainee; "
                         "no person is enrolled (DEC-194). docs/training-log.md keeps the operator's own reading "
                         "as context.",
            "packet": {"sha256": pkt["sha256"], "generatedOn": pkt["generatedOn"], "lessons": len(pkt["lessons"]),
                       "areas": sorted({x["area"] for x in pkt["lessons"]})},
            "passMark": PASS, "dueDays": DUE_DAYS, "history": history,
            "methods": {k: {"ok": v[0], **({"reason": v[1]} if v[1] else {})} for k, v in methods.items()}}


def evaluate(previous, decisions, incidents, n_rules, n_ksis, now):
    """(currency, completion, summary) for one build."""
    today = now.date()
    pkt = packet(decisions, incidents, n_rules, n_ksis, today)
    history = cycle(previous, pkt, now)
    req = required_items(decisions, incidents, n_rules, n_ksis, today)
    cur, comp = currency(history, req), completion(history, today, pkt["sha256"])
    return cur, comp, summary(pkt, history, {"currency": cur, "completion": comp})
