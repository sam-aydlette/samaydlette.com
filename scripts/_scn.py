"""Significant Change Notification rules as code (SCN-*).

One module for everything the SCN gate, the deploy-time builder and the
scheduled deadline check share:

- the evaluation every change carries (SCN-CSO-EVA): an `SCN-Type:` line, an
  `SCN-Rationale:` line and, for a change that needs a notification, an
  `SCN-Record:` line naming its record in docs/scn/scn-register.csv;
- the register (docs/scn/scn-register.csv) and its validation (SCN-CSO-INF,
  SCN-RTR-NNR, the transformative template fields);
- the notices each record owes and their deadlines in business days, read from
  the vendored FedRAMP rules (SCN-ADP-NTF, SCN-TRF-NIP/NFP/NAF/NAV/UPD), plus
  the operator's 5-business-day retroactive window for emergency changes
  (SCN-CSO-EMG, docs/incident-response.md);
- the evaluation log (SCN-CSO-MAR) and the published notification index
  (SCN-CSO-HIS): both only ever grow, and a build that would drop or rewrite a
  published entry fails.

Notification is publication: FedRAMP's rules name the method for every SCN
notice as an update to the FedRAMP Certification Data, and that is all this
code does. It sends nothing to anyone.

Stdlib only; dates are ISO strings in every file.
"""

import csv
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bizdays  # noqa: E402
import _rules  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
REGISTER = REPO / "docs" / "scn" / "scn-register.csv"
BASE = "https://samaydlette.com/.well-known/"
INDEX_NAME = "significant-change-notifications"
LOG_NAME = "scn-evaluations"
FEED_NAME = "significant-change-notifications.atom"
SOURCE_URL = "https://github.com/sam-aydlette/samaydlette.com/blob/main/"

# Every value an evaluation may carry. `class-change` is a valid evaluation
# that the gate refuses: a change of certification class is not a significant
# change at all but a new certification, and it needs a new assessment.
TYPES = ("not-significant", "routine-recurring", "adaptive", "transformative", "emergency", "class-change")
# Evaluations that owe a notification record.
NEEDS_RECORD = ("adaptive", "transformative", "emergency")
# The types a record may have (SCN-RTR-NNR: no formal notification for routine
# recurring changes, and none for changes that are not significant).
RECORD_TYPES = ("adaptive", "transformative")
# Operator procedure (docs/incident-response.md): retroactive SCN materials for
# an emergency change within 5 business days.
EMERGENCY_BIZDAYS = 5

SCN_ID_RE = re.compile(r"^SCN-\d{4}-\d{3}$")
_LINE = r"^[ \t>]*(?:#+[ \t]*)?(?:[-*][ \t]+)?(?:\*\*)?{key}(?:\*\*)?[ \t]*:(?:\*\*)?[ \t]*(.*?)[ \t]*$"
TYPE_LINE = re.compile(_LINE.format(key="SCN-Type"), re.I | re.M)
RATIONALE_LINE = re.compile(_LINE.format(key="SCN-Rationale"), re.I | re.M)
RECORD_LINE = re.compile(_LINE.format(key="SCN-Record"), re.I | re.M)
PLACEHOLDER = re.compile(r"^(<.*>|tbd|todo|n/?a|none|-+|\.+|same|see above|see below)$", re.I)
MIN_RATIONALE = 15
MAX_RATIONALE = 500

REGISTER_COLUMNS = (
    "scn_id", "fedramp_id", "assessor_name", "related_vulnerability", "scn_type", "categorization_rationale",
    "short_description", "reason_for_change", "customer_impact", "plan_and_timeline", "sia_reference",
    "new_risks_summary", "approver_name", "approver_title", "status", "date_initiated", "date_started",
    "date_finished", "verified_on", "emergency", "evaluation_prs", "plan_final", "tpr_human_validation",
    "tpr_assessor_or_reason", "sar_reference", "docs_to_update", "docs_updated_on", "docs_update_not_required",
)
INF_REQUIRED = ("scn_id", "scn_type", "categorization_rationale", "short_description", "reason_for_change",
                "customer_impact", "plan_and_timeline", "sia_reference", "approver_name", "approver_title",
                "status", "date_initiated")
DATE_COLUMNS = ("date_initiated", "date_started", "date_finished", "verified_on", "docs_updated_on")
YES_NO = ("yes", "no")


class EvaluationError(ValueError):
    pass


# --- the evaluation on every change ----------------------------------------------

def _clean(v):
    return v.strip().strip("`*_").strip()


def normalize_type(raw):
    return re.sub(r"[\s_]+", "-", _clean(raw).lower())


def parse_evaluation(text):
    """{type, rationale, record} from a PR body or commit message.

    Raises EvaluationError naming exactly what is missing or wrong. There is no
    default: a change with no evaluation is not evaluated."""
    text = text or ""
    types = TYPE_LINE.findall(text)
    if not types:
        raise EvaluationError("no 'SCN-Type:' line: every change needs an explicit significant-change evaluation")
    if len(types) > 1:
        raise EvaluationError(f"{len(types)} 'SCN-Type:' lines: give exactly one evaluation")
    kind = normalize_type(types[0])
    if kind not in TYPES:
        raise EvaluationError(f"SCN-Type '{_clean(types[0])}' is not one of: {' | '.join(TYPES)}")
    rationales = RATIONALE_LINE.findall(text)
    if not rationales:
        raise EvaluationError("no 'SCN-Rationale:' line: say in one line why the change is this type")
    if len(rationales) > 1:
        raise EvaluationError(f"{len(rationales)} 'SCN-Rationale:' lines: give exactly one")
    rationale = _clean(rationales[0])
    if PLACEHOLDER.match(rationale) or len(rationale) < MIN_RATIONALE:
        raise EvaluationError(f"SCN-Rationale is empty or a placeholder (at least {MIN_RATIONALE} characters "
                              "explaining the categorization)")
    records = [_clean(r) for r in RECORD_LINE.findall(text)]
    if len(records) > 1:
        raise EvaluationError(f"{len(records)} 'SCN-Record:' lines: name one record")
    record = records[0] if records else None
    if kind in NEEDS_RECORD:
        if not record:
            raise EvaluationError(f"SCN-Type {kind} needs an 'SCN-Record: SCN-YYYY-NNN' line naming its record "
                                  "in docs/scn/scn-register.csv (the next free ID if the record is not written yet)")
        if not SCN_ID_RE.match(record):
            raise EvaluationError(f"SCN-Record '{record}' is not an SCN ID (SCN-YYYY-NNN)")
    elif record:
        raise EvaluationError(f"SCN-Type {kind} makes no notification (SCN-RTR-NNR), so it names no SCN-Record")
    return {"type": kind, "rationale": rationale[:MAX_RATIONALE], "record": record}


def gate(text, index=None, today=None):
    """(errors, notices, evaluation) for one change's evaluation text.

    `index` is the published notification index, needed only for a
    transformative change: it may merge only once its initial plan has been
    published 30 business days and its final plan 10 (SCN-TRF-NIP/NFP)."""
    today = today or date.today()
    try:
        ev = parse_evaluation(text)
    except EvaluationError as exc:
        return [str(exc)], [], None
    errors, notices = [], []
    if ev["type"] == "class-change":
        errors.append("SCN-Type class-change blocks the merge: a change of certification class is a new "
                      "certification, not a significant change. Stop and plan a new assessment "
                      "(docs/policies/cm-policy.md).")
    elif ev["type"] == "emergency":
        notices.append(f"emergency change (SCN-CSO-EMG): the retroactive record {ev['record']} must be in the "
                       f"register and published within {EMERGENCY_BIZDAYS} business days "
                       "(docs/incident-response.md); the scheduled SCN deadline check enforces it")
    elif ev["type"] == "transformative":
        errors += transformative_lead_errors(ev["record"], index, today)
    elif ev["type"] == "adaptive":
        notices.append(f"adaptive change: the notice for {ev['record']} must be published within "
                       f"{timeframe('SCN-ADP-NTF')} business days of finishing (SCN-ADP-NTF)")
    return errors, notices, ev


def transformative_lead_errors(record, index, today):
    if index is None:
        return ["cannot read the published notification index, so the transformative lead times cannot be "
                "checked (fail closed)"]
    scn = next((s for s in index.get("notifications", []) if s.get("scnId") == record), None)
    if scn is None:
        return [f"{record} has no published notification: a transformative change starts no sooner than "
                f"{timeframe('SCN-TRF-NIP')} business days after its initial plan is published (SCN-TRF-NIP)"]
    published = {n["stage"]: n.get("publishedOn") for n in scn.get("notices", [])}
    errors = []
    for stage, rule in (("initial-plan", "SCN-TRF-NIP"), ("final-plan", "SCN-TRF-NFP")):
        on = published.get(stage)
        if not on:
            errors.append(f"{record}: no {stage} notice published ({rule})")
            continue
        ready = _bizdays.add_business_days(date.fromisoformat(on), timeframe(rule))
        if today < ready:
            errors.append(f"{record}: the {stage} notice was published {on}; the change may start on or after "
                          f"{ready.isoformat()} ({timeframe(rule)} business days, {rule})")
    return errors


# --- FedRAMP timeframes -----------------------------------------------------------

def timeframe(rule_id):
    """The rule's business-day timeframe, from the vendored rules (never typed in)."""
    rules, _ = _rules.load_rules()
    family, subset = rule_id.split("-")[0], rule_id.split("-")[1]
    try:
        r = rules["FRR"][family]["data"]["all"][subset][rule_id]
    except KeyError:
        raise SystemExit(f"::error::SCN: rule {rule_id} not in the vendored rules (fail-closed)") from None
    if r.get("timeframe_type") != "bizdays" or not isinstance(r.get("timeframe_num"), int):
        raise SystemExit(f"::error::SCN: rule {rule_id} has no business-day timeframe (fail-closed)")
    return r["timeframe_num"]


# --- the register ------------------------------------------------------------------

def read_register(path=REGISTER):
    with Path(path).open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = tuple(reader.fieldnames or ())
        rows = [{k: (v or "").strip() for k, v in r.items()} for r in reader]
    return header, rows


def _date(v):
    try:
        return date.fromisoformat(v) if v else None
    except ValueError:
        return None


def validate_register(header, rows, root=REPO):
    """Every error in the register; empty means it can be published."""
    errors = []
    if header != REGISTER_COLUMNS:
        missing = [c for c in REGISTER_COLUMNS if c not in header]
        extra = [c for c in header if c not in REGISTER_COLUMNS]
        errors.append(f"register columns differ from the template (missing {missing}, unexpected {extra})")
        return errors
    seen = set()
    for r in rows:
        sid = r["scn_id"] or "<no id>"
        where = f"{sid}:"
        if not SCN_ID_RE.match(r["scn_id"]):
            errors.append(f"{where} scn_id is not SCN-YYYY-NNN")
        if sid in seen:
            errors.append(f"{where} duplicate scn_id")
        seen.add(sid)
        for c in INF_REQUIRED:
            if not r[c]:
                errors.append(f"{where} {c} is empty (SCN-CSO-INF)")
        if r["scn_type"] and r["scn_type"] not in RECORD_TYPES:
            errors.append(f"{where} scn_type '{r['scn_type']}': only adaptive and transformative changes get a "
                          "notification record (SCN-RTR-NNR)")
        for c in DATE_COLUMNS:
            if r[c] and _date(r[c]) is None:
                errors.append(f"{where} {c} '{r[c]}' is not an ISO date")
        order = [(c, _date(r[c])) for c in ("date_initiated", "date_started", "date_finished", "verified_on")]
        known = [(c, d) for c, d in order if d]
        for (c1, d1), (c2, d2) in zip(known, known[1:], strict=False):
            if d2 < d1:
                errors.append(f"{where} {c2} {d2} is before {c1} {d1}")
        if r["sia_reference"] and not (Path(root) / r["sia_reference"]).is_file():
            errors.append(f"{where} sia_reference {r['sia_reference']} does not exist")
        if r["emergency"] not in YES_NO:
            errors.append(f"{where} emergency must be yes or no")
        if r["emergency"] == "yes" and not r["evaluation_prs"]:
            errors.append(f"{where} an emergency record names the change(s) it documents in evaluation_prs")
        if r["scn_type"] == "adaptive" and not r["new_risks_summary"]:
            errors.append(f"{where} new_risks_summary is empty (SCN-ADP-NTF)")
        if r["scn_type"] == "transformative":
            errors += [f"{where} {m}" for m in _transformative_errors(r)]
    return errors


def _transformative_errors(r):
    errs = []
    if not r["date_started"]:
        errs.append("date_started (the planned start) is required: the notice windows count back from it "
                    "(SCN-TRF-NIP/NFP)")
    if r["plan_final"] not in YES_NO:
        errs.append("plan_final must be yes or no (SCN-TRF-NFP)")
    if r["tpr_human_validation"] not in YES_NO:
        errs.append("tpr_human_validation must be yes or no: does the change need human validation? (SCN-TRF-TPR)")
    if not r["tpr_assessor_or_reason"]:
        errs.append("tpr_assessor_or_reason: name the third-party assessor engaged, or why none was (SCN-TRF-TPR)")
    if not r["new_risks_summary"]:
        errs.append("new_risks_summary is empty (SCN-TRF-NIP, SCN-TRF-NAV)")
    if r["verified_on"] and not r["sar_reference"]:
        errs.append("sar_reference: link the security assessment report, or say why there is none (SCN-TRF-NAV)")
    if r["date_finished"] and not (r["docs_to_update"] or r["docs_update_not_required"]):
        errs.append("docs_to_update (the service documentation to update) or docs_update_not_required "
                    "(how that was determined) is required once finished (SCN-TRF-UPD)")
    if r["docs_updated_on"] and not r["docs_to_update"]:
        errs.append("docs_updated_on without docs_to_update")
    return errs


# --- notices and deadlines ----------------------------------------------------------

def notices_due(row):
    """The notices a record owes now: [{stage, rule, deadline, kind}].

    kind "by": publish on or before the deadline. kind "before-start": publish
    at least the rule's business days before the change starts, i.e. on or
    before the deadline. An emergency record's notices are retroactive: each is
    due within EMERGENCY_BIZDAYS of the change finishing (or starting)."""
    out = []
    t = row["scn_type"]
    start, finish, verified = _date(row["date_started"]), _date(row["date_finished"]), _date(row["verified_on"])
    emergency = row["emergency"] == "yes"
    retro_from = finish or start or _date(row["date_initiated"])

    def add(stage, rule, deadline, kind):
        if emergency:
            deadline, kind = _bizdays.add_business_days(retro_from, EMERGENCY_BIZDAYS), "retroactive"
            rule = f"{rule}; SCN-CSO-EMG"
        out.append({"stage": stage, "rule": rule, "deadline": deadline, "kind": kind})

    if t == "adaptive" and finish:
        add("after-finish", "SCN-ADP-NTF", _bizdays.add_business_days(finish, timeframe("SCN-ADP-NTF")), "by")
    if t == "transformative":
        if start:
            add("initial-plan", "SCN-TRF-NIP", _bizdays.add_business_days(start, -timeframe("SCN-TRF-NIP")),
                "before-start")
            if row["plan_final"] == "yes":
                add("final-plan", "SCN-TRF-NFP", _bizdays.add_business_days(start, -timeframe("SCN-TRF-NFP")),
                    "before-start")
        if finish:
            add("after-finish", "SCN-TRF-NAF", _bizdays.add_business_days(finish, timeframe("SCN-TRF-NAF")), "by")
        if verified:
            add("after-verification", "SCN-TRF-NAV",
                _bizdays.add_business_days(verified, timeframe("SCN-TRF-NAV")), "by")
    return out


def docs_update_deadline(row):
    finish = _date(row["date_finished"])
    if row["scn_type"] != "transformative" or not finish:
        return None
    return _bizdays.add_business_days(finish, timeframe("SCN-TRF-UPD"))


def merge_notices(row, previous, today):
    """This build's notices for a record. A notice already published keeps the
    date it was first published; a new one is published today."""
    prev = {n["stage"]: n for n in previous or []}
    out = []
    for n in notices_due(row):
        on = prev.get(n["stage"], {}).get("publishedOn") or today.isoformat()
        out.append({"stage": n["stage"], "rule": n["rule"], "deadline": n["deadline"].isoformat(),
                    "publishedOn": on, "onTime": date.fromisoformat(on) <= n["deadline"]})
    # A stage published before is never dropped, even if the record no longer owes it.
    for stage, n in prev.items():
        if stage not in {o["stage"] for o in out}:
            out.append(n)
    return out


# --- append-only records ----------------------------------------------------------

def append_only_errors(previous, current, key):
    """Errors if `current` does not start with every entry of `previous`,
    unchanged and in order (`key` names an entry in messages)."""
    errors = []
    if len(current) < len(previous):
        errors.append(f"{len(previous) - len(current)} published entr(ies) would be dropped")
    for i, (p, c) in enumerate(zip(previous, current, strict=False)):
        if p != c:
            errors.append(f"published entry {i} ({p.get(key)}) would be rewritten")
    return errors


def retention_errors(previous_index, current_index):
    """SCN-CSO-HIS: every notification published before is still published,
    with the notices it had and their publication dates."""
    if not previous_index:
        return []
    cur = {s["scnId"]: s for s in current_index.get("notifications", [])}
    errors = []
    for s in previous_index.get("notifications", []):
        sid = s.get("scnId")
        if sid not in cur:
            errors.append(f"{sid} was published and would be dropped")
            continue
        now = {n["stage"]: n.get("publishedOn") for n in cur[sid].get("notices", [])}
        for n in s.get("notices", []):
            if now.get(n["stage"]) != n.get("publishedOn"):
                errors.append(f"{sid} {n['stage']} notice published {n.get('publishedOn')} would be "
                              f"dropped or re-dated")
    return errors


# --- the scheduled deadline check -------------------------------------------------

def overdue(rows, index, log_entries, today):
    """Everything late and still outstanding. A notice published late is a
    fact the index records (onTime false), not an open item."""
    out = []
    by_id = {r["scn_id"]: r for r in rows}
    published = {s["scnId"]: {n["stage"] for n in s.get("notices", [])}
                 for s in (index or {}).get("notifications", [])}
    for e in log_entries:
        if e.get("scn_type") not in NEEDS_RECORD or not e.get("scn_record"):
            continue
        ref, merged = e["scn_record"], date.fromisoformat(e["merged_on"])
        if ref in by_id:
            continue
        if e["scn_type"] == "transformative":
            due = merged
        elif e["scn_type"] == "emergency":
            due = _bizdays.add_business_days(merged, EMERGENCY_BIZDAYS)
        else:
            due = _bizdays.add_business_days(merged, timeframe("SCN-ADP-NTF"))
        if today > due:
            out.append(f"{ref}: named by the {e['scn_type']} change {e.get('commit', '')[:12]} merged {merged}, "
                       f"but not in the register (due {due.isoformat()})")
    for r in rows:
        for n in notices_due(r):
            if n["stage"] not in published.get(r["scn_id"], set()) and today > n["deadline"]:
                out.append(f"{r['scn_id']}: {n['stage']} notice ({n['rule']}) not published; due "
                           f"{n['deadline'].isoformat()}")
        upd = docs_update_deadline(r)
        if upd and not r["docs_updated_on"] and not r["docs_update_not_required"] and today > upd:
            out.append(f"{r['scn_id']}: service documentation not updated; due {upd.isoformat()} (SCN-TRF-UPD)")
    return out
