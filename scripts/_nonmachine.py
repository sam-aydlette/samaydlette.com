"""Non-machine information resources and their verification (VDR-TFR-NMV).

Providers MUST verify and validate the status of non-machine-based information
resources at least once every 3 months. data/non-machine-resources.json lists
them (policies, procedures, plans, the operator role, records and registers).
Nobody verifies them by hand: every resource gets machine checks, run on every
deploy (enforced) and every night (published), so the verification is never
more than a day old:

  exists       the file is there;
  paths        every repository path it cites (a relative Markdown link, or a
               `scripts/...`, `data/...`, `docs/...`, `infrastructure/...`,
               `tests/...`, `website/...` or `.github/...` path in backticks)
               resolves, relative to the document or to the repository root;
  decisions    every DEC ID it cites is in the decision register;
  retired      it names no retired mechanism (RETIRED: the POA&M, the SSP, the
               CDS overview, Basic Auth, Duo-enforced MFA, "no SCN-Type label is
               required", long-lived deploy keys), except on a line that says the
               thing is retired, replaced or no longer used;
  counts       a stated count tagged `<!-- nmv-count NAME=N -->` equals what the
               code says (COUNTERS), and the tagged line states N;
  register     a register is loaded by its own validator (the decision register)
               or parsed as JSON;
  manual work  no sentence commits a person to a recurring review, reading,
               tabletop, acknowledgement or reconciliation (MANUAL_WORK): those
               are automated (scripts/_scheduled_review.py and its kin). A
               sentence that cites DEC-195 (the three recurring human acts that
               remain) may describe one, and a section headed as history may
               record what used to be done.

The status (/.well-known/vdr-non-machine-vv.json) is the quarterly V&V record:
when every check passes, verifiedAt is the time of the run; when any fails,
verifiedAt is the epoch, so the published freshness window is red at once.
Fails closed: a missing or malformed register is an error, never an empty list.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATH = REPO / "data" / "non-machine-resources.json"
TOP_KEYS = {"$schema", "$comment", "schema", "max_age_days", "resources"}
ENTRY_KEYS = {"id", "path", "kind", "title", "owner", "verifies"}
KINDS = {"policy", "procedure", "plan", "role", "record", "register"}
ID_RE = re.compile(r"^NMR-[A-Z0-9-]+$")
# The rule's "at least once every 3 months": the longest three calendar months.
RULE_MAX_DAYS = 92
EPOCH = "1970-01-01T00:00:00+00:00"
# Directories whose every Markdown file is a non-machine resource that must be listed.
MUST_LIST: tuple[tuple[str, set[str]], ...] = (("docs/policies", {"README.md"}), ("docs/runbooks", set()),
                                              ("docs/procedures", set()))

# Retired mechanisms. A line that says the thing is retired or replaced may name it.
RETIRED = {
    "POA&M": re.compile(r"\bPOA&(?:amp;)?M\b|\bPOAM-\d+|\bplan of action and milestones\b", re.I),
    "SSP": re.compile(r"\bSSP\b|\bSystem Security Plan\b"),
    "CDS overview": re.compile(r"\bCDS overview\b", re.I),
    "Basic Auth": re.compile(r"\bBasic Auth(?:entication)?\b", re.I),
    "Duo-enforced MFA": re.compile(r"\b(?:via|through|by|with) Duo\b(?! Mobile)|\bDuo (?:root )?MFA\b", re.I),
    "no SCN-Type label": re.compile(r"no SCN-Type label is required", re.I),
    "long-lived deploy keys": re.compile(r"(?<!no )(?<!never )(?<!without )long-lived (?:deploy|deployment|AWS|access) "
                                         r"(?:access )?keys?", re.I),
}
RETIRED_OK = re.compile(r"\b(?:retired|replaced|replaces|formerly|superseded|no longer|backfilled|"
                        r"instead of|was removed|removed in)\b", re.I)
# Manual work (DEC-195): a person, a review-like act and a recurring cadence in one
# sentence, or a "Review cadence:" line. Everything recurring is a mechanism now.
MANUAL_ACTOR = re.compile(r"\b(?:operator|owner|Sam|the team|staff|personnel|a person|a human|humans?|manually|"
                          r"by hand|in person)\b", re.I)
MANUAL_ACT = re.compile(r"\b(?:review(?:s|ed|ing)?|reads?|re-?reads?|inspect\w*|walk\w*|tabletops?|re-?acknowledg\w*|"
                        r"acknowledg\w*|reconcil\w*|audits?|checks?|confirm\w*|examin\w*|look\w* (?:at|over))\b",
                        re.I)
MANUAL_CADENCE = re.compile(r"\b(?:daily|weekly|monthly|quarterly|annual(?:ly)?|yearly|biannual\w*|semi-?annual\w*|"
                            r"every (?:day|week|month|quarter|year|\d+ (?:days|weeks|months))|"
                            r"once an? (?:week|month|quarter|year)|each (?:week|month|quarter|year))\b", re.I)
REVIEW_CADENCE_LINE = re.compile(r"\breview cadence\b", re.I)
# A sentence that names the mechanism doing the recurring act describes automation.
MECHANISM = re.compile(r"`?(?:scripts|tools|infrastructure)/[\w./-]+|\.github/workflows/|\b[\w-]+\.ya?ml\b|"
                       r"\b(?:automat\w*|generated|simulated|machine|nightly|the deploy|every deploy|emitter|Lambda|the script|"
                       r"the pipeline|workflow|the gate)\b", re.I)
MANUAL_OK = re.compile(r"\bDEC-195\b")
# Names of published, automated products, not acts: "the Quarterly Review" (CCM-QTR-MTG, held by
# scripts/hold-quarterly-review.py), "the Ongoing Certification Report" and "the Annual Security
# Review" (scripts/hold-security-review.py). Case-sensitive: "the annual security review" is not one.
# Code spans and file names are not prose ("quarterly-reviews.json" commits nobody).
CODE_OR_FILE = re.compile(r"`[^`]*`|[\w./<>-]+\.(?:json|ics|md|py|ya?ml|csv|bundle|html|js|tf)\b")
PROPER_NAMES = re.compile(r"\bQuarterly Reviews?\b|\bOngoing Certification Reports?\b|\bAnnual Security Reviews?\b")
HISTORY_HEADING = re.compile(r"^(#+)\s.*\b(?:history|historical|changelog|change log|revision log)\b", re.I)
DEC_RE = re.compile(r"\bDEC-\d{3}\b")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
CODE_PATH_RE = re.compile(r"`((?:scripts|data|docs|infrastructure|tests|\.github|website)/[^`\s]+)`")
COUNT_TAG_RE = re.compile(r"<!--\s*nmv-count\s+([a-z0-9-]+)=(\d+)\s*-->")
NUMBER_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
                "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"]


def _watchdog_alarms(repo):
    tf = (repo / "infrastructure" / "watchdog.tf").read_text(encoding="utf-8")
    block = tf[tf.index("watchdog_alarms = {"):]
    depth = 0
    for i, ch in enumerate(block):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                block = block[:i]
                break
    return len(re.findall(r'^\s{4}"[a-z0-9-]+"\s*=\s*\{', block, re.M))


def _policies(repo):
    return len(list((repo / "docs" / "policies").glob("*-policy.md")))


COUNTERS = {"watchdog-alarms": _watchdog_alarms, "family-policies": _policies}


def _fail(msg):
    raise SystemExit(f"::error::non-machine resources: {msg} (fail-closed)")


def validate(doc, where="data/non-machine-resources.json"):
    if not isinstance(doc, dict) or doc.get("schema") != "non-machine-resources/2":
        _fail(f"{where} is not a non-machine-resources/2 document")
    if set(doc) - TOP_KEYS:
        _fail(f"{where}: unknown field(s) {sorted(set(doc) - TOP_KEYS)}")
    m = doc.get("max_age_days")
    if not isinstance(m, int) or isinstance(m, bool) or not 1 <= m <= RULE_MAX_DAYS:
        _fail(f"{where}: max_age_days must be an integer from 1 to {RULE_MAX_DAYS}")
    res = doc.get("resources")
    if not isinstance(res, list) or not res:
        _fail(f"{where}: resources must be a non-empty list")
    seen = set()
    for e in res:
        rid = e.get("id") if isinstance(e, dict) else None
        if not isinstance(rid, str) or not ID_RE.match(rid) or rid in seen:
            _fail(f"{where}: entry id {rid!r} is not a unique NMR-...")
        seen.add(rid)
        if set(e) != ENTRY_KEYS:
            _fail(f"{rid}: fields must be exactly {sorted(ENTRY_KEYS)}")
        if e["kind"] not in KINDS:
            _fail(f"{rid}: kind {e['kind']!r} is not one of {sorted(KINDS)}")
        for k in ("path", "title", "owner", "verifies"):
            if not isinstance(e[k], str) or not e[k].strip():
                _fail(f"{rid}: {k} must be a non-empty string")
    return doc


def load(path=None):
    p = Path(path) if path else DEFAULT_PATH
    if not p.is_file():
        _fail(f"{p} not found")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc.__class__.__name__}")
    return validate(doc, str(p))


def _resolves(ref, doc_path, repo):
    ref = ref.split("#", 1)[0].rstrip("/.,;:")
    if not ref or re.search(r"[<>*{}$]|YYYY|NNN", ref):
        return True    # a pattern or placeholder, not a path
    return any((base / ref).exists() for base in (doc_path.parent, repo))


def _sentences(text):
    """(first line number, sentence) for prose outside sections headed as history."""
    out, buf, start, skip = [], [], None, None
    for n, line in enumerate(text.splitlines(), 1):
        h = re.match(r"^(#+)\s", line)
        if h:
            level = len(h.group(1))
            if skip is not None and level <= skip:
                skip = None
            if skip is None and HISTORY_HEADING.match(line):
                skip = level
        if skip is not None:
            continue
        for part in re.split(r"(?<=[.!?])\s+|^\s*$|^\s*[-*|]\s|^#+\s", line):
            if part is None:
                continue
            if start is None:
                start = n
            buf.append(part)
            joined = " ".join(buf).strip()
            if re.search(r"[.!?]$", joined) or not line.strip() or line.lstrip().startswith(("-", "*", "|", "#")):
                if joined:
                    out.append((start, joined))
                buf, start = [], None
        if not line.strip():
            if buf and " ".join(buf).strip():
                out.append((start, " ".join(buf).strip()))
            buf, start = [], None
    if buf and " ".join(buf).strip():
        out.append((start, " ".join(buf).strip()))
    return out


def manual_work(text):
    """[(line, sentence)] for every sentence that commits a person to recurring
    manual work (MANUAL_WORK), outside history sections and DEC-195's acts."""
    found = []
    for n, s in _sentences(text):
        if MANUAL_OK.search(s):
            continue
        prose = PROPER_NAMES.sub("", CODE_OR_FILE.sub("", s))
        if not (MANUAL_ACT.search(prose) or REVIEW_CADENCE_LINE.search(prose)) or not MANUAL_CADENCE.search(prose):
            continue
        if MANUAL_ACTOR.search(prose) or not MECHANISM.search(s) or REVIEW_CADENCE_LINE.search(prose):
            found.append((n, s))
    return found


def text_problems(rid, text, doc_path, repo, decision_ids):
    """Every machine-check failure for one Markdown resource."""
    out = [f"{rid}: line {n} commits a person to recurring manual work: {s[:90]!r}" for n, s in manual_work(text)]
    for n, line in enumerate(text.splitlines(), 1):
        refs = [r for r in LINK_RE.findall(line) if not re.match(r"[a-z]+:|#|/", r)]
        refs += CODE_PATH_RE.findall(line)
        for ref in refs:
            if not _resolves(ref, doc_path, repo):
                out.append(f"{rid}: line {n} cites {ref}, which does not exist")
        for dec in DEC_RE.findall(line):
            if dec not in decision_ids:
                out.append(f"{rid}: line {n} cites {dec}, which is not in the decision register")
        if not RETIRED_OK.search(line):
            for term, rx in RETIRED.items():
                if rx.search(line):
                    out.append(f"{rid}: line {n} names a retired mechanism ({term})")
        for name, stated in COUNT_TAG_RE.findall(line):
            fn = COUNTERS.get(name)
            if fn is None:
                out.append(f"{rid}: line {n} tags an unknown count {name!r}")
                continue
            actual, n_stated = fn(repo), int(stated)
            words = {stated} | ({NUMBER_WORDS[n_stated]} if n_stated < len(NUMBER_WORDS) else set())
            visible = COUNT_TAG_RE.sub("", line).lower()
            if actual != n_stated:
                out.append(f"{rid}: line {n} states {name} = {n_stated}; the code has {actual}")
            elif not any(re.search(rf"\b{w}\b", visible) for w in words):
                out.append(f"{rid}: line {n} tags {name} = {n_stated} but does not state it")
    return out


def register_problems(rid, path):
    """A register is checked by its own validator, or parsed as JSON."""
    try:
        if path.name == "decisions.json":
            import _decisions   # noqa: PLC0415 (only the decision register needs it)
            _decisions.load(path)
        else:
            json.loads(path.read_text(encoding="utf-8"))
    except SystemExit as exc:
        return [f"{rid}: {path.name} does not validate ({str(exc)[:160]})"]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"{rid}: {path.name} is not valid JSON ({type(exc).__name__})"]
    return []


def problems(doc, decisions, repo=REPO):
    """Every reason a resource does not pass its machine checks, as strings;
    empty when all pass. `decisions` is a loaded decisions/1 register."""
    ids = {r["id"] for r in decisions["decisions"]}
    out = []
    listed = {e["path"] for e in doc["resources"]}
    for e in doc["resources"]:
        rid, p = e["id"], repo / e["path"]
        if not p.is_file():
            out.append(f"{rid}: {e['path']} does not exist")
            continue
        if e["kind"] == "register":
            out += register_problems(rid, p)
        else:
            out += text_problems(rid, p.read_text(encoding="utf-8"), p, repo, ids)
    for folder, skip in MUST_LIST:
        for p in sorted((repo / folder).glob("*.md")):
            rel = f"{folder}/{p.name}"
            if p.name not in skip and rel not in listed:
                out.append(f"{rel} has no entry in the register")
    return list(dict.fromkeys(out))


def status(doc, decisions, now=None, repo=REPO):
    """The published status (/.well-known/vdr-non-machine-vv.json), the
    quarterly V&V record: verifiedAt is this run when every check passes, else
    the epoch."""
    now = now or datetime.now(timezone.utc)
    probs = problems(doc, decisions, repo)
    ok = not probs
    verified = now.isoformat() if ok else EPOCH
    return {
        "schema": "non-machine-vv/2",
        "rule": "VDR-TFR-NMV",
        "generatedAt": now.isoformat(),
        "verifiedAt": verified,
        "nextDueBy": (now.date() + timedelta(days=doc["max_age_days"])).isoformat() if ok else now.date().isoformat(),
        "maxAgeDays": doc["max_age_days"],
        "method": "Machine checks on every deploy and every night (scripts/_nonmachine.py): the file exists, every "
                  "path and DEC ID it cites resolves, it names no retired mechanism, every tagged count matches "
                  "the code, and a register validates. No person verifies anything by hand.",
        "checks": ["exists", "paths", "decisions", "retired", "counts", "register"],
        "status": "ok" if ok else "lapsed",
        "problems": probs,
        "source": "data/non-machine-resources.json",
        "resources": [{"id": e["id"], "kind": e["kind"], "title": e["title"], "path": e["path"],
                       "owner": e["owner"], "verifies": e["verifies"],
                       "lastVerified": verified[:10] if ok else None,
                       "result": "fail" if any(p.startswith(e["id"] + ":") for p in probs) else "pass"}
                      for e in doc["resources"]],
    }
