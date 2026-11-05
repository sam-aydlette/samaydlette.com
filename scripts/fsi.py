#!/usr/bin/env python3
"""Work the FedRAMP Security Inbox from the operator's machine.

    fsi.py list [--all]                       open (or all) register items
    fsi.py show ID                            the register item and the message, as text
    fsi.py triage ID [--respond-by ISO] [--note TEXT]
    fsi.py close ID --outcome OUTCOME --note TEXT
    fsi.py exercise --reply-to ADDRESS [--designation D] [--smtp] [--record DIR]

Runs with the operator's own AWS credentials (the operators group's
fedramp-inbox-operator policy) through the aws CLI; no SDK dependency.
docs/runbooks/fedramp-security-inbox.md says when to use each command.

Every message is untrusted input. `show` prints text only: the plain-text
part if there is one, otherwise the HTML part reduced to its text. Nothing is
rendered, no link is followed, no attachment is opened or saved; attachments
are listed by sanitised name and size. Control and bidirectional-override
characters are removed from everything printed.

`exercise` runs the dated end-to-end exercise (AFC-CSO-RCV/ACK/EMR/CRA): it
invokes the inbox function with a synthetic Emergency Test from a FedRAMP
address (the real classifier, not a bypass), checks the register item, the
acknowledgement and the page, optionally sends one real message through SES
receiving (--smtp), and writes an outcomes-only record (no addresses, no
subjects) for the operator to commit under docs/exercises/.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOMAIN = "samaydlette.com"
DASHED = DOMAIN.replace(".", "-")
BUCKET = f"{DASHED}-fsi-mail"
FUNCTION = f"{DASHED}-fedramp-inbox"
REGION = "us-east-2"
EXERCISE_FROM = f"fsi-exercise@{DOMAIN}"
OPEN, CLOSED = "register/open/", "register/closed/"
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
CONTROL = re.compile("[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
OUTCOMES = ("completed", "not-fedramp", "no-action-required", "exercise-complete")
MAX_BODY = 200_000


def fsi_address() -> str:
    return json.loads((REPO / "data" / "cds" / "offering.json").read_text())["fedramp_security_inbox"]["address"]


def clean(text: str) -> str:
    return CONTROL.sub("", text)


def aws(*args: str, binary: bool = False) -> bytes | str:
    cmd = ["aws", "--region", REGION, *args]
    out = subprocess.run(cmd, capture_output=True, check=False)
    if out.returncode != 0:
        raise SystemExit(f"aws {args[0]} {args[1] if len(args) > 1 else ''} failed: {clean(out.stderr.decode(errors='replace'))[:400]}")
    return out.stdout if binary else out.stdout.decode()


def get_object(key: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "obj"
        aws("s3api", "get-object", "--bucket", BUCKET, "--key", key, str(dest))
        return dest.read_bytes()


def put_json(key: str, doc: dict) -> None:
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "obj.json"
        src.write_text(json.dumps(doc, indent=2))
        aws("s3api", "put-object", "--bucket", BUCKET, "--key", key, "--body", str(src),
            "--content-type", "application/json")


def keys(prefix: str) -> list[str]:
    out = json.loads(aws("s3api", "list-objects-v2", "--bucket", BUCKET, "--prefix", prefix, "--output", "json") or "{}")
    return [o["Key"] for o in out.get("Contents", [])]


def record_id(value: str) -> str:
    if not ID_RE.match(value):
        raise SystemExit("not a register ID")
    return value


def find(rid: str) -> tuple[str, dict]:
    for prefix in (OPEN, CLOSED):
        key = f"{prefix}{rid}.json"
        if key in keys(key):
            return key, json.loads(get_object(key))
    raise SystemExit(f"no register item {rid}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- commands ------------------------------------------------------------------

def cmd_list(a) -> int:
    prefixes = (OPEN, CLOSED) if a.all else (OPEN,)
    rows = []
    for prefix in prefixes:
        for key in keys(prefix):
            r = json.loads(get_object(key))
            rows.append(r)
    rows.sort(key=lambda r: r.get("received_at") or "")
    for r in rows:
        print(clean(f"{r.get('id')}  {r.get('designation'):<14} {r.get('status'):<8} received {r.get('received_at')}  "
                    f"triage by {r.get('triage_by')}  due {r.get('respond_by') or '-'}  ack {r.get('ack', {}).get('status')}  "
                    f"page {r.get('page', {}).get('status')}{'  EXERCISE' if r.get('exercise') else ''}"))
    if not rows:
        print("no register items")
    return 0


class _Text(HTMLParser):
    """Collect an HTML part's text. Nothing is fetched or rendered."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def message_text(raw: bytes) -> str:
    """The message as safe text: selected headers, the body as text, attachment names."""
    msg = BytesParser(policy=policy.default).parsebytes(raw[: 20 * 1024 * 1024])
    lines = [f"{h}: {clean(str(msg.get(h, '')))[:500]}" for h in ("From", "To", "Date", "Subject", "Message-ID")]
    body = msg.get_body(preferencelist=("plain",))
    if body is not None:
        text = body.get_content()
    else:
        html = msg.get_body(preferencelist=("html",))
        if html is not None:
            p = _Text()
            p.feed(html.get_content())
            text = "[HTML-only message: text extracted, not rendered]\n" + "".join(p.parts)
        else:
            text = "[no text body]"
    lines += ["", clean(text)[:MAX_BODY], ""]
    for part in msg.iter_attachments():
        name = clean(part.get_filename() or "(unnamed)")[:120]
        size = len(part.get_payload(decode=True) or b"")
        lines.append(f"[attachment not opened: {name}, {part.get_content_type()}, {size} bytes]")
    return "\n".join(lines)


def cmd_show(a) -> int:
    rid = record_id(a.id)
    _, r = find(rid)
    print(clean(json.dumps(r, indent=2)))
    if r.get("object_key"):
        print("\n--- message (text only; untrusted) ---")
        print(message_text(get_object(r["object_key"])))
    return 0


def cmd_triage(a) -> int:
    rid = record_id(a.id)
    key, r = find(rid)
    if r.get("status") == "closed":
        raise SystemExit("already closed")
    if a.respond_by:
        due = datetime.fromisoformat(a.respond_by.replace("Z", "+00:00"))
        if due.tzinfo is None:
            raise SystemExit("--respond-by needs a timezone (e.g. 2026-11-10T15:00-05:00)")
        r["respond_by"] = due.astimezone(timezone.utc).isoformat()
        r["deadline_basis"] = "Timeframe stated in the message, recorded at triage"
    elif r.get("designation") == "IMPORTANT":
        raise SystemExit("Important messages need --respond-by: the timeframe the message states (AFC-CSO-IMA)")
    r["status"] = "triaged"
    r.setdefault("history", []).append({"at": now_iso(), "action": "triaged", "note": clean(a.note or "")[:1000]})
    put_json(key, r)
    print(f"{rid}: triaged; required actions due {r.get('respond_by') or 'n/a'}")
    return 0


def cmd_close(a) -> int:
    rid = record_id(a.id)
    key, r = find(rid)
    if not key.startswith(OPEN):
        raise SystemExit("already closed")
    r["status"] = "closed"
    r["outcome"] = a.outcome
    r["closed_at"] = now_iso()
    r.setdefault("history", []).append({"at": r["closed_at"], "action": f"closed: {a.outcome}", "note": clean(a.note)[:1000]})
    put_json(f"{CLOSED}{rid}.json", r)
    aws("s3api", "delete-object", "--bucket", BUCKET, "--key", key)
    late = r.get("respond_by") and r["closed_at"] > r["respond_by"]
    print(f"{rid}: closed ({a.outcome}){'; AFTER the deadline ' + r['respond_by'] if late else ''}")
    return 0


def _smtp_leg(nonce: str, timeout_s: int = 180) -> dict:
    start = time.time()
    before = set(keys("inbound/"))
    aws("sesv2", "send-email", "--from-email-address", EXERCISE_FROM,
        "--destination", json.dumps({"ToAddresses": [fsi_address()]}),
        "--content", json.dumps({"Simple": {"Subject": {"Data": f"FSI exercise {nonce} (SMTP leg)"},
                                            "Body": {"Text": {"Data": f"Exercise {nonce}. No action."}}}}))
    while time.time() - start < timeout_s:
        for key in sorted(set(keys("inbound/")) - before):
            if nonce.encode() in get_object(key)[:65536]:
                return {"stored": True, "seconds": round(time.time() - start)}
        time.sleep(10)
    return {"stored": False, "seconds": timeout_s}


def cmd_exercise(a) -> int:
    if not ADDRESS_RE.match(a.reply_to):
        raise SystemExit("--reply-to must be an address (verified in SES while the account is in the sandbox)")
    started = datetime.now(timezone.utc)
    nonce = f"{started:%Y%m%d}-{secrets.token_hex(4)}"
    payload = {"exercise": {"nonce": nonce, "reply_to": a.reply_to, "designation": a.designation}}
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "out.json"
        aws("lambda", "invoke", "--function-name", FUNCTION, "--cli-binary-format", "raw-in-base64-out",
            "--payload", json.dumps(payload), str(out))
        result = json.loads(out.read_text())
    steps = {
        "classified_as_fedramp": result.get("designation") == a.designation,
        "registered": False,
        "acknowledgement_sent": (result.get("ack") or {}).get("status") == "sent",
        "page_published": (result.get("page") or {}).get("status") == "sent",
        "deadline_assigned": bool(result.get("respond_by")) if a.designation in ("EMERGENCY", "EMERGENCY_TEST") else None,
    }
    rid = result.get("exercise")
    if isinstance(rid, str) and ID_RE.match(rid):
        steps["registered"] = f"{OPEN}{rid}.json" in keys(f"{OPEN}{rid}.json")
    if a.smtp:
        steps["smtp_received_and_stored"] = _smtp_leg(nonce)["stored"]
    failures = [k for k, v in steps.items() if v is False]
    record = {
        "schema": "fsi-exercise/1",
        "exercise": True,
        "rule_ids": ["AFC-CSO-RCV", "AFC-CSO-ACK", "AFC-CSO-EMR", "AFC-CSO-CRA", "AFC-CSO-TFG"],
        "started_at": started.isoformat(timespec="seconds"),
        "designation": a.designation,
        "register_id": rid,
        "steps": steps,
        "ack_error": (result.get("ack") or {}).get("error"),
        "page_delivery": "published to the alert topic; the operator confirms the email arrived when closing the item",
        "result": "fail" if failures else "pass",
    }
    print(json.dumps(record, indent=2))
    if a.record:
        dest = Path(a.record) / f"fsi-exercise-{started:%Y-%m-%d}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(record, indent=2) + "\n")
        print(f"wrote {dest}")
    print(f"\nNext: confirm the page and the acknowledgement arrived, then\n"
          f"  python3 scripts/fsi.py close {rid} --outcome exercise-complete --note 'page and ack received'")
    return 1 if failures else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list")
    p.add_argument("--all", action="store_true")
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("show")
    p.add_argument("id")
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("triage")
    p.add_argument("id")
    p.add_argument("--respond-by")
    p.add_argument("--note")
    p.set_defaults(fn=cmd_triage)
    p = sub.add_parser("close")
    p.add_argument("id")
    p.add_argument("--outcome", required=True, choices=OUTCOMES)
    p.add_argument("--note", required=True)
    p.set_defaults(fn=cmd_close)
    p = sub.add_parser("exercise")
    p.add_argument("--reply-to", required=True)
    p.add_argument("--designation", default="EMERGENCY_TEST", choices=("EMERGENCY_TEST", "EMERGENCY", "IMPORTANT", "GENERAL"))
    p.add_argument("--smtp", action="store_true", help="also send one real message through SES receiving")
    p.add_argument("--record", help="directory to write the dated exercise record into (e.g. docs/exercises)")
    p.set_defaults(fn=cmd_exercise)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
