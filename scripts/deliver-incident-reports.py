#!/usr/bin/env python3
"""Deliver every incident report to a SIMULATED FedRAMP and agency recipient.

IEC-CSO-IIR/OIR/FIR ask that each report reach FedRAMP and every affected
agency; IEC-CSO-AIR asks that this be automated. This proof of concept has no
FedRAMP certification and no agency customer, so by the operator's decision the
recipients are simulated and NOTHING IS SENT. What is real is the mechanism:
every report the incident log lists is read back, checked against the sha256
the log published for it and against FedRAMP's incident report schema, and
handed to each recipient, whose (simulated) receipt is the hash it received.

Any failure exits 1 and writes nothing, which stops the deploy (and the
unattended publisher) before anything is published:
  - a report the log lists is missing, or its bytes differ from the log's sha256
  - a report does not validate against FedRAMP's incident report schema
  - a report file in the directory is not listed in the log
  - a reportable incident has a report with no FedRAMP or no agency recipient

On success it writes incident-deliveries.json, the delivery log, labelled as a
simulation, for the workflow to sign and publish under /.well-known/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _offering  # noqa: E402
import _fedramp_schema as fs  # noqa: E402

FEDRAMP = "FedRAMP Incident Desk (simulated): accepts every report, replies to none, and has never heard of this system"
DEFAULT_AGENCY = "Department of Hypothetical Affairs (simulated): this system has no agency customer"
NOTICE = ("SIMULATION. Every incident report below was 'delivered' to simulated recipients: nothing was sent to "
          "FedRAMP or to any agency, and no inbox anywhere received anything. The delivery mechanism is real and runs "
          "on every deploy and every unattended publish: each report is read back, checked against the sha256 in "
          "incident-reports.json and against FedRAMP's incident report schema, and its receipt is that hash. A "
          "delivery that fails stops publication. Real recipients would need an operator decision and a FedRAMP "
          "certification, neither of which exists.")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def deliver(log: dict, report_dir: Path, now: str | None = None, registry=None) -> tuple[dict | None, list[str]]:
    """(delivery log, problems). The delivery log is None when there are problems."""
    problems: list[str] = []
    deliveries = []
    listed = set()
    for inc in log.get("incidents", []):
        reports = inc.get("reports") or []
        if reports and not (inc.get("evaluation") or {}).get("reportable"):
            problems.append(f"{inc.get('id')}: reports issued for an incident evaluated not reportable")
        for r in reports:
            name = r.get("file") or ""
            listed.add(name)
            path = report_dir / name
            if "/" in name or not name.startswith("incident-INC-") or not path.is_file():
                problems.append(f"{inc.get('id')}: report {name!r} is listed but missing")
                continue
            got = sha256(path)
            if got != r.get("sha256"):
                problems.append(f"{name}: bytes differ from the sha256 the incident log publishes")
                continue
            doc = json.loads(path.read_text())
            errors = fs.validate(doc, "incident", registry)
            if errors:
                problems.append(f"{name}: does not validate against FedRAMP's incident report schema ({errors[0]})")
                continue
            agencies = [a for a in (doc.get("affectedAgencies") or []) if isinstance(a, str) and a.strip()]
            recipients: list[dict[str, object]] = [{"recipient": FEDRAMP, "kind": "fedramp"}]
            recipients += [{"recipient": f"{a} (simulated)", "kind": "agency"} for a in agencies] or \
                [{"recipient": DEFAULT_AGENCY, "kind": "agency"}]
            for rc in recipients:
                rc.update(simulated=True, transport="none: simulated, nothing sent", receipt_sha256=got,
                          result="accepted (simulated)")
            kinds = {rc["kind"] for rc in recipients}
            if kinds != {"fedramp", "agency"}:
                problems.append(f"{name}: no FedRAMP and agency recipient")
            deliveries.append({"incident": inc.get("id"), "exercise": bool(inc.get("exercise")),
                               "report_type": r.get("type"), "file": name, "sha256": got,
                               "issued_at": r.get("issued_at"), "recipients": recipients})
    for path in sorted(report_dir.glob("incident-INC-*.json")):
        if path.name not in listed:
            problems.append(f"{path.name}: a report file the incident log does not list")
    if problems:
        return None, problems
    return {
        "schema": "incident-deliveries/1",
        "simulation": True,
        "notice": NOTICE,
        "engagement": _engagement.STATEMENT,
        "emitted_at": now or datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/deliver-incident-reports.py",
        "incident_log": "https://samaydlette.com/.well-known/incident-reports.json",
        "incident_log_emitted_at": log.get("emitted_at"),
        "summary": {"reports_delivered": len(deliveries),
                    "recipients_reached": sum(len(d["recipients"]) for d in deliveries),
                    "messages_actually_sent": 0},
        "deliveries": deliveries,
    }, []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", type=Path, default=Path("."), help="where incident-reports.json and the reports are")
    ap.add_argument("--output", type=Path, default=None)
    a = ap.parse_args(argv)
    log = json.loads((a.dir / "incident-reports.json").read_text())
    out, problems = deliver(log, a.dir)
    for p in problems:
        print(f"::error::incident report delivery (simulated): {p}")
    if problems or out is None:
        print(f"incident report delivery: {len(problems)} problem(s); nothing delivered, nothing written")
        return 1
    target = a.output or (a.dir / "incident-deliveries.json")
    target.write_text(json.dumps(_offering.stamp_fedramp_id(out), indent=2) + "\n")
    print(f"incident report delivery (SIMULATED, nothing sent): {out['summary']['reports_delivered']} report(s) to "
          f"{out['summary']['recipients_reached']} simulated recipient(s); wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
