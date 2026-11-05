#!/usr/bin/env python3
"""Totally Real Assessment Services, LLC (simulated): the stand-in assessor.

SIMULATED. This is a GitHub Actions workflow in the provider's own repository
playing the part of an independent assessor, so the assessor port can be
exercised end to end on every deploy. It is not independent of the provider,
it is not a FedRAMP Recognized independent assessment service, it has no
FedRAMP assessor ID, and nothing it writes is a FedRAMP independent assessment.

What it does, on every deploy, before the Security Decision Record is built:

  verification  for each FedRAMP rule in the provider's assessor guide, checks
                the status is Implemented or Not Applicable and re-runs or
                re-reads every piece of evidence the guide names: runs every
                cited test itself (one pytest run), finds every cited workflow
                step, and looks every cited decision up in the register;
  validation    fetches every cited published artifact from the live site,
                verifies its Sigstore signature against the publishing
                workflow's identity, and checks its age against the governed
                window; and checks every KSI in the guide is in the live,
                signature-verified KSI signal.

It writes one result record per rule and per KSI and one overall summary
(IVV-IAS-OSA), in the provider's assessor-record format, into one set file. Its
workflow signs that file keylessly under the assessor's own workflow identity,
which the provider pins (infrastructure/keys/assessor-identity.json). It
imports nothing from the provider's scripts/.

Exit status is non-zero, and the deploy does not proceed, when any cited test
fails or does not run, a cited step or decision is missing, a status is short
of Implemented or Not Applicable, or a published artifact's signature does not
verify. An artifact not yet published (first published by the deploy under
assessment) or past its window is an observation, recorded but not fatal: the
deploy is what refreshes it.
"""

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404: runs pytest and cosign with fixed argument lists
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # nosec B405: parses the JUnit file this run's own pytest wrote
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ORG = "Totally Real Assessment Services, LLC (simulated)"
KEY_ID = "sigstore-keyless:simulated-assessor.yml"
SET_NAME = "simulated-assessment.json"
DISCLAIMER = (
    "SIMULATED. Totally Real Assessment Services, LLC is a GitHub Actions workflow in the provider's own "
    "repository, wearing a lanyard. It is not independent, it is not a FedRAMP Recognized independent "
    "assessment service, its assessor ID is NOT-A-REAL-ASSESSOR-ID, and nothing here is a FedRAMP independent "
    "assessment. It exists to show the assessor port working end to end. Our rates are very competitive: free.")
STEP_LINE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$")
ISSUER = "https://token.actions.githubusercontent.com"
COMPLETE = ("Implemented", "Not Applicable")


def canonical(record):
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- checks ---------------------------------------------------------------------------

def run_tests(refs, repo):
    """{ref: "passed" | "failed" | "skipped" | "not run"} from one pytest run."""
    if not refs:
        return {}
    with tempfile.TemporaryDirectory() as d:
        junit = Path(d) / "junit.xml"
        # Whole files, not node IDs: pytest refuses the entire run when one node
        # ID does not exist, and a missing cited test must read "not run" here.
        files = sorted({r.split("::", 1)[0] for r in refs if (Path(repo) / r.split("::", 1)[0]).is_file()})
        if files:
            subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}",
                            *files], cwd=repo, check=False)  # nosec B603: fixed argv
        cases = {}
        if junit.exists():
            for case in ET.parse(junit).getroot().iter("testcase"):  # nosec B314: own file
                parts = case.get("classname", "").split(".")
                func = case.get("name", "").split("[", 1)[0]
                if len(parts) >= 2 and parts[-1][:1].isupper():
                    key = "/".join(parts[:-1]) + f".py::{parts[-1]}::{func}"
                else:
                    key = "/".join(parts) + f".py::{func}"
                bad = case.find("failure") is not None or case.find("error") is not None
                out = "failed" if bad else "skipped" if case.find("skipped") is not None else "passed"
                cases.setdefault(key, []).append(out)
    res = {}
    for ref in refs:
        got = cases.get(ref.split("[", 1)[0])
        res[ref] = ("not run" if not got else "passed" if all(c == "passed" for c in got)
                    else "failed" if "failed" in got else "skipped")
    return res


def step_exists(repo, wf, step):
    p = Path(repo) / ".github" / "workflows" / wf
    if not p.is_file():
        return False
    return any((m := STEP_LINE.match(line)) and m.group(1).strip().strip("'\"") == step
               for line in p.read_text().splitlines())


def decision_in_force(repo, dec_id):
    doc = json.loads((Path(repo) / "data" / "decisions.json").read_text())
    return any(d.get("id") == dec_id and d.get("status") == "in-force" for d in doc.get("decisions", []))


ALLOWED_HOST = "samaydlette.com"


def http_get(url):
    """(status, body bytes, headers). 404 is a status, not an exception. Only
    HTTPS on the provider's own site: a guide entry naming another scheme (such
    as file://) or another host is refused rather than fetched."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST:
        raise SystemExit(f"::error::simulated assessor: refusing to fetch {url!r} (only https://{ALLOWED_HOST})")
    req = urllib.request.Request(url, headers={"User-Agent": "totally-real-assessor/1 (simulated)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310: https URLs from the guide
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, b"", dict(e.headers or {})


def cosign_verify(blob, bundle, identity):
    with tempfile.TemporaryDirectory() as d:
        b, s = Path(d) / "blob", Path(d) / "bundle"
        b.write_bytes(blob)
        s.write_bytes(bundle)
        r = subprocess.run(["cosign", "verify-blob", "--bundle", str(s), "--certificate-identity", identity,
                            "--certificate-oidc-issuer", ISSUER, str(b)],
                           capture_output=True, check=False)  # nosec B603: fixed argv
        return r.returncode == 0


def _age_hours(body, headers, ts, now):
    raw = None
    if ts.get("source") == "json":
        try:
            raw = json.loads(body)
            for part in ts["field"].split("."):  # dotted path, e.g. metadata.lastUpdated
                raw = raw.get(part) if isinstance(raw, dict) else None
        except ValueError:
            return None
        if not isinstance(raw, str):
            return None
        try:
            t = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        lm = headers.get("Last-Modified") or headers.get("last-modified")
        if not lm:
            return None
        t = parsedate_to_datetime(lm)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (now - t).total_seconds() / 3600


class Assessor:
    def __init__(self, guide, repo, now, get=None, verify=None, tests=None):
        self.guide, self.repo, self.now = guide, repo, now
        self.get, self.verify, self.tests = get or http_get, verify or cosign_verify, tests or run_tests
        self._artifacts = {}

    def artifact(self, chk):
        """(outcome, note): outcome is pass | observation | fail."""
        url = chk["url"]
        if url in self._artifacts:
            return self._artifacts[url]
        status, body, headers = self.get(url)
        name = url.rsplit("/", 1)[1]
        if status == 404:
            res = ("observation", f"{name} is not yet published; it is first published by the deploy under "
                                  "assessment, and validated at the next assessment")
        elif status != 200:
            res = ("fail", f"{name} returned HTTP {status}")
        else:
            notes = [f"{name} served"]
            res = None
            if chk.get("bundle_url"):
                bstatus, bundle, _ = self.get(chk["bundle_url"])
                ids = [self.guide["identities"][i] for i in chk["identities"]]
                if bstatus != 200 or not any(self.verify(body, bundle, i) for i in ids):
                    res = ("fail", f"{name}'s signature does not verify against "
                                   f"{' or '.join(chk['identities'])} identity")
                else:
                    notes.append(f"signature verified ({'/'.join(chk['identities'])} identity)")
            if res is None:
                age = _age_hours(body, headers, chk["timestamp"], self.now)
                if age is None:
                    res = ("observation", "; ".join(notes) + "; its age could not be read")
                elif age > chk["max_age_hours"]:
                    res = ("observation", "; ".join(notes) + f"; {age:.0f}h old, past its "
                                                             f"{chk['max_age_hours']}h window")
                else:
                    res = ("pass", "; ".join(notes) + f"; {age:.0f}h old (window {chk['max_age_hours']}h)")
        self._artifacts[url] = res
        return res

    def assess(self):
        rules = self.guide["rules"]
        test_refs = {ev["check"]["pytest"] for r in rules for ev in r["evidence"] if "pytest" in ev["check"]}
        test_res = self.tests(test_refs, self.repo)
        results = []
        for r in rules:
            ver, val, outcome = [], [], "pass"

            def worst(o):
                nonlocal outcome
                order = {"pass": 0, "observation": 1, "fail": 2}
                outcome = o if order[o] > order[outcome] else outcome

            if r["status"] not in COMPLETE:
                ver.append(f"status is {r['status']}, short of Implemented or Not Applicable")
                worst("fail")
            elif r["status"] == "Not Applicable":
                ver.append(f"Not Applicable ({r['force']}): {r.get('not_applicable', 'no reason given')}")
                if not r.get("not_applicable"):
                    worst("fail")
            for ev in r["evidence"]:
                chk = ev["check"]
                if "pytest" in chk:
                    res = test_res.get(chk["pytest"], "not run")
                    ver.append(f"test {chk['pytest']} {res} (re-run by the assessor)")
                    if res != "passed":
                        worst("fail")
                elif "workflow" in chk:
                    ok = step_exists(self.repo, chk["workflow"], chk["step"])
                    ver.append(f"step {chk['step']!r} {'present' if ok else 'MISSING'} in {chk['workflow']}")
                    if not ok:
                        worst("fail")
                elif "decision" in chk:
                    ok = decision_in_force(self.repo, chk["decision"])
                    ver.append(f"decision {chk['decision']} {'in force' if ok else 'NOT in force'}")
                    if not ok:
                        worst("fail")
                elif "artifact" in chk:
                    o, note = self.artifact(chk["artifact"])
                    val.append(note)
                    worst(o)
            if r["status"] == "Implemented" and not r["evidence"]:
                ver.append("Implemented with no evidence")
                worst("fail")
            if "simulated" in r:
                ver.append(f"relies on a simulated counterparty ({r['simulated']['counterparty']})")
            results.append((r["rule_id"], outcome, ver, val))
        return results, self.assess_ksis()

    def assess_ksis(self):
        guide = self.guide
        url = f"{guide['site']}/.well-known/ksi-signal.json"
        status, body, _ = self.get(url)
        bstatus, bundle, _ = self.get(f"{guide['site']}/.well-known/ksi-signal.bundle")
        if status != 200 or bstatus != 200 or not self.verify(body, bundle, guide["identities"]["deploy"]):
            return [(k["ksi_id"], "fail", ["the live KSI signal could not be fetched or its signature did "
                                           "not verify"], []) for k in guide["ksis"]]
        sig = json.loads(body)
        by_id = {k["id"]: k for k in sig.get("ksis", [])}
        out = []
        for k in guide["ksis"]:
            s = by_id.get(k["ksi_id"])
            if s is None:
                out.append((k["ksi_id"], "observation", [f"not in the published signal {sig.get('signal_id')}"],
                            []))
                continue
            if s.get("status") != "pass":
                out.append((k["ksi_id"], "fail",
                            [f"the published signal {sig.get('signal_id')} reports status {s.get('status')!r} "
                             f"(method {s.get('method')})"], []))
                continue
            out.append((k["ksi_id"], "pass",
                        [f"in the published signal {sig.get('signal_id')} with status {s.get('status')} by "
                         f"method {s.get('method')}"],
                        ["KSI signal served and its signature verified (deploy identity)"]))
        return out


# --- the record set ------------------------------------------------------------------------

def _record(rid, kind, text, issued, subject_id=None):
    rec = {"record_type": "assessor-record", "schema_version": "1", "record_id": rid,
           "assessor": {"organization": ORG, "key_id": KEY_ID}, "issued_at": issued, "kind": kind, "text": text}
    if subject_id:
        rec["rule_id"] = subject_id
    rec["signature"] = {"algorithm": "SIGSTORE_KEYLESS_SET", "value": hashlib.sha256(canonical(rec)).hexdigest(),
                        "signed_set": SET_NAME}
    return rec


def _text(what, outcome, ver, val):
    label = {"pass": "Pass", "observation": "Pass with observation", "fail": "FAIL"}[outcome]
    parts = [f"SIMULATED assessment of {what}, not a FedRAMP Recognized assessment. Result: {label}."]
    if ver:
        parts.append("Independent verification: " + "; ".join(ver) + ".")
    if val:
        parts.append("Independent validation: " + "; ".join(val) + ".")
    elif ver:
        parts.append("Independent validation: no published artifact cited; validated through the verification "
                     "above.")
    return " ".join(parts)


def build_set(guide, rule_results, ksi_results, now, commit, guide_sha):
    issued = now.replace(microsecond=0).isoformat()
    tag = now.strftime("%Y%m%dT%H%M%SZ")
    records = [_record(f"TRAS-{tag}-{rid}", "finding", _text(f"rule {rid}", o, ver, val), issued, rid)
               for rid, o, ver, val in rule_results]
    records += [_record(f"TRAS-{tag}-{kid}", "finding", _text(f"KSI {kid}", o, ver, val), issued, kid)
                for kid, o, ver, val in ksi_results]

    def count(res):
        return {o: sum(1 for x in res if x[1] == o) for o in ("pass", "observation", "fail")}

    rc, kc = count(rule_results), count(ksi_results)
    obs = [f"{x[0]}: {'; '.join(x[3] or x[2])}" for x in rule_results + ksi_results if x[1] == "observation"]
    fails = [x[0] for x in rule_results + ksi_results if x[1] == "fail"]
    summary = (f"Overall summary (IVV-IAS-OSA), SIMULATED. {ORG} verified and validated all "
               f"{len(rule_results)} applicable FedRAMP rules and all {len(ksi_results)} Key Security Indicators "
               f"for commit {commit or 'unknown'}: rules {rc['pass']} pass, {rc['observation']} pass with "
               f"observation, {rc['fail']} fail; KSIs {kc['pass']} pass, {kc['observation']} pass with "
               f"observation, {kc['fail']} fail. Failures: {', '.join(fails) or 'none'}. Areas of dispute: none. "
               f"Observations: {' | '.join(sorted(set(obs))) or 'none'}. {DISCLAIMER}")
    records.append(_record(f"TRAS-{tag}-SUMMARY", "summary", summary, issued))
    return {"assessment_type": "simulated-independent-assessment", "schema_version": "1",
            "simulated": True, "fedramp_recognized": False, "assessor_id": "NOT-A-REAL-ASSESSOR-ID",
            "disclaimer": DISCLAIMER, "assessor": {"organization": ORG, "key_id": KEY_ID},
            "issued_at": issued,
            "subject": {"site": guide["site"], "commit": commit, "assessor_guide_sha256": guide_sha},
            "results": {"rules": rc, "ksis": kc},
            "records": records}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simulated assessor (not a FedRAMP Recognized assessment).")
    ap.add_argument("--guide", required=True, help="the provider's assessor-guide.json")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--commit", default=None)
    ap.add_argument("--output", default=SET_NAME)
    a = ap.parse_args(argv)
    raw = Path(a.guide).read_bytes()
    guide = json.loads(raw)
    now = datetime.now(timezone.utc)
    rules, ksis = Assessor(guide, a.repo, now).assess()
    doc = build_set(guide, rules, ksis, now, a.commit, hashlib.sha256(raw).hexdigest())
    Path(a.output).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    fails = [x for x in rules + ksis if x[1] == "fail"]
    for x in fails:
        print(f"::error::simulated assessor: {x[0]} failed: {'; '.join(x[2] + x[3])}")
    print(f"simulated assessment: rules {doc['results']['rules']}, KSIs {doc['results']['ksis']}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
