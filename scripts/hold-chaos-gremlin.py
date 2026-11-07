#!/usr/bin/env python3
"""Hold the monthly Chaos Gremlin restore drill, from the evidence nightly (KSI-RPL-TRC, KSI-RPL-RRO; CP-4, CP-9(1), CP-10).

No person runs it (DEC-195). On the first of every month the nightly copies a
sample of the deployed site into a versioned scratch bucket, lets the Chaos
Gremlin (simulated) loose on it, and restores what it broke from S3 object
versions, the restore docs/recovery-plan.md names for site content:

  (a) copied in       a sample of the files the deploy uploads, chosen afresh
                      from the due date, is fetched from the live site; each
                      must match the deployed commit in git (sha256, the
                      deploy's cache-busting query string aside) before it is
                      put into the scratch bucket;
  (b) damage          the Gremlin deletes some objects and overwrites others
                      with its own bytes, and the damage is read back (a drill
                      whose damage did not land proves nothing);
  (c) restore         each damaged object is restored by copying its newest
                      version written before the damage over the current one,
                      and every object in the sample is read back and must
                      match the deployed commit (sha256);
  (d) objectives      the measured restore time must be inside the recovery
                      time objective, and the restored versions' age at the
                      time of the damage inside the recovery point objective,
                      both read from data/recovery-objectives.json;
  (e) planted forgery the same comparison is fed the Gremlin's forged bytes in
                      place of one restored object, every run, and must catch it.

The scratch bucket (infrastructure/bootstrap/recovery-drill.tf) is versioned,
private, encrypted and expires everything after seven days. The nightly role
may put, read, read versions of and delete objects in it, and nothing else in
it; it cannot delete a version, so the history the restore uses cannot be
purged by the drill. Nothing touches the production bucket: the live site is
only read over HTTPS.

It writes vdr-drill-chaos-gremlin-<due date>.json and .view.md (never rewritten) and
the index vdr-drill-chaos-gremlins.json. A failing drill is not frozen: the run
fails and the next run holds it again; scripts/check-scheduled-review.py fails
the nightly and the deploy from the day after a due date with none published.

  hold-chaos-gremlin.py --commit SHA [--previous-index vdr-drill-chaos-gremlins.json] \\
      --out DIR --new-files FILE [--bucket NAME]
"""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _offering  # noqa: E402
import _recovery_objectives  # noqa: E402
import _scheduled_review as sr  # noqa: E402

RV = sr.REVIEWS["chaos-gremlin"]
BUCKET = "samaydlette-com-recovery-drill"
BUCKET_ADDRESS = "aws_s3_bucket.recovery_drill (infrastructure/bootstrap/recovery-drill.tf)"
SAMPLE = 20
DELETE = 3
OVERWRITE = 3
GREMLIN_BYTES = b"The Chaos Gremlin (simulated) was here. It ate your file and left this note. Restore from versions."
# S3 LastModified is whole seconds: wait past the copy-in's last second before the damage.
SETTLE_SECONDS = 2.0


def _fail(msg):
    raise SystemExit(f"::error::chaos gremlin: {msg} (fail-closed)")


def _rx():
    spec = importlib.util.spec_from_file_location("recovery_for_gremlin", HERE / "hold-recovery-exercise.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _sha(rel, body, normalize):
    return hashlib.sha256(normalize(rel, body)).hexdigest()


def _rank(seed, rel):
    return hashlib.sha256(f"{seed}:{rel}".encode()).hexdigest()


def sample(tree, due, n=SAMPLE):
    """The files drilled this month: addressable at the edge, chosen from the due
    date so each month draws a different set; index.html always among them."""
    addressable = [r for r in tree if "." in r.rsplit("/", 1)[-1]]
    picked = sorted(addressable, key=lambda r: _rank(due.isoformat(), r))[:n]
    if "index.html" in tree and "index.html" not in picked:
        picked = ["index.html", *picked[:n - 1]]
    return sorted(picked)


def damage_plan(keys, due):
    """(deleted, overwritten): the Gremlin's choices, also from the due date."""
    order = sorted(keys, key=lambda r: _rank(f"gremlin:{due.isoformat()}", r))
    return sorted(order[:DELETE]), sorted(order[DELETE:DELETE + OVERWRITE])


# --- the scratch bucket ---------------------------------------------------------------------

class S3Error(Exception):
    pass


class S3Cli:
    """The drill's S3 calls through the AWS CLI with the nightly role's credentials."""

    def __init__(self, bucket=BUCKET, region="us-east-2"):
        self.bucket, self.region = bucket, region
        self._tmp = tempfile.TemporaryDirectory(prefix="gremlin-")

    def _run(self, args, parse=True):
        p = subprocess.run(["aws", "s3api", *args, "--bucket", self.bucket, "--region", self.region,  # nosec B603
                            "--output", "json"], capture_output=True, text=True, timeout=120, check=False)
        if p.returncode != 0:
            code = next((w for w in ("AccessDenied", "NoSuchKey", "NoSuchBucket", "NoSuchVersion")
                         if w in p.stderr), "Unknown")
            raise S3Error(f"s3api {args[0]}: {code}")
        return json.loads(p.stdout or "{}") if parse else None

    def _file(self, name):
        return str(Path(self._tmp.name) / hashlib.sha256(name.encode()).hexdigest())

    def put(self, key, body):
        f = self._file(key)
        Path(f).write_bytes(body)
        return self._run(["put-object", "--key", key, "--body", f]).get("VersionId")

    def delete(self, key):
        self._run(["delete-object", "--key", key])

    def get(self, key):
        """The current object's bytes, or None when its latest version is a delete marker."""
        f = self._file(key + "#get")
        try:
            self._run(["get-object", "--key", key, f])
        except S3Error as exc:
            if "NoSuchKey" in str(exc):
                return None
            raise
        return Path(f).read_bytes()

    def versions(self, key):
        """[{version_id, last_modified, delete_marker}] of exactly `key`."""
        out = self._run(["list-object-versions", "--prefix", key])
        rows = [{"version_id": v["VersionId"], "last_modified": _ts(v["LastModified"]), "delete_marker": False}
                for v in out.get("Versions") or [] if v.get("Key") == key]
        rows += [{"version_id": v["VersionId"], "last_modified": _ts(v["LastModified"]), "delete_marker": True}
                 for v in out.get("DeleteMarkers") or [] if v.get("Key") == key]
        return rows

    def restore_version(self, key, version_id):
        src = f"{self.bucket}/{urllib.parse.quote(key)}?versionId={urllib.parse.quote(version_id)}"
        self._run(["copy-object", "--key", key, "--copy-source", src])


def _ts(v):
    t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


# --- the drill ------------------------------------------------------------------------------

def restore(s3, key, incident_at):
    """Copy the newest version written before the damage over the current one;
    returns that version's last-modified time, or None when there is none."""
    floor = incident_at.replace(microsecond=0)
    good = [v for v in s3.versions(key) if not v["delete_marker"] and v["last_modified"] < floor]
    if not good:
        return None
    best = max(good, key=lambda v: v["last_modified"])
    s3.restore_version(key, best["version_id"])
    return best["last_modified"]


def mismatches(bodies, tree, normalize):
    """Keys whose bytes are missing or differ from the deployed commit."""
    return sorted(rel for rel, body in bodies.items()
                  if body is None or _sha(rel, body, normalize) != _sha(rel, tree[rel], normalize))


def drill(due, tree, get, s3, objectives, normalize, prefix, clock=time.monotonic, wallclock=None,
          sleep=time.sleep):
    """Run the drill; returns (checks, record). `get` fetches the live site."""
    wallclock = wallclock or (lambda: datetime.now(timezone.utc))
    gremlin = sr.CAST["gremlin"]
    rels = sample(tree, due)
    key = {r: f"{prefix}{r}" for r in rels}
    checks, transcript = [], []

    def check(cid, title, ok, detail):
        checks.append({"id": cid, "title": title, "result": "pass" if ok else "fail", "detail": detail})

    # (a) copy in, each object proved to be the deployed commit first
    differ, unreachable = [], []
    for r in rels:
        status, body = get(f"https://samaydlette.com/{urllib.parse.quote(r)}")
        if status != 200:
            unreachable.append(r)
        elif _sha(r, body, normalize) != _sha(r, tree[r], normalize):
            differ.append(r)
        else:
            s3.put(key[r], body)
    copied = len(rels) - len(differ) - len(unreachable)
    check("copied-in", "Deployed site objects fetched live, each identical to the deployed commit, and copied into "
                       "the versioned scratch bucket", copied == len(rels) and copied > 0,
          f"{copied} of {len(rels)} copied" + (f"; differ from the commit: {', '.join(differ)}" if differ else "")
          + (f"; not served: {', '.join(unreachable)}" if unreachable else ""))
    if copied != len(rels) or not rels:
        return checks, {"objects": rels, "transcript": transcript}
    transcript.append({"speaker": gremlin, "line": f"Ooh, {len(rels)} shiny files. I will have some of those."})

    # (b) the damage, read back
    sleep(SETTLE_SECONDS)
    incident_at = wallclock()
    deleted, overwritten = damage_plan(rels, due)
    for r in deleted:
        s3.delete(key[r])
    for r in overwritten:
        s3.put(key[r], GREMLIN_BYTES)
    landed = [r for r in deleted if s3.get(key[r]) is None] + \
             [r for r in overwritten if s3.get(key[r]) == GREMLIN_BYTES]
    check("damage", f"{gremlin} deleted {len(deleted)} object(s) and overwrote {len(overwritten)}, and the damage "
                    "read back", len(landed) == len(deleted) + len(overwritten),
          f"{len(landed)} of {len(deleted) + len(overwritten)} damaged objects read back damaged")
    transcript.append({"speaker": gremlin, "line": f"Deleted {', '.join(deleted)}. Scribbled on "
                                                    f"{', '.join(overwritten)}. Nobody will ever know."})

    # (c) restore from versions, timed, then read every object back
    started = clock()
    points, lost = {}, []
    for r in deleted + overwritten:
        at = restore(s3, key[r], incident_at)
        if at is None:
            lost.append(r)
        else:
            points[r] = at
    bodies = {r: s3.get(key[r]) for r in rels}
    elapsed = clock() - started
    bad = mismatches(bodies, tree, normalize)
    check("restored", "Every damaged object restored from its prior version, and every object in the drill matches "
                      "the deployed commit (sha256)", not lost and not bad,
          f"{len(points)} restored from versions, {len(rels) - len(bad)} of {len(rels)} match the commit"
          + (f"; no prior version: {', '.join(lost)}" if lost else "") + (f"; differ: {', '.join(bad)}" if bad else ""))
    transcript.append({"speaker": "Versioning", "line": "I kept every version. I always keep every version."})

    # (d) the objectives
    rto_h, rpo_h = objectives["rto"]["hours"], objectives["rpo"]["hours"]
    check("rto", f"The restore took less than the recovery time objective ({objectives['rto']['stated']})",
          elapsed <= rto_h * 3600, f"restored and verified in {elapsed:.1f} seconds; the objective is {rto_h} hours")
    ages = [(incident_at - t).total_seconds() for t in points.values()]
    oldest = max(ages) if ages else None
    check("rpo", f"Every restore point was younger than the recovery point objective ({objectives['rpo']['stated']}) "
                 "when the damage happened", oldest is not None and 0 <= oldest <= rpo_h * 3600,
          f"the oldest restored version was {oldest:.0f} seconds old at the damage; the objective is {rpo_h} hours"
          if oldest is not None else "no object was restored")

    # (e) the planted forgery: the Gremlin's bytes passed off as one restored object
    target = overwritten[0] if overwritten else rels[0]
    forged = {**bodies, target: GREMLIN_BYTES}
    caught = mismatches(forged, tree, normalize) == sorted(set(bad) | {target})
    check("forgery-caught", f"A planted forgery ({gremlin}'s bytes in place of one restored object) is caught by the "
                            "same comparison", caught, f"the comparison flagged {target}" if caught
          else "the comparison did not flag the forged object")
    transcript.append({"speaker": gremlin, "line": "Fine. I also tried swapping one back in after the restore. "
                                                   "The hashes noticed. They always notice."})
    return checks, {"objects": rels, "damaged": {"deleted": deleted, "overwritten": overwritten},
                    "incidentAt": incident_at.isoformat(), "restoreSeconds": round(elapsed, 3),
                    "oldestRestorePointSeconds": None if oldest is None else round(oldest, 3),
                    "transcript": transcript}


def build(due, now, fedramp_id, tree, get, s3, commit, objectives, normalize, **kw):
    prefix = f"drill/{due.isoformat()}/{now.strftime('%Y%m%dT%H%M%S')}/"
    checks, record = drill(due, tree, get, s3, objectives, normalize, prefix, **kw)
    doc = sr.base_doc(RV, due, now, fedramp_id, f"Chaos Gremlin restore drill for {due:%B %Y} (automated; the "
                                                "Gremlin is simulated, the damage and the restore are real)")
    doc.update({"rules": ["KSI-RPL-TRC", "KSI-RPL-RRO"], "controls": ["cp-4", "cp-9.1", "cp-10"],
                "deployedCommit": commit, "bucket": BUCKET_ADDRESS, "keyPrefix": prefix,
                "objectives": {"rtoHours": objectives["rto"]["hours"], "rpoHours": objectives["rpo"]["hours"],
                               "source": "data/recovery-objectives.json"},
                "gremlin": sr.CAST["gremlin"],
                "method": "scripts/hold-chaos-gremlin.py, run by evidence-nightly.yml on its due date: deployed objects "
                          "are copied into a versioned scratch bucket, damaged, and restored from S3 object versions "
                          "(docs/recovery-plan.md, Backup alignment). Production is only read.",
                "plan": "docs/recovery-plan.md", "drill": record,
                "checks": checks, "result": sr.result_of(checks)})
    return sr.finish(doc, "the Chaos Gremlin drill")


def run(previous, out, now, fedramp_id, commit, s3, get=None, repo=None, objectives=None, **kw):
    rx = _rx()
    today = now.date()
    due = sr.due_now(RV, previous, today)
    entries, files, failed = [], [], []
    if due:
        tree = rx.site_tree(commit, repo or rx.REPO)
        objectives = objectives or _recovery_objectives.load()
        for d in due:
            try:
                doc = build(d, now, fedramp_id, tree, get or rx.http_get, s3, commit, objectives, rx.normalize, **kw)
            except S3Error as exc:
                print(f"::error::chaos gremlin drill due {d}: the scratch bucket could not be used ({exc}); apply "
                      "infrastructure/bootstrap/recovery-drill.tf (the deploy's secure-configuration comparison, "
                      "ci-roles.nightly-recovery-drill-scope, fails until it is applied)")
                failed.append(d)
                continue
            if doc["result"] != "pass":
                for c in doc["checks"]:
                    if c["result"] != "pass":
                        print(f"::error::chaos gremlin drill due {d}: {c['title']}: {c['detail']}")
                failed.append(d)
                continue
            entry, written = sr.write(out, RV, d, doc)
            entries.append(entry)
            files += written
    index = sr.index_doc(RV, previous, entries, now, fedramp_id)
    sr.write_json(out, RV.index, index)
    return index, entries, files, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--commit", required=True, help="the commit the published inventory was built from")
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--new-files", default=None)
    ap.add_argument("--bucket", default=BUCKET)
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    now = sr.now_utc(a.now)
    prev = Path(a.previous_index) if a.previous_index else None
    previous = json.loads(prev.read_text()) if prev and prev.is_file() else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    index, entries, files, failed = run(previous, out, now, _offering.fedramp_id(), a.commit, S3Cli(a.bucket))
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in files))
    for e in entries:
        print(f"chaos gremlin drill due {e['dueDate']}: {e['result']}")
    print(f"chaos gremlin drills: {len(index['reviews'])} held; next due {index['nextDueDate']}")
    if failed:
        _fail(f"the drill due {', '.join(map(str, failed))} did not pass; it is held again on the next run once fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
