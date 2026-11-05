#!/usr/bin/env python3
"""Independent availability monitor (CDS-CSO-AVR, CDS-TRC-USH).

Runs on GitHub Actions (.github/workflows/availability-probe.yml), outside AWS,
so it keeps reporting when the offering is down. Each run probes the core
services once over HTTPS, appends the result to the rolling history carried in
the previous feed, derives availability incidents, and writes:

  availability-status.json   machine-readable: current status, 30-day
                             availability per service, incidents, samples
  availability-status.md     the same for people

The workflow publishes both to the repository's `availability-status` branch,
served by GitHub (raw.githubusercontent.com and the github.com file view), not
by the offering's own CloudFront or S3.

An incident is a service failing on INCIDENT_MIN_SAMPLES or more consecutive
probes; it starts at the first failing probe and ends at the next passing one.
A single failed probe is counted as transient, not an incident, since one probe
from one runner can fail for reasons on the runner's side.

    availability-probe.py --previous prev.json --out-dir status      (probe)
    availability-probe.py --check-fresh feed.json --max-age-hours 2  (deploy guard)
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

SITE = "https://samaydlette.com"
COGNITO_UI = "https://samaydlette-com-silk-reeling.auth.us-east-2.amazoncognito.com/"
# (key, service, url, statuses that mean "up")
TARGETS = (
    ("site", "Website", f"{SITE}/", (200,)),
    ("trust-center", "Trust center", f"{SITE}/trust/", (200,)),
    ("certification-data", "Certification data (/.well-known/)", f"{SITE}/.well-known/ksi-signal.json", (200,)),
    ("silk-reeling", "Silk Reeling application", f"{SITE}/silk-reeling/", (200,)),
    ("silk-reeling-sign-in", "Silk Reeling sign-in (Cognito hosted UI)", COGNITO_UI, (200,)),
)
HISTORY_DAYS = 35
WINDOW_DAYS = 30
INCIDENT_MIN_SAMPLES = 2
TIMEOUT_S = 20
FEED_URL = ("https://raw.githubusercontent.com/sam-aydlette/samaydlette.com/"
            "availability-status/availability-status.json")
PAGE_URL = ("https://github.com/sam-aydlette/samaydlette.com/blob/"
            "availability-status/availability-status.md")


def _iso(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def fetch(url):
    """(up-or-status reason, HTTP status or None). No redirects followed."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "samaydlette-availability-probe"})
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:  # nosec B310: fixed https URLs
            resp.read(4096)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError) as exc:
        return f"no response ({type(getattr(exc, 'reason', exc)).__name__})"


def probe_once(fetcher, now):
    sample = {"t": _iso(now), "probed": [k for k, *_ in TARGETS], "fail": {}}
    for key, _service, url, ok in TARGETS:
        got = fetcher(url)
        if got not in ok:
            sample["fail"][key] = f"HTTP {got}" if isinstance(got, int) else str(got)
    return sample


def incidents(samples):
    """Incidents (>= INCIDENT_MIN_SAMPLES consecutive failures) and transient counts per service."""
    out, transient = [], {}
    services = {k: s for k, s, *_ in TARGETS}
    for key in services:
        run = []
        seq = [s for s in samples if key in s.get("probed", [])]
        for i, s in enumerate(seq + [None]):
            failed = s is not None and key in s.get("fail", {})
            if failed:
                run.append(s)
                continue
            if len(run) >= INCIDENT_MIN_SAMPLES:
                out.append({"service": key, "service_name": services[key], "start": run[0]["t"],
                            "end": s["t"] if s is not None else None, "failed_probes": len(run),
                            "failing_check": run[-1]["fail"][key]})
            elif run:
                transient[key] = transient.get(key, 0) + len(run)
            run = []
    return sorted(out, key=lambda x: (x["start"], x["service"])), transient


def availability(samples, now):
    since = now - timedelta(days=WINDOW_DAYS)
    out = {}
    for key, service, url, _ok in TARGETS:
        seq = [s for s in samples if key in s.get("probed", []) and _parse(s["t"]) >= since]
        up = sum(1 for s in seq if key not in s.get("fail", {}))
        out[key] = {"service": service, "url": url, "probes": len(seq), "up": up,
                    "availability_percent": round(100.0 * up / len(seq), 3) if seq else None}
    return out


def build(previous, sample, now):
    prev_samples = [s for s in (previous or {}).get("samples", []) if isinstance(s, dict) and "t" in s]
    cutoff = now - timedelta(days=HISTORY_DAYS)
    samples = [s for s in prev_samples if _parse(s["t"]) >= cutoff] + [sample]
    began = (previous or {}).get("history_began") or sample["t"]
    incs, transient = incidents(samples)
    window_start = _iso(now - timedelta(days=WINDOW_DAYS))
    return {
        "feed_type": "availability-status",
        "fedRampId": _offering.fedramp_id(),
        "rules": ["CDS-CSO-AVR", "CDS-TRC-USH"],
        "generated_at": sample["t"],
        "monitor": "GitHub Actions (.github/workflows/availability-probe.yml), outside AWS: it keeps "
                   "reporting when the offering is unavailable.",
        "published_at": {"json": FEED_URL, "human": PAGE_URL},
        "history_began": began,
        "history_note": "History begins at the monitor's first run; before that no independent "
                        "measurement exists. Scheduled runs are every 15 minutes, and GitHub may delay one.",
        "incident_rule": f"{INCIDENT_MIN_SAMPLES} or more consecutive failed probes of one service; a single "
                         "failed probe is counted as transient.",
        "current": {k: ("down" if k in sample["fail"] else "up") for k, *_ in TARGETS},
        "current_failures": sample["fail"],
        "window_days": WINDOW_DAYS,
        "availability": availability(samples, now),
        "incidents": [i for i in incs if (i["end"] or "9999") >= window_start],
        "transient_failures": transient,
        "samples": samples,
    }


def render_markdown(doc):
    cur = doc["current"]
    out = ["# Service availability (independent monitor)", "",
           f"_{doc['monitor']}_", "",
           f"- **Last probe:** {doc['generated_at']}",
           f"- **History began:** {doc['history_began']}. {doc['history_note']}",
           f"- **Incident rule:** {doc['incident_rule']}",
           f"- **Machine-readable:** {doc['published_at']['json']}", "",
           "## Now and over the past 30 days", "",
           "| Service | Now | Availability (30 days) | Probes |", "|---|---|---|---|"]
    for key, a in doc["availability"].items():
        pct = "n/a" if a["availability_percent"] is None else f"{a['availability_percent']}%"
        out.append(f"| {a['service']} | {cur.get(key, 'n/a')} | {pct} | {a['probes']} |")
    out += ["", "## Availability incidents (past 30 days)", ""]
    if not doc["incidents"]:
        out.append("None.")
    else:
        out += ["| Service | Start | End | Failed probes | Failing check |", "|---|---|---|---|---|"]
        for i in reversed(doc["incidents"]):
            out.append(f"| {i['service_name']} | {i['start']} | {i['end'] or 'ongoing'} | "
                       f"{i['failed_probes']} | {i['failing_check']} |")
    if doc["transient_failures"]:
        out += ["", "Transient (single) failed probes: " +
                ", ".join(f"{k} {v}" for k, v in sorted(doc["transient_failures"].items()))]
    out += ["", "---", "_Source of truth: `availability-status.json` on this branch._"]
    return "\n".join(out)


def ongoing_incidents(doc):
    return [i for i in doc.get("incidents", []) if i.get("end") is None]


def check_fresh(path, max_age_hours, now=None):
    """Problems with a fetched feed: [] when it is ours, well formed and fresh."""
    now = now or datetime.now(timezone.utc)
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return ["the independent availability feed is missing or not JSON"]
    if doc.get("feed_type") != "availability-status":
        return ["the independent availability feed is not an availability-status document"]
    try:
        age = now - _parse(doc["generated_at"])
    except (KeyError, ValueError):
        return ["the independent availability feed has no generated_at"]
    if age > timedelta(hours=max_age_hours):
        return [f"the independent availability feed is {age} old (limit {max_age_hours} h): the monitor "
                "on GitHub Actions is not running"]
    if not doc.get("samples"):
        return ["the independent availability feed carries no probes"]
    return []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--previous", default=None)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--check-fresh", default=None, metavar="FEED")
    ap.add_argument("--max-age-hours", type=float, default=2.0)
    ap.add_argument("--fail-on-incident", default=None, metavar="FEED",
                    help="exit 1 when FEED shows an ongoing incident (the workflow's alert)")
    a = ap.parse_args(argv)
    if a.fail_on_incident:
        doc = json.loads(Path(a.fail_on_incident).read_text())
        ongoing = ongoing_incidents(doc)
        for i in ongoing:
            print(f"::error::availability incident: {i['service_name']} down since {i['start']} "
                  f"({i['failing_check']})", file=sys.stderr)
        return 1 if ongoing else 0
    if a.check_fresh:
        why = check_fresh(a.check_fresh, a.max_age_hours)
        for w in why:
            print(f"::error::availability: {w}", file=sys.stderr)
        if not why:
            print("ok: the independent availability feed is present and fresh")
        return 1 if why else 0
    previous = {}
    if a.previous and Path(a.previous).exists():
        try:
            previous = json.loads(Path(a.previous).read_text())
        except json.JSONDecodeError:
            previous = {}
    if previous.get("feed_type") != "availability-status":
        previous = {}
    started = time.monotonic()
    now = datetime.now(timezone.utc)
    doc = build(previous, probe_once(fetch, now), now)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "availability-status.json").write_text(json.dumps(doc, indent=1) + "\n")
    (out / "availability-status.md").write_text(render_markdown(doc) + "\n")
    down = sorted(doc["current_failures"])
    print(f"probed {len(TARGETS)} services in {time.monotonic() - started:.1f}s; down: {down or 'none'}; "
          f"{len(doc['samples'])} samples kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
