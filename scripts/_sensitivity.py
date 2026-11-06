"""Sensitivity screen for the Ongoing Certification Report (CCM-OCR-LSI, CCM-QTR-NID).

The OCR and the content prepared for a Quarterly Review are public. Before
either is written, every string in it is screened for what would help an
attacker or identify a person, and the build fails closed on any hit:

  account-id   a standalone twelve-digit number (an AWS account ID; _redact)
  email        an email address outside the system's domain and FedRAMP's
  ipv4         an IPv4 address
  aws-key      an AWS access key ID (AKIA/ASIA...)
  token        a GitHub token or a private key block
  handle       a GitHub @handle (feedback summaries are anonymized: no names)

What it reports never repeats the matched text. The operator's judgment of
anything the screen cannot see is recorded per report as the public-release
determination (CCM-OCR-RPS), a decision record.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _redact  # noqa: E402

ALLOWED_EMAIL_DOMAINS = ("samaydlette.com", "fedramp.gov", "gsa.gov")
PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"),
    "ipv4": re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"),
    "aws-key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "handle": re.compile(r"(?<![\w.@/])@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?![\w@.-])"),
}
CHECKS = ("account-id", *PATTERNS)
# Identifiers the build itself mints (a UUID can end in twelve digits); never prose.
SKIP_KEYS = ("ksi_signal_id", "contentSha256", "sha256")


def _strings(value, path=""):
    if isinstance(value, str):
        yield path or "/", value
    elif isinstance(value, dict):
        for k, v in value.items():
            if k not in SKIP_KEYS:
                yield from _strings(v, f"{path}/{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}/{i}")


def screen(doc):
    """[(json path, check)] for every hit in `doc` (a JSON value or a string)."""
    hits = []
    for where, text in _strings(doc):
        if _redact.find(text):
            hits.append((where, "account-id"))
        for name, rx in PATTERNS.items():
            for m in rx.finditer(text):
                if name == "email" and m.group(1).lower() in ALLOWED_EMAIL_DOMAINS:
                    continue
                hits.append((where, name))
    return hits


def require_clean(doc, what):
    hits = screen(doc)
    if hits:
        shown = "; ".join(f"{w} ({c})" for w, c in hits[:10])
        raise SystemExit(f"::error::sensitivity screen: {what} carries {len(hits)} item(s) that must not be "
                         f"published: {shown} (fail-closed)")
    return {"checks": list(CHECKS), "findings": 0}
