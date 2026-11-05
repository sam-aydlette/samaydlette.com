#!/usr/bin/env python3
"""The SCN gate (SCN-CSO-EVA): every change carries an explicit evaluation.

Run by .github/workflows/scn-tag.yml over a pull request's description (or a
direct push's commit message). Passes only when the text carries:

    SCN-Type: not-significant | routine-recurring | adaptive | transformative | emergency | class-change
    SCN-Rationale: one line on why the change is that type
    SCN-Record: SCN-YYYY-NNN        (adaptive, transformative and emergency only)

There is no default: a missing or placeholder evaluation fails. class-change
always fails: a change of certification class is a new certification. A
transformative change fails until its initial plan has been published for 30
business days and its final plan for 10 (SCN-TRF-NIP/NFP), read from the
published notification index. Exit 0 pass, 1 fail.

    scn-evaluate.py --text-env PR_BODY --source "PR description"
    scn-evaluate.py --text-file body.md --index-file index.json --today 2026-11-05
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _scn  # noqa: E402

INDEX_URL = _scn.BASE + _scn.INDEX_NAME + ".json"


def fetch_index(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 (fixed https URL)
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"notifications": []}
        return None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--text-env", help="environment variable holding the text")
    src.add_argument("--text-file", help="file holding the text")
    ap.add_argument("--source", default="change description", help="what the text is, for messages")
    ap.add_argument("--index-file", help="the notification index (default: fetch the published one)")
    ap.add_argument("--index-url", default=INDEX_URL)
    ap.add_argument("--today", help="ISO date (tests)")
    a = ap.parse_args(argv)

    text = os.environ.get(a.text_env, "") if a.text_env else Path(a.text_file).read_text()
    today = date.fromisoformat(a.today) if a.today else date.today()
    needs_index = _scn.TYPE_LINE.search(text or "") and \
        _scn.normalize_type(_scn.TYPE_LINE.search(text).group(1)) == "transformative"
    index = None
    if needs_index:
        index = json.loads(Path(a.index_file).read_text()) if a.index_file else fetch_index(a.index_url)

    errors, notices, ev = _scn.gate(text, index, today)
    for n in notices:
        print(f"::notice::{n}")
    if errors:
        for e in errors:
            print(f"::error::SCN evaluation ({a.source}): {e}")
        print("See docs/policies/cm-policy.md and docs/scn/evaluation-examples.md for the format and examples.")
        return 1
    print(f"SCN-Type: {ev['type']} (from {a.source}); rationale: {ev['rationale']}"
          + (f"; record {ev['record']}" if ev["record"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
