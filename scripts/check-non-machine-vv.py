#!/usr/bin/env python3
"""VDR-TFR-NMV: run the machine checks on every non-machine information resource
(scripts/_nonmachine.py) and write the verification and validation record.

    check-non-machine-vv.py [--register data/non-machine-resources.json]
                            [--decisions data/decisions.json] [--out vdr-non-machine-vv.json]
                            [--enforce]

--out writes the status the nightly and the deploy publish. --enforce exits 1
when any check fails (the deploy); without it the status is written with
status "lapsed" and verifiedAt at the epoch, so the published freshness window
turns the watchdog red at once (the nightly).
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402
import _decisions  # noqa: E402
import _nonmachine  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--register", default=None)
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--enforce", action="store_true")
    a = ap.parse_args(argv)
    doc = _nonmachine.load(a.register)
    reg = _decisions.load(a.decisions)
    st = _nonmachine.status(doc, reg)
    if a.out:
        Path(a.out).write_text(json.dumps(_offering.stamp_fedramp_id(st), indent=2) + "\n", encoding="utf-8")
    print(f"Non-machine V&V (VDR-TFR-NMV): {len(st['resources'])} resources, machine checks "
          f"{', '.join(st['checks'])}: {st['status']}")
    for p in st["problems"]:
        print(f"::{'error' if a.enforce else 'warning'}::non-machine V&V: {p}", file=sys.stderr)
    return 1 if (a.enforce and st["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
