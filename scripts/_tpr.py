"""Third-party information resources for the CPO (MAS-CSO-TPR).

The CPO schema's `thirdPartyInformationResources` object, built from the
decided records in data/third-party-components.json. None of these resources is
recorded as FedRAMP certified, so every entry goes under `nonCertified`; this
module never asserts a resource's authorization status. A record without a
decision, or a decided record without a use case, fails closed: the CPO never
lists a resource the operator has not decided.
"""

import json
from pathlib import Path

THIRD_PARTY_PATH = Path(__file__).resolve().parent.parent / "data" / "third-party-components.json"


def _fail(msg):
    raise SystemExit(f"::error::third-party records: {msg} (fail-closed)")


def cpo_third_party_information_resources(path=THIRD_PARTY_PATH):
    """{"nonCertified": [{"name", "provider", "website"?, "useCase"}]}, one entry
    per third-party record, sorted by component ID."""
    try:
        recs = json.loads(Path(path).read_text())["components"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        _fail(f"cannot read {path} ({type(exc).__name__})")
    out = []
    for cid, rec in sorted(recs.items()):
        if not (rec.get("decided_by") and rec.get("decided_on")):
            _fail(f"{cid} has no decision (decided_by, decided_on)")
        use = rec.get("usage_and_configuration")
        name = rec.get("upstream_offering") or cid
        if not (isinstance(use, str) and use.strip() and rec.get("provider")):
            _fail(f"{cid} lacks provider or usage_and_configuration")
        entry = {"name": name, "provider": rec["provider"], "useCase": use}
        if isinstance(rec.get("website"), str) and rec["website"].startswith("https://"):
            entry["website"] = rec["website"]
        out.append(entry)
    return {"nonCertified": out}
