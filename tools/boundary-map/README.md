# Boundary map exporter (local only)

Produces the live map on `/research/authorization-boundary.html` from a local RAMPART
instance: TAP (The Analogy Platform) running the samsite plugin. Like `tools/essay`, it
never runs in CI; the pipeline publishes whatever snapshot is committed.

## Why it works this way

- **TAP collects and lays out; the site only redraws.** The exporter reads back the scene
  TAP drew (positions, groups, flags, flows) instead of recomputing a layout, so the map
  on the site is TAP's output, not an approximation of it.
- **The meaning is versioned here.** `docs/boundary/boundary-classification.json` says
  which zone and group each resource belongs to, what exists but is not collected, and
  the data-flow table. The exporter feeds it to TAP before every export and records its
  SHA-256 in the snapshot, so a snapshot names the exact classification that produced it.
- **Static, not hosted.** TAP's pages all sit behind a login and its compose stack is a
  development stack, so it cannot serve the public. A static snapshot keeps the site's
  CSP (`script-src 'self'`, `connect-src 'self'`), cost and boundary unchanged.
- **Per export, not per build.** CI cannot run TAP (it needs the stack, the collector
  credentials and a passkey-gated instance). The snapshot carries its collection time
  and each collector's last run, and the page shows its age.

## Running it

Prerequisites: a TAP session with the samsite plugin's boundary page (the operator's
`rampart/phase0` branch at the time of writing) up at `http://localhost:8220`, its
collectors run recently, and Playwright:

```
python3 -m pip install -r tools/boundary-map/requirements.txt
python3 -m playwright install chromium-headless-shell
make boundary-map                       # or: python3 tools/boundary-map/export.py --help
```

Then review the diff to `website/assets/boundary-map/` and commit it with the change
that motivated it. `make check` runs `tests/test_boundary_map.py` against the committed
snapshot.

## What it will not publish

The export fails, writing nothing, if the snapshot contains an ARN, a 12-digit account
ID or an email address. Only the classification tags that are public by design are kept
(`Archetype`, `DataClassification`, `DataSensitivity`, `InternetReachable`,
`MissionCriticality`, `Environment`). Resource names are kept: every name on the map is
already published in the `/.well-known/` artifacts or the public Terraform.

AWS resources that the latest successful AWS collection did not see are left off the map
and listed under `not_seen_in_latest_collection`, because TAP's AWS collector does not
retire resources that have been deleted.
