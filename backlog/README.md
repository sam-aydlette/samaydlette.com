# Backlog

One file per task, named `NNN-short-slug.md`, numbered in filing order. Each file opens with a one-line title followed by single-paragraph fields, then `---` and free-form notes:

```
# <one-sentence title>
REPO: <repository the task changes>
STATUS: <QUEUED | IN_PROGRESS | PARKED | DONE | FAILED>
RESOLUTION: <only when STATUS is DONE; see below>
REVIVE WHEN: <only when STATUS is PARKED; see below>
ACCEPTANCE: <runnable checks that prove the task is done>
OUT OF SCOPE: <what the task must not change>
LANDMINES: <measured traps, with file:line and the commit they were measured on>
DEPENDS ON: <task numbers, or "none">
LIVE-EDGE: <how to verify the outcome against production, not the build>
---
<notes>
```

`DEPENDS ON` and `LIVE-EDGE` were added on 2026-10-22. Older items gained `DEPENDS ON` when they were re-measured; `LIVE-EDGE` is required for new items.

## Closing an item

`STATUS` takes only the five values above. Close an item with `STATUS: DONE` plus a `RESOLUTION:` line that gives one of the following and a date:

- `completed`
- `folded into NNN (survives: …)`: list what carries over into the other task.
- `superseded by …`
- `obsolete`: give the reason.

`FAILED` is only for an attempt that was made and did not work. Parking uses `STATUS: PARKED` plus a `REVIVE WHEN:` line naming the event that would bring the item back.

## Sequence: data-mesh and fabric plan (filed 2026-10-22)

The aim is to make the proof of concept show domain ownership, data as a product, a self-serve platform and federated computational governance across two CSOs: the website and Silk Reeling. One authorization boundary contains both, the shared services are published once, and a portfolio query runs over the published products in place.

Trunk changes (`scripts/build-ksi-signal.py`, `scripts/reconcile.py`, or any published signed artifact) land one at a time, in order. Leaves run in parallel.

| Phase | Items | Notes |
|---|---|---|
| 0: leaves | 009, 010, 011, 012, 004, then 001 | 010 after 009. 001 lands last in the phase, after human PR #427, and before any trunk change. |
| 1: trunk preparation | 003 → 005 → 006 | 013 and 014 (data files and schemas only) run alongside. |
| 2: MVP trunk | 015 → 016 → 017 → 018 → 019 → 020 → 021 → 022 → 023 → 024 | 025 after 019 and 021, alongside 022 and 023. 034's mockups once 014 lands; its build after 018, 024 and 025. 023 is a security decision and an operator-applied bootstrap change. |
| 3: optional | 026–033, 008 (after 018) | 007 is parked. 002 is folded into 019. |

The minimum set that meets the plan's acceptance test is Phases 0–2. A visitor can then verify:

- each product's owner, contract and live freshness
- two signed CSO products
- the portfolio query
- global and local decision rights
- the statement that one person holds every role
- the service-model map

The plan makes no claim of certification, authorization, an agency sponsor or federal data. It adds no synthetic system. A third system (InsightWeaver) is deliberately excluded for now; the registry design makes adding one a data change.
