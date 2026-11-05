# Significant-change evaluation: format and one example per type (SCN-CSO-EVA)

Every pull request (or direct push) to `main` carries an evaluation in its
description. [`.github/workflows/scn-tag.yml`](../../.github/workflows/scn-tag.yml)
fails the change without one; there is no default. The rules are in
[`scripts/_scn.py`](../../scripts/_scn.py).

```
SCN-Type: <not-significant | routine-recurring | adaptive | transformative | emergency | class-change>
SCN-Rationale: <one line: why the change is this type>
SCN-Record: SCN-YYYY-NNN    (adaptive, transformative and emergency only)
```

The deploy copies every merged evaluation into the append-only log at
`/.well-known/scn-evaluations.json` (SCN-CSO-MAR).

The types follow FedRAMP's definitions (FRD-SGC, FRD-RTR, FRD-ADP, FRD-TRF). A
change that is not likely to substantively affect the security or privacy
posture is **not-significant**. Examples marked *fictitious* are permitted by the
SCN-CSO-EVA artifact; they show the reasoning and are not changes to this system.

## not-significant

*Fictitious.* A typo fix on the about page.

```
SCN-Type: not-significant
SCN-Rationale: content-only edit to a public page; no component, boundary, data flow or access change.
```

## routine-recurring

*Fictitious.* The weekly Dependabot patch bump of a library already in the
inventory, with no breaking change.

```
SCN-Type: routine-recurring
SCN-Rationale: weekly patch bump of an inventoried library, part of ongoing vulnerability remediation; no breaking change.
```

No notification is made (SCN-RTR-NNR): the gate refuses an `SCN-Record` on this
type, and the register refuses a routine-recurring row.

## adaptive

*Real:* [SCN-2026-006](SCN-2026-006-remove-anthropic-interconnection.md), the
removal of the Anthropic API interconnection.

```
SCN-Type: adaptive
SCN-Rationale: removes an external interconnection, a boundary-crossing flow and a secret; no new service or data, no class change.
SCN-Record: SCN-2026-006
```

The record goes into [`scn-register.csv`](scn-register.csv) and is published
within 10 business days of the change finishing (SCN-ADP-NTF).

## transformative

*Fictitious.* The offering begins accepting agency user accounts and storing
their data: a new capability that changes how customers use the service.

```
SCN-Type: transformative
SCN-Rationale: introduces federal customer data and agency accounts, which changes existing risk determinations.
SCN-Record: SCN-2027-001
```

The record is written from [`TEMPLATE-transformative.md`](TEMPLATE-transformative.md)
first. The gate blocks the merge until the initial plan has been published 30
business days and the final plan 10 (SCN-TRF-NIP, SCN-TRF-NFP).

## emergency

*Fictitious.* A leaked credential is rotated immediately.

```
SCN-Type: emergency
SCN-Rationale: rotates a leaked credential now; waiting for notice windows would itself raise risk.
SCN-Record: SCN-2026-099
```

The retroactive record is due within 5 business days
([`docs/incident-response.md`](../incident-response.md)); the scheduled deadline
check ([`.github/workflows/scn-deadlines.yml`](../../.github/workflows/scn-deadlines.yml))
fails until it is in the register.

## class-change

*Fictitious.* A change that would move the offering out of Class C.

```
SCN-Type: class-change
SCN-Rationale: the offering would hold data that takes it above Class C.
```

The gate always fails this type: a class change is a new certification and
needs a new assessment, not a significant change notification.
