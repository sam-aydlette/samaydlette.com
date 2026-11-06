# SCN-YYYY-NNN — Transformative change: <title>

Copy this file to `SCN-YYYY-NNN-<slug>.md` and add the row to
[`scn-register.csv`](scn-register.csv) **before** the change starts. The
register row is what the deploy publishes and what the checks read; the columns
named below are required by [`scripts/_scn.py`](../../scripts/_scn.py) for a
transformative row.

## Timeline and notices

| Notice | Rule | When | Register column that drives it |
| --- | --- | --- | --- |
| Initial plan | SCN-TRF-NIP | published ≥ 30 business days before `date_started` | the row exists with `date_started` |
| Final plan | SCN-TRF-NFP | published ≥ 10 business days before `date_started` | `plan_final` = `yes` |
| After finishing | SCN-TRF-NAF | within 5 business days of `date_finished` | `date_finished` |
| After verification | SCN-TRF-NAV | within 5 business days of `verified_on` | `verified_on`, `sar_reference`, `new_risks_summary` |
| Documentation updated | SCN-TRF-UPD | within 30 business days of `date_finished` | `docs_to_update`, `docs_updated_on` (or `docs_update_not_required`) |

A notice is given when a deploy publishes it: the index records each notice's
deadline and the date it was first published. The SCN gate blocks the merge of
the change until the initial and final plans have been published long enough.
Business days exclude weekends and US federal holidays.

## 1. Categorization (SCN-CSO-EVA)

Why this change is transformative (FRD-TRF), and why it is not a class change.

## 2. Required information (SCN-CSO-INF)

Register columns: `fedramp_id`, `assessor_name`, `related_vulnerability`,
`categorization_rationale`, `short_description`, `reason_for_change`,
`customer_impact`, `plan_and_timeline`, `sia_reference` (this file),
`approver_name`, `approver_title`.

## 3. Likely security impacts and changes in risk (SCN-TRF-NIP)

Summary in `new_risks_summary`; detail here.

## 4. Third-party review (SCN-TRF-TPR)

- `tpr_human_validation`: `yes` or `no` — does the scope or impact need human validation?
- `tpr_assessor_or_reason`: the assessor engaged to review the scope and impact before the change starts, or why none was engaged.

## 5. Verification, assessment and validation (SCN-TRF-NAV)

The plan, the result, and `sar_reference`: the security assessment report, or why there is none.

## 6. Documentation updates (SCN-TRF-UPD)

`docs_to_update` (semicolon-separated paths) and, once done, `docs_updated_on`.
If none is needed, `docs_update_not_required` says how that was determined.
