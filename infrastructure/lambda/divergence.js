// =============================================================================
// DEPLOY <-> RUNTIME DIVERGENCE
// =============================================================================
// The deploy gate evaluates a Terraform plan; this Lambda evaluates the live
// account a day later. Both run the same compiled policy, so a disagreement is
// meaningful: either the account drifted after apply, or the two enforcement
// points were fed different facts about the same resource. Until this check
// existed the disagreement was published on both sides and read by neither.
//
// The load-bearing distinction is between a resource that regressed and an
// evaluator that could not look. A `category: "input"` violation
// (resource_read_error, config_error, input_error) means this Lambda failed to
// reach a verdict — an observer fault. Counting those as regressions would
// report drift every time a permission is missing, which is exactly the
// failure this pipeline has already published for four weeks. They are
// reported separately as `unassessed`, and the overall status degrades rather
// than diverging.
//
// Callers acting on this block (alerting, gating, any future rollback) must
// key on `status === "diverged"` and on `regressions`, never on the raw
// validation results, or they inherit that conflation.
// =============================================================================

function computeDivergence(deploySignal, validations) {
    const deployStatus = new Map((deploySignal.ksis ?? []).map((k) => [k.id, k.status]));
    const regressed = new Map();
    const unassessed = new Map();
    let unattributed = 0;

    for (const v of validations) {
        if (v.result !== 'fail') continue;
        for (const viol of v.violations ?? []) {
            const ksiIds = viol.ksi_ids ?? [];
            if (ksiIds.length === 0) {
                unattributed += 1;
                continue;
            }
            const target = viol.category === 'input' ? unassessed : regressed;
            for (const id of ksiIds) {
                if (!target.has(id)) target.set(id, new Set());
                target.get(id).add(viol.id);
            }
        }
    }

    const entries = (m, runtimeStatus, filter) =>
        [...m.entries()]
            .filter(([id]) => (filter ? filter(deployStatus.get(id)) : true))
            .map(([id, ids]) => ({
                ksi_id: id,
                deploy_status: deployStatus.get(id) ?? 'unknown',
                runtime_status: runtimeStatus,
                violation_ids: [...ids].sort(),
            }))
            .sort((a, b) => a.ksi_id.localeCompare(b.ksi_id));

    // Only a KSI the deploy gate published as PASSING can regress. Where both
    // enforcement points already agree a KSI is failing there is no divergence
    // to report — the finding is simply open.
    const regressions = entries(regressed, 'fail', (s) => s === 'pass');
    const unassessedList = entries(unassessed, 'unassessed', null);

    let status = 'converged';
    if (regressions.length > 0) status = 'diverged';
    else if (unassessedList.length > 0 || unattributed > 0) status = 'degraded';

    return {
        status,
        compared_against: {
            signal_id: deploySignal.signal_id ?? null,
            emitted_at: deploySignal.emitted_at ?? null,
            commit: deploySignal.provenance?.source?.commit ?? null,
        },
        ksis_compared: deployStatus.size,
        regressions,
        unassessed: unassessedList,
        unattributed_failures: unattributed,
    };
}

module.exports = { computeDivergence };
