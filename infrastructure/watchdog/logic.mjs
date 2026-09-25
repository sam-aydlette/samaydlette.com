// Pure logic for the evidence SLA watchdog (index.mjs). No AWS SDK here, so
// it is testable anywhere node runs; see tests/test_evidence_watchdog.py.

export const KEYS = {
    vdr: '.well-known/vdr-report.json',
    runtime: '.well-known/ksi-signal-runtime.json',
    status: '.well-known/vdr-status.json',
};

// Reported when an artifact cannot be read or has no usable timestamp. Far past
// any threshold, so it reads as a breach on every alarm.
export const UNREADABLE_AGE_HOURS = 9999;

// The nightly runs twice a day. A beacon older than this means runs have been
// missed, whatever the last one said: the cron may be disabled or stuck.
export const MAX_BEACON_AGE_HOURS = 26;

export function ageHours(iso, now = Date.now()) {
    if (typeof iso !== 'string') return null;
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return null;
    return (now - t) / 3600000;
}

// 1 = page. The beacon is written by every nightly run, pass or fail, with the
// overall result and each gate's outcome.
export function nightlyFailed(status, now = Date.now()) {
    if (!status || typeof status !== 'object') return 1;
    const age = ageHours(status.finished_at, now);
    if (age === null || age > MAX_BEACON_AGE_HOURS) return 1;
    return status.result === 'success' ? 0 : 1;
}

export function computeMetrics({ vdr, runtime, status }, now = Date.now()) {
    const vdrAge = vdr ? ageHours(vdr.emitted_at, now) : null;
    const runtimeAge = runtime ? ageHours(runtime.emitted_at, now) : null;
    return {
        VdrAgeHours: vdrAge === null ? UNREADABLE_AGE_HOURS : vdrAge,
        RuntimeSignalAgeHours: runtimeAge === null ? UNREADABLE_AGE_HOURS : runtimeAge,
        NightlyFailed: nightlyFailed(status, now),
    };
}

export function metricData(metrics, now) {
    return Object.entries(metrics).map(([MetricName, Value]) => ({
        MetricName,
        Value,
        Unit: MetricName === 'NightlyFailed' ? 'Count' : 'None',
        Timestamp: new Date(now),
    }));
}
