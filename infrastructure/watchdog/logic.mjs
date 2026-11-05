// Pure logic for the evidence SLA watchdog (index.mjs). No AWS SDK here, so
// it is testable anywhere node runs; see tests/test_evidence_watchdog.py.
//
// The freshness windows are not set here. They come from the governed config
// (infrastructure/schemas/freshness-config.json, packaged beside this file as
// freshness-config.json), which the trust center, the published-evidence check
// and the alarm thresholds in watchdog.tf also read. parseConfig() applies the
// same rules as scripts/_freshness.py and throws on anything invalid: a
// watchdog without valid windows fails its run, publishes nothing, and the
// alarms (missing data = breaching) page.

export const KEYS = {
    vdr: '.well-known/vdr-report.json',
    runtime: '.well-known/ksi-signal-runtime.json',
    status: '.well-known/vdr-status.json',
    incidents: '.well-known/incident-reports.json',
};

// Every artifact a metric below depends on. The config must list them.
export const REQUIRED = [KEYS.vdr, KEYS.runtime, KEYS.status, KEYS.incidents, '.well-known/boundary-corroboration.json'];

// Reported when an artifact cannot be read or has no usable timestamp. Far past
// any threshold, so it reads as a breach on every alarm.
export const UNREADABLE_AGE_HOURS = 9999;

const PATH_RE = /^\.well-known\/[A-Za-z0-9][A-Za-z0-9._-]*$/;
const FIELD_RE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CADENCES = new Set(['nightly', 'runtime', 'deploy', 'operator']);
const MAX_WINDOW_HOURS = 8760;

function invalid(msg) {
    throw new Error(`freshness config invalid: ${msg}`);
}

const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';

export function parseConfig(cfg) {
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) invalid('not an object');
    for (const k of ['version', 'decided_by', 'rationale']) if (!nonEmpty(cfg[k])) invalid(`${k} must be a non-empty string`);
    for (const k of ['decided_on', 'review_by']) if (typeof cfg[k] !== 'string' || !DATE_RE.test(cfg[k])) invalid(`${k} must be an ISO date`);
    if (!Array.isArray(cfg.artifacts) || cfg.artifacts.length === 0) invalid('artifacts must be a non-empty list');
    const windows = {};
    for (const a of cfg.artifacts) {
        if (!a || typeof a !== 'object') invalid('artifact is not an object');
        if (typeof a.path !== 'string' || !PATH_RE.test(a.path) || a.path.includes('..')) invalid(`bad path ${JSON.stringify(a.path)}`);
        if (a.path in windows) invalid(`${a.path} is listed twice`);
        const w = a.max_age_hours;
        if (typeof w !== 'number' || !Number.isFinite(w) || w <= 0 || w > MAX_WINDOW_HOURS) invalid(`${a.path}: bad max_age_hours`);
        if (!CADENCES.has(a.cadence)) invalid(`${a.path}: bad cadence`);
        if (typeof a.signed !== 'boolean') invalid(`${a.path}: signed must be a boolean`);
        const ts = a.timestamp || {};
        const okTs = (ts.source === 'last_modified' && Object.keys(ts).length === 1)
            || (ts.source === 'json' && Object.keys(ts).length === 2 && typeof ts.field === 'string' && FIELD_RE.test(ts.field));
        if (!okTs) invalid(`${a.path}: bad timestamp`);
        windows[a.path] = w;
    }
    const absent = REQUIRED.filter((p) => !(p in windows));
    if (absent.length) invalid(`required artifacts not listed: ${absent.join(', ')}`);
    return { version: cfg.version, artifacts: cfg.artifacts, windows };
}

export function ageHours(iso, now = Date.now()) {
    if (typeof iso !== 'string') return null;
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return null;
    return (now - t) / 3600000;
}

// The timestamp an artifact's age is measured from: its configured JSON field,
// or the object's last-modified time. `reading` is { body, lastModified } as
// read from the bucket, or null when the object could not be read.
export function timestampOf(artifact, reading) {
    if (!reading) return null;
    if (artifact.timestamp.source === 'last_modified') {
        const lm = reading.lastModified;
        return lm instanceof Date ? lm.toISOString() : (typeof lm === 'string' ? lm : null);
    }
    let node;
    try { node = JSON.parse(reading.body); } catch { return null; }
    for (const part of artifact.timestamp.field.split('.')) {
        node = node && typeof node === 'object' ? node[part] : undefined;
    }
    return typeof node === 'string' && node ? node : null;
}

function parsedBody(reading) {
    if (!reading) return null;
    try { return JSON.parse(reading.body); } catch { return null; }
}

// 1 = page. The beacon is written by every nightly run, pass or fail, with the
// overall result and each gate's outcome. Older than its governed window means
// runs have been missed, whatever the last one said.
export function nightlyFailed(status, maxBeaconAgeHours, now = Date.now()) {
    if (!status || typeof status !== 'object') return 1;
    const age = ageHours(status.finished_at, now);
    if (age === null || age > maxBeaconAgeHours) return 1;
    return status.result === 'success' ? 0 : 1;
}

// How many incident reports are past their Class C deadline and not issued
// (IEC-CSO-IIR/OIR/FIR). The incident log lists each report still due with its
// deadline (scripts/build-incident-report.py, obligations_due); this counts the
// ones whose time has passed on AWS's clock, so a missed one-hour Initial
// report pages within the hour even if nothing republishes the log. A log that
// is missing, unreadable or has no list is a breach (1), never zero.
export function incidentReportsOverdue(log, now = Date.now()) {
    if (!log || typeof log !== 'object' || !Array.isArray(log.obligations_due)) return 1;
    let overdue = 0;
    for (const d of log.obligations_due) {
        const due = Date.parse(d && d.due_at);
        if (Number.isNaN(due) || due < now) overdue += 1;
    }
    return overdue;
}

// Every listed artifact past its window, or unreadable, or without a usable
// timestamp. One metric for all of them keeps the cost flat as the list grows;
// the log line names which.
export function staleArtifacts(config, readings, now = Date.now()) {
    const stale = [];
    for (const a of config.artifacts) {
        const age = ageHours(timestampOf(a, readings[a.path]), now);
        if (age === null || age > a.max_age_hours) stale.push(a.path);
    }
    return stale;
}

export function computeMetrics(config, readings, now = Date.now()) {
    const age = (path) => {
        const a = config.artifacts.find((x) => x.path === path);
        const h = ageHours(timestampOf(a, readings[path]), now);
        return h === null ? UNREADABLE_AGE_HOURS : h;
    };
    const stale = staleArtifacts(config, readings, now);
    return {
        metrics: {
            VdrAgeHours: age(KEYS.vdr),
            RuntimeSignalAgeHours: age(KEYS.runtime),
            NightlyFailed: nightlyFailed(parsedBody(readings[KEYS.status]), config.windows[KEYS.status], now),
            StaleArtifacts: stale.length,
            IncidentReportsOverdue: incidentReportsOverdue(parsedBody(readings[KEYS.incidents]), now),
        },
        stale,
    };
}

const COUNTS = new Set(['NightlyFailed', 'StaleArtifacts', 'IncidentReportsOverdue']);

export function metricData(metrics, now) {
    return Object.entries(metrics).map(([MetricName, Value]) => ({
        MetricName,
        Value,
        Unit: COUNTS.has(MetricName) ? 'Count' : 'None',
        Timestamp: new Date(now),
    }));
}
