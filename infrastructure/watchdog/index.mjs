// =============================================================================
// EVIDENCE SLA WATCHDOG
// =============================================================================
// Measures, from outside GitHub, whether the published compliance evidence is
// fresh, and whether the unattended nightly refresh last succeeded. Runs hourly
// on an EventBridge schedule and publishes three CloudWatch metrics; alarms on
// those metrics page the operator by email through SNS.
//
// Why it exists: from 2026-09-09 to 2026-09-24 the nightly failed every night
// and the only signal was a GitHub issue in a notifications tab. The nightly's
// own alert job cannot detect its own absence either: if GitHub disables the
// cron, neither the refresh nor the alert runs. This runs on AWS's clock.
//
// It reads the artifacts straight from the site bucket, not the public URL, so
// the function makes AWS API calls only and needs no internet egress.
//
// It reads every artifact listed in the governed freshness config
// (freshness-config.json, packaged beside this file from
// infrastructure/schemas/), and nothing else.
//
// Metrics (namespace from METRIC_NAMESPACE):
//   VdrAgeHours            age of .well-known/vdr-report.json
//   RuntimeSignalAgeHours  age of .well-known/ksi-signal-runtime.json (daily)
//   NightlyFailed          1 if the nightly's status beacon says it failed, is
//                          missing, or is too old to trust; else 0
//   StaleArtifacts         how many listed artifacts are past their governed
//                          window, unreadable, or without a usable timestamp
//   IncidentReportsOverdue how many incident reports the published incident
//                          log lists as due whose Class C deadline has passed
//                          (1 if the log is missing or unreadable)
//
// A missing or invalid config fails the run before anything is published; the
// alarms read the missing data as a breach and page.
//
// A read or parse failure is reported as a breach (UNREADABLE_AGE_HOURS / 1),
// never skipped: an artifact the watchdog cannot read is not evidence that it
// is fine. If this function stops publishing entirely, the alarms treat the
// missing data as breaching.
// =============================================================================

import { readFile } from 'node:fs/promises';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { KEYS, computeMetrics, metricData, parseConfig } from './logic.mjs';

const CONFIG_URL = new URL('./freshness-config.json', import.meta.url);

async function read(s3, bucket, key) {
    try {
        const out = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        return { body: await out.Body.transformToString(), lastModified: out.LastModified ?? null };
    } catch (err) {
        console.warn(JSON.stringify({ msg: 'artifact unreadable', key, error: err.name || String(err) }));
        return null;
    }
}

export async function handler(_event, _context, deps = {}) {
    const bucket = process.env.S3_BUCKET;
    const namespace = process.env.METRIC_NAMESPACE;
    if (!bucket || !namespace) throw new Error('S3_BUCKET and METRIC_NAMESPACE must be set');

    // Fail closed: no valid governed windows, no metrics (and so, a page).
    const config = parseConfig(JSON.parse(await (deps.readConfig || (() => readFile(CONFIG_URL, 'utf8')))()));

    const s3 = deps.s3 || new S3Client({});
    const cw = deps.cw || new CloudWatchClient({});
    const now = deps.now || Date.now();

    const paths = config.artifacts.map((a) => a.path);
    const bodies = await Promise.all(paths.map((p) => read(s3, bucket, p)));
    const readings = Object.fromEntries(paths.map((p, i) => [p, bodies[i]]));
    const { metrics, stale } = computeMetrics(config, readings, now);

    await cw.send(new PutMetricDataCommand({
        Namespace: namespace,
        MetricData: metricData(metrics, now),
    }));

    // One structured line per run: the numbers the alarms act on, and which
    // artifacts are stale, for the log.
    let beacon = null;
    try { beacon = JSON.parse(readings[KEYS.status]?.body); } catch { beacon = null; }
    console.log(JSON.stringify({ msg: 'evidence watchdog', config_version: config.version, ...metrics, stale,
        nightly: beacon ? { result: beacon.result, finished_at: beacon.finished_at } : null }));
    return metrics;
}
