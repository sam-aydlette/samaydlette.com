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
// Metrics (namespace from METRIC_NAMESPACE):
//   VdrAgeHours            age of .well-known/vdr-report.json (policy: < 24h)
//   RuntimeSignalAgeHours  age of .well-known/ksi-signal-runtime.json (daily)
//   NightlyFailed          1 if the nightly's status beacon says it failed, is
//                          missing, or is too old to trust; else 0
//
// A read or parse failure is reported as a breach (UNREADABLE_AGE_HOURS / 1),
// never skipped: an artifact the watchdog cannot read is not evidence that it
// is fine. If this function stops publishing entirely, the alarms treat the
// missing data as breaching.
// =============================================================================

import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { KEYS, computeMetrics, metricData } from './logic.mjs';

async function readJson(s3, bucket, key) {
    try {
        const out = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        return JSON.parse(await out.Body.transformToString());
    } catch (err) {
        console.warn(JSON.stringify({ msg: 'artifact unreadable', key, error: err.name || String(err) }));
        return null;
    }
}

export async function handler(_event, _context, deps = {}) {
    const bucket = process.env.S3_BUCKET;
    const namespace = process.env.METRIC_NAMESPACE;
    if (!bucket || !namespace) throw new Error('S3_BUCKET and METRIC_NAMESPACE must be set');

    const s3 = deps.s3 || new S3Client({});
    const cw = deps.cw || new CloudWatchClient({});
    const now = deps.now || Date.now();

    const [vdr, runtime, status] = await Promise.all([
        readJson(s3, bucket, KEYS.vdr),
        readJson(s3, bucket, KEYS.runtime),
        readJson(s3, bucket, KEYS.status),
    ]);
    const metrics = computeMetrics({ vdr, runtime, status }, now);

    await cw.send(new PutMetricDataCommand({
        Namespace: namespace,
        MetricData: metricData(metrics, now),
    }));

    // One structured line per run: the numbers the alarms act on, for the log.
    console.log(JSON.stringify({ msg: 'evidence watchdog', ...metrics,
        nightly: status ? { result: status.result, finished_at: status.finished_at } : null }));
    return metrics;
}
