// =============================================================================
// FEDRAMP SECURITY INBOX: handler (AFC-CSO-INB, TFG, RCV, CRA, EMR, IMA, ACK)
// =============================================================================
// One function, three triggers:
//
//   SES receipt rule (Event)  a message arrived. SES has already stored the raw
//                             message in the inbox bucket (the rule's first
//                             action), so nothing here can lose it. For FedRAMP
//                             mail: write a register record, acknowledge the
//                             sender, page the operator. Other mail is left in
//                             the bucket and logged by reference only.
//   EventBridge (hourly)      check the live receiving configuration against
//                             what Terraform declared, count overdue register
//                             items, publish both as metrics. Alarms on those
//                             metrics page through the evidence-alert topic.
//   direct invoke {exercise}  scripts/fsi.py exercise: the same path as a real
//                             FedRAMP message, marked as an exercise, with the
//                             acknowledgement sent to the operator's address.
//                             Only principals that can invoke the function
//                             (the operator and the deploy role) can do this.
//
// The function makes AWS API calls only. It never reads the message body and
// never logs a subject or address: logs carry the SES message ID and outcomes.
//
// Idempotent on retry: SES invokes asynchronously, so a failure is retried. An
// existing register record is read back and only the steps that did not
// complete are attempted again, so a sender is not acknowledged twice.
// =============================================================================

import {
    REGISTER_OPEN, buildAck, classify, configProblems, newRecord, overdue, pageFor,
} from './logic.mjs';

const MAX_OPEN_RECORDS = 500;

function env() {
    const need = ['FSI_ADDRESS', 'MAIL_BUCKET', 'MAIL_PREFIX', 'ALERT_TOPIC_ARN', 'METRIC_NAMESPACE',
        'RULE_SET', 'RULE_NAME', 'DOMAIN', 'ZONE_ID', 'MX_TARGET'];
    const e = Object.fromEntries(need.map((k) => [k, process.env[k]]));
    const missing = need.filter((k) => !e[k]);
    if (missing.length) throw new Error(`missing environment: ${missing.join(', ')}`);
    e.FSI_ADDRESS = e.FSI_ADDRESS.toLowerCase();
    e.RUNBOOK = process.env.RUNBOOK_URL || '';
    return e;
}

function log(obj) {
    console.log(JSON.stringify(obj));
}

/** The AWS SDK calls this function makes, behind one seam the tests replace. */
export async function awsDeps() {
    const [s3m, snsm, sesv2m, sesm, r53m, cwm] = await Promise.all([
        import('@aws-sdk/client-s3'), import('@aws-sdk/client-sns'), import('@aws-sdk/client-sesv2'),
        import('@aws-sdk/client-ses'), import('@aws-sdk/client-route-53'), import('@aws-sdk/client-cloudwatch'),
    ]);
    const s3 = new s3m.S3Client({});
    const sns = new snsm.SNSClient({});
    const sesv2 = new sesv2m.SESv2Client({});
    const ses = new sesm.SESClient({});
    const r53 = new r53m.Route53Client({});
    const cw = new cwm.CloudWatchClient({});
    return {
        async getRecord(bucket, key) {
            try {
                const out = await s3.send(new s3m.GetObjectCommand({ Bucket: bucket, Key: key }));
                return JSON.parse(await out.Body.transformToString());
            } catch (err) {
                if (err?.name === 'NoSuchKey') return null;
                throw err;
            }
        },
        async putRecord(bucket, key, record) {
            await s3.send(new s3m.PutObjectCommand({
                Bucket: bucket, Key: key, Body: JSON.stringify(record, null, 2), ContentType: 'application/json',
            }));
        },
        async listOpen(bucket, limit) {
            const keys = [];
            let token;
            do {
                const out = await s3.send(new s3m.ListObjectsV2Command({ Bucket: bucket, Prefix: REGISTER_OPEN, ContinuationToken: token }));
                for (const o of out.Contents || []) keys.push(o.Key);
                token = out.IsTruncated ? out.NextContinuationToken : undefined;
            } while (token && keys.length < limit);
            return keys.slice(0, limit);
        },
        async sendRaw(from, to, raw) {
            const out = await sesv2.send(new sesv2m.SendEmailCommand({
                FromEmailAddress: from, Destination: { ToAddresses: [to] },
                Content: { Raw: { Data: Buffer.from(raw, 'utf8') } },
            }));
            return out.MessageId;
        },
        async publish(topicArn, subject, message) {
            const out = await sns.send(new snsm.PublishCommand({ TopicArn: topicArn, Subject: subject, Message: message }));
            return out.MessageId;
        },
        async activeRuleSet() {
            return ses.send(new sesm.DescribeActiveReceiptRuleSetCommand({}));
        },
        async identity(domain) {
            try {
                return await sesv2.send(new sesv2m.GetEmailIdentityCommand({ EmailIdentity: domain }));
            } catch (err) {
                if (err?.name === 'NotFoundException') return null;
                throw err;
            }
        },
        async account() {
            return sesv2.send(new sesv2m.GetAccountCommand({}));
        },
        async mx(zoneId, name) {
            const out = await r53.send(new r53m.ListResourceRecordSetsCommand({
                HostedZoneId: zoneId, StartRecordName: name, StartRecordType: 'MX', MaxItems: 1,
            }));
            const rr = (out.ResourceRecordSets || []).find((r) => r.Type === 'MX' && r.Name.replace(/\.$/, '') === name);
            return rr ? rr.ResourceRecords.map((x) => x.Value) : [];
        },
        async metrics(namespace, data) {
            await cw.send(new cwm.PutMetricDataCommand({ Namespace: namespace, MetricData: data }));
        },
    };
}

/** Acknowledge and page for one register record, skipping what already succeeded. */
async function react(e, aws, record, { ackTo, rfcMessageId, loop }, nowMs) {
    const key = `${REGISTER_OPEN}${record.id}.json`;
    if (record.ack.status === 'pending' || record.ack.status === 'failed') {
        if (loop) {
            record.ack = { status: 'suppressed', reason: loop };
        } else {
            try {
                const raw = buildAck({
                    fsiAddress: e.FSI_ADDRESS, to: ackTo, subject: record.subject, rfcMessageId,
                    receivedAt: record.received_at, designation: record.designation, ref: record.id, exercise: record.exercise,
                });
                await aws.sendRaw(e.FSI_ADDRESS, ackTo, raw);
                record.ack = { status: 'sent', at: new Date(nowMs).toISOString() };
            } catch (err) {
                record.ack = { status: 'failed', at: new Date(nowMs).toISOString(), error: String(err?.name || 'Error').slice(0, 80) };
            }
        }
    }
    let pageError = null;
    if (record.page.status !== 'sent') {
        const { subject, message } = pageFor(record, { runbook: e.RUNBOOK });
        try {
            await aws.publish(e.ALERT_TOPIC_ARN, subject, message);
            record.page = { status: 'sent', at: new Date(nowMs).toISOString() };
        } catch (err) {
            pageError = err;
            record.page = { status: 'failed', at: new Date(nowMs).toISOString(), error: String(err?.name || 'Error').slice(0, 80) };
        }
    }
    await aws.putRecord(e.MAIL_BUCKET, key, record);
    log({ msg: 'fedramp message handled', id: record.id, designation: record.designation, exercise: record.exercise,
        ack: record.ack.status, page: record.page.status });
    // A page that did not go out is the one failure that must not be quiet:
    // throwing makes SES retry the invocation and counts in the Errors alarm.
    if (pageError) throw new Error(`page failed for ${record.id}`);
    return record;
}

async function onMail(e, aws, event, nowMs) {
    const results = [];
    for (const rec of event.Records || []) {
        const c = classify(rec.ses);
        if (!c.id) {
            log({ msg: 'message without a usable SES message ID; stored by SES, not registered' });
            continue;
        }
        if (c.kind !== 'fedramp') {
            log({ msg: 'non-FedRAMP message stored', id: c.id, spam: c.verdicts.spam, virus: c.verdicts.virus });
            results.push({ id: c.id, kind: 'other' });
            continue;
        }
        const key = `${REGISTER_OPEN}${c.id}.json`;
        const received = Date.parse(c.received_at) || nowMs;
        const record = (await aws.getRecord(e.MAIL_BUCKET, key))
            || newRecord(c, received, { objectKey: `${e.MAIL_PREFIX}${c.id}` });
        await react(e, aws, record, { ackTo: c.from, rfcMessageId: c.rfc_message_id, loop: c.loop }, nowMs);
        results.push({ id: c.id, kind: 'fedramp', designation: c.designation, ack: record.ack.status, page: record.page.status });
    }
    return { handled: results };
}

async function onExercise(e, aws, ex, nowMs, context) {
    const nonce = String(ex.nonce || '');
    if (!/^[A-Za-z0-9-]{8,64}$/.test(nonce)) throw new Error('exercise nonce must be 8-64 letters, digits or hyphens');
    const designation = ['EMERGENCY', 'EMERGENCY_TEST', 'IMPORTANT', 'GENERAL'].includes(ex.designation) ? ex.designation : 'EMERGENCY_TEST';
    const label = { EMERGENCY: 'Emergency', EMERGENCY_TEST: 'Emergency Test', IMPORTANT: 'Important', GENERAL: '' }[designation];
    // A synthetic SES record from a FedRAMP address, so the exercise runs the
    // real classifier rather than a bypass. The acknowledgement goes to the
    // operator's own (SES-verified) address, never to FedRAMP.
    const c = classify({
        mail: {
            messageId: `exercise-${nonce}`,
            source: 'fedramp_security@fedramp.gov',
            timestamp: new Date(nowMs).toISOString(),
            headers: [{ name: 'Message-ID', value: `<exercise-${nonce}@exercise.invalid>` }],
            commonHeaders: { from: ['FedRAMP (exercise) <fedramp_security@fedramp.gov>'], subject: `${label}: FSI exercise ${nonce}`.trim() },
        },
        receipt: { timestamp: new Date(nowMs).toISOString(), spfVerdict: { status: 'PASS' }, dkimVerdict: { status: 'PASS' }, dmarcVerdict: { status: 'PASS' } },
    });
    if (c.kind !== 'fedramp' || c.designation !== designation) throw new Error('exercise message was not classified as intended');
    const record = newRecord(c, nowMs, { exercise: true });
    record.invoked_by = context?.invokedFunctionArn ? 'direct-invoke' : 'unknown';
    await react(e, aws, record, { ackTo: ex.reply_to, rfcMessageId: c.rfc_message_id, loop: null }, nowMs);
    return { exercise: record.id, designation, ack: record.ack, page: record.page, respond_by: record.respond_by };
}

async function onSchedule(e, aws, nowMs, context) {
    const expected = {
        ruleSet: e.RULE_SET, rule: e.RULE_NAME, address: e.FSI_ADDRESS, bucket: e.MAIL_BUCKET,
        prefix: e.MAIL_PREFIX, functionArn: context?.invokedFunctionArn?.split(':').slice(0, 7).join(':'), mx: e.MX_TARGET,
    };
    const live = {};
    const unreadable = [];
    for (const [k, fn] of [['ruleSet', () => aws.activeRuleSet()], ['identity', () => aws.identity(e.DOMAIN)],
        ['account', () => aws.account()], ['mx', () => aws.mx(e.ZONE_ID, e.DOMAIN)]]) {
        try {
            live[k] = await fn();
        } catch (err) {
            unreadable.push(`${k} unreadable (${err?.name || 'Error'})`);
            live[k] = k === 'mx' ? ['<unreadable>'] : null;
        }
    }
    const config = [...unreadable, ...configProblems(expected, live)];

    const records = [];
    let registerUnreadable = 0;
    try {
        for (const key of await aws.listOpen(e.MAIL_BUCKET, MAX_OPEN_RECORDS)) {
            const r = await aws.getRecord(e.MAIL_BUCKET, key);
            if (r) records.push(r);
        }
    } catch (err) {
        registerUnreadable = 1;
        log({ msg: 'register unreadable', error: err?.name || 'Error' });
    }
    const late = overdue(records, nowMs);
    const overdueCount = late.length + registerUnreadable;
    await aws.metrics(e.METRIC_NAMESPACE, [
        { MetricName: 'InboxConfigProblems', Value: config.length, Unit: 'Count' },
        { MetricName: 'InboxOverdue', Value: overdueCount, Unit: 'Count' },
    ]);
    log({ msg: 'inbox check', config_problems: config, overdue: late, open_records: records.length });
    return { config_problems: config, overdue: late, open_records: records.length };
}

export async function handler(event, context, deps = {}) {
    const e = env();
    const nowMs = deps.now ?? Date.now();
    const aws = deps.aws ?? await awsDeps();
    if (Array.isArray(event?.Records) && event.Records[0]?.eventSource === 'aws:ses') return onMail(e, aws, event, nowMs);
    if (event && typeof event.exercise === 'object' && event.exercise !== null) return onExercise(e, aws, event.exercise, nowMs, context);
    if (event?.source === 'aws.events') return onSchedule(e, aws, nowMs, context);
    throw new Error('unrecognised event');
}
