// =============================================================================
// FEDRAMP SECURITY INBOX: pure logic (no AWS calls, no I/O)
// =============================================================================
// Everything here is a pure function of its inputs so it can be tested
// directly in node (tests/test_fedramp_inbox.py). index.mjs wires it to SES,
// S3, SNS and CloudWatch.
//
// Every byte of an inbound message is untrusted input. Nothing here executes,
// evaluates or renders message content: the only fields read are the sender
// addresses, the Subject header, a few loop-prevention headers and SES's own
// verdicts, and every string taken from the message is length-capped and
// stripped of control and bidirectional-override characters before it is
// stored, put in a page, or put in a reply header. The message body is never
// read by the function at all (SES stores it in S3; the operator reads it
// with scripts/fsi.py, which prints text only).
//
// Rules implemented (FedRAMP Consolidated Rules 2026, AFC family):
//   AFC-CSO-TFG  mail from @fedramp.gov or @gsa.gov is FedRAMP by default,
//                whatever its spam verdict or authentication result
//   AFC-CSO-EMR  Emergency-designated mail pages the senior security official
//   AFC-CSO-CRA  Emergency / Emergency Test mail gets a tracked deadline
//   AFC-CSO-IMA  Important mail gets a tracked item
//   AFC-CSO-ACK  FedRAMP mail is acknowledged automatically
// and the designators come from AFC-FRP-CDS, the Emergency senders from
// AFC-FRP-UFS and the default Class C timeframe from AFC-FRP-ERT.
// =============================================================================

// AFC-CSO-TFG: exact domains, compared case-insensitively. Subdomains are not
// FedRAMP: the rule names "@fedramp.gov" and "@gsa.gov" addresses.
export const FEDRAMP_DOMAINS = Object.freeze(['fedramp.gov', 'gsa.gov']);

// AFC-FRP-UFS: FedRAMP sends Emergency and Emergency Test messages from these.
export const EMERGENCY_SENDERS = Object.freeze(['fedramp_security@gsa.gov', 'fedramp_security@fedramp.gov']);

export const DESIGNATIONS = Object.freeze(['EMERGENCY', 'EMERGENCY_TEST', 'IMPORTANT', 'GENERAL']);

// How long the operator has to open (triage) a FedRAMP message before the
// overdue alarm pages, by designation. The page itself goes out on receipt.
export const TRIAGE_HOURS = Object.freeze({ EMERGENCY: 2, EMERGENCY_TEST: 2, IMPORTANT: 24, GENERAL: 72 });

// AFC-FRP-ERT default for Class C: "by 3:00 p.m. Eastern Time on the 2nd
// business day". The message's own timeframe governs (AFC-CSO-CRA); this is
// the deadline the register carries until the operator records that one.
export const CLASS_C_BUSINESS_DAYS = 2;
export const CLASS_C_HOUR_ET = 15;

export const MAX_SUBJECT = 200;
const MAX_ADDRESS = 254;

const CONTROL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g;
const ADDR_SPEC = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$/;
const MESSAGE_ID = /^[A-Za-z0-9._-]{1,128}$/;
const RFC_MESSAGE_ID = /^<[\x21-\x3b\x3d\x3f-\x7e]{1,250}>$/;

/** Collapse a header value to one safe line: no control or bidi characters, capped. */
export function cleanText(value, max = MAX_SUBJECT) {
    return String(value ?? '').replace(CONTROL, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** The addr-spec in a From-style header value, lower-cased, or null. */
export function parseAddress(value) {
    const s = cleanText(value, 1000);
    if (!s) return null;
    const angled = [...s.matchAll(/<([^<>\s]+)>/g)];
    const candidate = (angled.length ? angled[angled.length - 1][1] : s).toLowerCase();
    if (candidate.length > MAX_ADDRESS || !ADDR_SPEC.test(candidate)) return null;
    return candidate;
}

export function domainOf(address) {
    return address ? address.slice(address.lastIndexOf('@') + 1) : null;
}

export function isFedrampAddress(address) {
    return FEDRAMP_DOMAINS.includes(domainOf(address));
}

/**
 * AFC-FRP-CDS designator in a Subject line. Matching is deliberately broad
 * (anywhere in the subject, any case, "[Emergency]" or "EMERGENCY TEST:"):
 * a false Emergency costs a page; a missed one costs the deadline.
 */
export function designationOf(subject) {
    const s = cleanText(subject, 1000).toLowerCase();
    if (/\bemergency[\s_-]*test\b/.test(s)) return 'EMERGENCY_TEST';
    if (/\bemergency\b/.test(s)) return 'EMERGENCY';
    if (/\bimportant\b/.test(s)) return 'IMPORTANT';
    return 'GENERAL';
}

function header(headers, name) {
    const want = name.toLowerCase();
    for (const h of headers || []) {
        if (h && typeof h.name === 'string' && h.name.toLowerCase() === want) return cleanText(h.value, 1000);
    }
    return null;
}

function verdict(v) {
    const s = v && typeof v.status === 'string' ? v.status.toUpperCase() : 'MISSING';
    return ['PASS', 'FAIL', 'GRAY', 'PROCESSING_FAILED'].includes(s) ? s : 'MISSING';
}

/** A stable, safe register ID from SES's message ID. */
export function safeId(messageId) {
    return MESSAGE_ID.test(String(messageId ?? '')) ? String(messageId) : null;
}

/**
 * Classify one SES receipt record (event.Records[i].ses).
 *
 * FedRAMP if the From header address or the envelope sender is at an exact
 * FedRAMP domain. Spam, virus and authentication verdicts are recorded and
 * shown to the operator, and never change the classification: the rule says
 * such mail is FedRAMP "by default", and only the operator, having confirmed
 * otherwise, closes it as not FedRAMP.
 */
export function classify(ses) {
    const mail = ses?.mail || {};
    const receipt = ses?.receipt || {};
    const common = mail.commonHeaders || {};
    const fromHeader = Array.isArray(common.from) ? common.from[0] : common.from;
    const from = parseAddress(fromHeader);
    const envelope = parseAddress(mail.source);
    const subject = cleanText(common.subject ?? header(mail.headers, 'subject'));
    const fedramp = isFedrampAddress(from) || isFedrampAddress(envelope);
    const designation = fedramp ? designationOf(subject) : 'GENERAL';
    const auth = { spf: verdict(receipt.spfVerdict), dkim: verdict(receipt.dkimVerdict), dmarc: verdict(receipt.dmarcVerdict) };
    const emergency = designation === 'EMERGENCY' || designation === 'EMERGENCY_TEST';
    return {
        id: safeId(mail.messageId),
        kind: fedramp ? 'fedramp' : 'other',
        from,
        envelope,
        sender_domain: domainOf(isFedrampAddress(from) ? from : envelope || from),
        subject,
        designation,
        auth,
        // VRE: FedRAMP sends with SPF, DKIM and DMARC configured. A failure does
        // not demote the message, it tells the operator to confirm the sender.
        authenticated: auth.dmarc === 'PASS' || (auth.dkim === 'PASS' && auth.spf === 'PASS'),
        verdicts: { spam: verdict(receipt.spamVerdict), virus: verdict(receipt.virusVerdict) },
        emergency_sender_ok: emergency ? EMERGENCY_SENDERS.includes(from) : null,
        rfc_message_id: (() => {
            const v = header(mail.headers, 'message-id');
            return v && RFC_MESSAGE_ID.test(v) ? v : null;
        })(),
        // No acknowledgement to unauthenticated mail: FedRAMP's own mail passes
        // SPF/DKIM/DMARC (AFC-FRP-VRE), so this loses nothing genuine, and it
        // stops a forged @gsa.gov From from turning the inbox into a reflector
        // that mails attacker-chosen subject text to any government address.
        // The message is still FedRAMP, registered and paged.
        loop: loopReason(mail, from) || (auth.dmarc === 'PASS' || (auth.dkim === 'PASS' && auth.spf === 'PASS') ? null : 'unauthenticated'),
        received_at: receipt.timestamp || mail.timestamp || null,
    };
}

/** Why an automatic reply must not be sent to this message, or null. */
export function loopReason(mail, from) {
    const auto = header(mail?.headers, 'auto-submitted');
    if (auto && auto.toLowerCase() !== 'no') return 'auto-submitted';
    const precedence = (header(mail?.headers, 'precedence') || '').toLowerCase();
    if (['bulk', 'junk', 'list', 'auto_reply'].includes(precedence)) return 'precedence';
    const source = String(mail?.source ?? '').trim();
    if (!source || source === '<>') return 'null-sender';
    const local = from ? from.slice(0, from.indexOf('@')) : '';
    if (['mailer-daemon', 'postmaster'].includes(local)) return 'daemon';
    if (!from) return 'no-from-address';
    return null;
}

// --- deadlines ---------------------------------------------------------------

const ET_PARTS = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', hour12: false, weekday: 'short',
});

function etParts(ms) {
    const p = Object.fromEntries(ET_PARTS.formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
    return { y: +p.year, m: +p.month, d: +p.day, hour: +p.hour % 24, weekday: p.weekday };
}

/** The UTC instant of hh:00 Eastern on the given ET calendar date. */
export function etInstant(y, m, d, hh) {
    for (const offset of [4, 5]) { // EDT, then EST
        const ms = Date.UTC(y, m - 1, d, hh + offset);
        const p = etParts(ms);
        if (p.y === y && p.m === m && p.d === d && p.hour === hh) return ms;
    }
    throw new Error(`no ${hh}:00 ET on ${y}-${m}-${d}`);
}

/**
 * 3:00 p.m. ET on the Nth business day, counting the day of receipt as day 1
 * when it is a weekday. That reading of "the 2nd business day" gives the
 * earlier of the two possible deadlines, and federal holidays are not skipped,
 * which can only make the deadline earlier still. Both err toward acting sooner.
 */
export function classCDeadline(receivedMs, businessDays = CLASS_C_BUSINESS_DAYS, hourEt = CLASS_C_HOUR_ET) {
    let { y, m, d } = etParts(receivedMs);
    let counted = 0;
    for (let i = 0; i < 14; i++) {
        const noon = etInstant(y, m, d, 12);
        const wd = etParts(noon).weekday;
        if (wd !== 'Sat' && wd !== 'Sun') counted += 1;
        if (counted === businessDays) return etInstant(y, m, d, hourEt);
        const next = etParts(noon + 24 * 3600 * 1000);
        ({ y, m, d } = next);
    }
    throw new Error('business-day search did not terminate');
}

/** The register's clock for one FedRAMP message. */
export function deadlines(designation, receivedMs) {
    const triage = receivedMs + TRIAGE_HOURS[designation] * 3600 * 1000;
    if (designation === 'EMERGENCY' || designation === 'EMERGENCY_TEST') {
        return {
            triage_by: new Date(triage).toISOString(),
            respond_by: new Date(classCDeadline(receivedMs)).toISOString(),
            deadline_basis: 'AFC-FRP-ERT Class C default (3:00 p.m. ET, 2nd business day); replace with the timeframe stated in the message',
        };
    }
    if (designation === 'IMPORTANT') {
        return {
            triage_by: new Date(triage).toISOString(),
            respond_by: null,
            deadline_basis: 'Record the timeframe stated in the message (AFC-CSO-IMA) when triaging',
        };
    }
    return { triage_by: new Date(triage).toISOString(), respond_by: null, deadline_basis: 'General communication: no elevated timeframe (AFC-FRP-CDS)' };
}

// --- register ----------------------------------------------------------------

export const REGISTER_OPEN = 'register/open/';
export const REGISTER_CLOSED = 'register/closed/';

export function newRecord(c, receivedMs, { objectKey, exercise = false } = {}) {
    return {
        schema: 'fsi-register/1',
        id: c.id,
        exercise,
        received_at: new Date(receivedMs).toISOString(),
        kind: c.kind,
        from: c.from,
        sender_domain: c.sender_domain,
        subject: c.subject,
        designation: c.designation,
        auth: c.auth,
        authenticated: c.authenticated,
        verdicts: c.verdicts,
        emergency_sender_ok: c.emergency_sender_ok,
        object_key: objectKey ?? null,
        status: 'open',
        ...deadlines(c.designation, receivedMs),
        ack: { status: 'pending' },
        page: { status: 'pending' },
        history: [],
    };
}

/**
 * Problems that should page, across the open register. A record is overdue when
 * nobody has triaged it in time, when its deadline has passed without closure,
 * or when its acknowledgement or page did not go out.
 */
export function overdue(records, nowMs) {
    const problems = [];
    for (const r of records) {
        const tag = `${r.id} (${r.designation}${r.exercise ? ', exercise' : ''})`;
        if (r.status === 'open' && r.triage_by && nowMs > Date.parse(r.triage_by)) problems.push(`${tag}: not triaged by ${r.triage_by}`);
        if (r.status !== 'closed' && r.respond_by && nowMs > Date.parse(r.respond_by)) problems.push(`${tag}: required actions not closed by ${r.respond_by}`);
        if (r.designation === 'IMPORTANT' && r.status !== 'open' && !r.respond_by) problems.push(`${tag}: triaged without recording the message's timeframe`);
        if (r.ack?.status === 'failed') problems.push(`${tag}: acknowledgement failed (${r.ack.error || 'unknown'})`);
        if (r.page?.status === 'failed') problems.push(`${tag}: page failed (${r.page.error || 'unknown'})`);
    }
    return problems;
}

// --- outbound text -------------------------------------------------------------

const LABEL = { EMERGENCY: 'EMERGENCY', EMERGENCY_TEST: 'EMERGENCY TEST', IMPORTANT: 'IMPORTANT', GENERAL: 'General' };

function encodeWord(s) {
    return `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

/**
 * The raw acknowledgement (RFC 5322). Every header value is either a constant,
 * a validated address, a validated Message-ID, or base64 encoded, so nothing
 * from the inbound message can inject a header.
 */
export function buildAck({ fsiAddress, to, subject, rfcMessageId, receivedAt, designation, ref, exercise }) {
    const fsi = parseAddress(fsiAddress);
    const rcpt = parseAddress(to);
    if (!fsi || !rcpt) throw new Error('acknowledgement needs valid From and To addresses');
    const subj = cleanText(subject);
    const lines = [
        `From: FedRAMP Security Inbox <${fsi}>`,
        `To: <${rcpt}>`,
        `Subject: ${encodeWord(`${exercise ? '[EXERCISE] ' : ''}Received: ${subj || '(no subject)'}`)}`,
        'Auto-Submitted: auto-replied',
        'X-Auto-Response-Suppress: All',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: base64',
    ];
    if (rfcMessageId && RFC_MESSAGE_ID.test(rfcMessageId)) {
        lines.push(`In-Reply-To: ${rfcMessageId}`, `References: ${rfcMessageId}`);
    }
    const body = [
        exercise ? 'THIS IS AN EXERCISE. No FedRAMP message was involved.\n' : '',
        `This is an automatic acknowledgement from the FedRAMP Security Inbox (${fsi}).`,
        '',
        `Your message was received at ${receivedAt}.`,
        `Designation recognised from the subject line: ${LABEL[designation] || 'General'}.`,
        `Reference: ${ref}`,
        '',
        'The security official has been notified. This reply is automatic; a person will respond separately.',
    ].join('\n');
    const b64 = Buffer.from(body, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
    return `${lines.join('\r\n')}\r\n\r\n${b64}\r\n`;
}

/** SNS subject (ASCII, at most 100 characters) and message for one record. */
export function pageFor(r, { runbook } = {}) {
    const label = LABEL[r.designation] || 'General';
    const prefix = r.exercise ? '[FSI EXERCISE]' : '[FSI]';
    const subject = `${prefix} ${label} FedRAMP message from ${r.sender_domain || 'unknown'}`
        .replace(/[^\x20-\x7e]/g, '?').slice(0, 100);
    const lines = [
        r.exercise ? 'EXERCISE: this page was produced by scripts/fsi.py exercise, not by FedRAMP.' : '',
        `Designation: ${label}`,
        `From: ${r.from || '(unparseable)'}`,
        `Subject: ${r.subject || '(none)'}`,
        `Received: ${r.received_at}`,
        `Open by (triage): ${r.triage_by}`,
        `Required actions due: ${r.respond_by || 'record the timeframe stated in the message'}`,
        `Deadline basis: ${r.deadline_basis}`,
        `Sender authentication: SPF ${r.auth?.spf}, DKIM ${r.auth?.dkim}, DMARC ${r.auth?.dmarc}` +
            (r.authenticated ? '' : ' -- NOT AUTHENTICATED: confirm the sender before acting (AFC-CSO-TFG)'),
        r.emergency_sender_ok === false ? 'Emergency designation from an address other than fedramp_security@ (AFC-FRP-UFS): confirm the sender.' : '',
        `Register reference: ${r.id}`,
        '',
        'Read the message with: python3 scripts/fsi.py show ' + r.id,
        runbook ? `Runbook: ${runbook}` : '',
    ].filter((x) => x !== '');
    return { subject, message: lines.join('\n') };
}

// --- configuration check ---------------------------------------------------------

/**
 * Compare the live receiving configuration with what Terraform declared. Each
 * problem is a sentence naming the setting; the count is the metric.
 */
export function configProblems(expected, live) {
    const p = [];
    const set = live.ruleSet;
    if (!set || !set.Metadata) {
        p.push('no receipt rule set is active');
    } else {
        if (set.Metadata.Name !== expected.ruleSet) p.push(`active rule set is ${set.Metadata.Name}, expected ${expected.ruleSet}`);
        const rules = set.Rules || [];
        const idx = rules.findIndex((r) => r.Name === expected.rule);
        if (idx < 0) {
            p.push(`rule ${expected.rule} is missing from the active rule set`);
        } else {
            const r = rules[idx];
            if (!r.Enabled) p.push(`rule ${expected.rule} is disabled`);
            const rcpts = (r.Recipients || []).map((x) => x.toLowerCase());
            if (rcpts.length !== 1 || rcpts[0] !== expected.address) p.push(`rule ${expected.rule} does not receive exactly the FedRAMP Security Inbox address`);
            if (!r.ScanEnabled) p.push('spam and virus scanning is off (verdicts are recorded, never used to drop FedRAMP mail)');
            if (r.TlsPolicy && r.TlsPolicy !== 'Optional') p.push(`TLS policy is ${r.TlsPolicy}; Require can refuse a sender (AFC-CSO-RCV)`);
            const acts = r.Actions || [];
            const s3 = acts[0]?.S3Action;
            const fn = acts[1]?.LambdaAction;
            if (!s3 || s3.BucketName !== expected.bucket || s3.ObjectKeyPrefix !== expected.prefix) p.push('first action does not store the message in the inbox bucket');
            if (!fn || fn.FunctionArn !== expected.functionArn || fn.InvocationType !== 'Event') p.push('second action does not hand the message to the inbox function');
            if (acts.length !== 2) p.push(`rule ${expected.rule} has ${acts.length} actions, expected 2`);
            // A rule ahead of ours that matches the address (or every address)
            // and stops, bounces or diverts the message would drop FedRAMP mail.
            for (const earlier of rules.slice(0, idx)) {
                const er = (earlier.Recipients || []).map((x) => x.toLowerCase());
                const matches = er.length === 0 || er.some((x) => x === expected.address || x === domainOf(expected.address));
                if (earlier.Enabled && matches) p.push(`rule ${earlier.Name} runs before ${expected.rule} for this address`);
            }
        }
    }
    const id = live.identity;
    if (!id) p.push('the domain identity is missing');
    else {
        if (!id.VerifiedForSendingStatus) p.push('the domain identity is not verified for sending');
        if (id.DkimAttributes?.Status !== 'SUCCESS') p.push(`DKIM status is ${id.DkimAttributes?.Status || 'unknown'}`);
        if (id.MailFromAttributes?.MailFromDomainStatus !== 'SUCCESS') p.push(`custom MAIL FROM status is ${id.MailFromAttributes?.MailFromDomainStatus || 'unknown'}`);
    }
    const acct = live.account;
    if (!acct) p.push('SES account status unreadable');
    else {
        if (!acct.ProductionAccessEnabled) p.push('SES account is in the sandbox: acknowledgements reach verified addresses only (AFC-CSO-ACK)');
        if (acct.SendingEnabled === false) p.push('SES sending is disabled for the account');
    }
    const mx = (live.mx || []).map((v) => String(v).trim().toLowerCase().replace(/^\d+\s+/, '').replace(/\.$/, ''));
    if (mx.length !== 1 || mx[0] !== expected.mx) p.push(`MX for the domain is ${JSON.stringify(mx)}, expected ["${expected.mx}"]`);
    return p;
}
