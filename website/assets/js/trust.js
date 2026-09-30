// Trust Center: renders /.well-known/trust-center.json (built and signed on every
// deploy by scripts/build-trust-center.py) for an Authorizing Official. The page
// is presentational: every word and number below comes from that document. All
// data reaches the DOM through textContent, never as markup.

const ROOT = typeof document === 'undefined' ? null : document.querySelector('[data-trust-center]');
const REPO = 'https://github.com/sam-aydlette/samaydlette.com';

const STATUS = {
    ok: { label: 'Verified', mark: '✓' },
    attention: { label: 'Needs attention', mark: '!' },
    not_observed: { label: 'Not observed', mark: '?' },
};

const KIND_LABELS = {
    vulnerability_disposition: 'Vulnerability disposition',
    policy_exception: 'Policy exception',
    poam_risk_decision: 'POA&M risk decision',
    significant_change: 'Significant change',
};

const ARTIFACTS = [
    ['trust-center.json', 'This page’s data: checks, decision queue, policy catalog, decision record'],
    ['boundary-map.json', 'The authorization boundary map'],
    ['reconcile-report.json', 'The reconciliation gate’s report for this deploy'],
    ['ksi-signal.json', 'The canonical inventory and KSI results'],
    ['oscal-ssp.json', 'System Security Plan (NIST OSCAL)'],
    ['oscal-poam.json', 'Plan of Action and Milestones (NIST OSCAL)'],
    ['vdr-report.json', 'Vulnerability Detection and Response report'],
    ['ksi-signal-runtime.json', 'The daily runtime re-validation (KMS-signed; key in runtime-signing-pubkey.pem)'],
];

const FRAMEWORKS = [
    ['moderate_coverage', 'FedRAMP Rev 5 Moderate baseline'],
    ['govramp_coverage', 'GovRAMP'],
    ['txramp1_coverage', 'TX-RAMP Level 1'],
    ['txramp2_coverage', 'TX-RAMP Level 2'],
    ['cmmc_coverage', 'CMMC Level 2'],
];

// ---------------------------------------------------------------------------
// Live re-checks. Two evidence streams change between deploys: the daily runtime
// signal and the nightly vulnerability refresh. The deploy-time verdict for them
// goes stale on a quiet week, so the page re-reads both and judges them now,
// against the windows the deploy published. The runtime verdict is the signed
// one the emitter recorded (divergence.status); the page never recomputes it
// from validation results, which cannot tell a regression from a read error.

const HOUR = 3600 * 1000;

function ageHours(iso, now) {
    const t = Date.parse(iso);
    return Number.isNaN(t) ? null : Math.round(((now - t) / HOUR) * 10) / 10;
}

export function evaluateRuntime(signal, now, windowHours) {
    const div = signal?.divergence || {};
    const age = ageHours(signal?.emitted_at, now);
    const stale = age === null || age > windowHours;
    const counts = `${div.ksis_compared ?? 0} KSIs compared, ${(div.regressions || []).length} regressed, ${(div.unassessed || []).length} not assessed`;
    const ageText = age === null ? 'age unknown' : `${age} h old (window ${windowHours} h)`;
    return {
        status: div.status === 'converged' && !stale ? 'ok' : 'attention',
        detail: `${div.status || 'unknown'}: ${counts}; ${ageText}${stale ? ', past its freshness window' : ''}.`,
        as_of: signal?.emitted_at || null,
    };
}

export function evaluateNightly(beacon, now, windowHours) {
    const age = ageHours(beacon?.finished_at, now);
    const stale = age === null || age > windowHours;
    const result = beacon?.result || 'unknown';
    return {
        status: result === 'success' && !stale ? 'ok' : 'attention',
        detail: `Last nightly run: ${result}${age === null ? '' : `, ${age} h ago (window ${windowHours} h)`}${stale ? ', past its freshness window' : ''}.`,
        as_of: beacon?.finished_at || null,
    };
}

function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = v;
        else e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children) {
        if (c === null || c === undefined || c === false) continue;
        e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
}

function slot(name) {
    return ROOT.querySelector(`[data-tc="${name}"]`);
}

function relativeAge(iso) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return null;
    const mins = Math.round((Date.now() - t) / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins} min ago`;
    const hours = Math.round(mins / 60);
    if (hours < 48) return `${hours} h ago`;
    return `${Math.round(hours / 24)} days ago`;
}

function when(iso) {
    if (!iso) return null;
    const age = relativeAge(iso);
    return el('time', { datetime: iso, title: iso }, age || iso);
}

function link(href, text) {
    // Only same-site paths and https URLs are ever rendered as links.
    if (typeof href !== 'string' || !(href.startsWith('/') || href.startsWith('https://'))) return document.createTextNode(text);
    return el('a', { href }, text);
}

// A published artifact becomes a link; a script is named by its file only.
function sourceRef(src) {
    if (src.startsWith('/')) return link(src, src.replace('/.well-known/', ''));
    return el('a', { href: `${REPO}/blob/main/${src}` }, src.split('/').pop());
}

function statusChip(status) {
    const s = STATUS[status] || STATUS.not_observed;
    return el('span', { class: `tc-chip tc-${status in STATUS ? status : 'not_observed'}` },
        el('span', { class: 'tc-chip-mark', 'aria-hidden': 'true' }, s.mark), s.label);
}

// ---------------------------------------------------------------------------

function renderFacts(doc) {
    const dl = slot('facts');
    const add = (k, v) => dl.append(el('div', {}, el('dt', { text: k }), el('dd', {}, v)));
    add('Program', el('span', {}, 'FedRAMP 20x Class C', el('span', { class: 'tc-fact-note', text: 'Adheres to; not certified' })));
    add('Impact level', (doc.system?.impact_level || 'unknown').replace(/^./, (c) => c.toUpperCase()));
    add('Published', when(doc.generated_at) || 'unknown');
    add('Build', doc.commit ? el('a', { href: `${REPO}/commit/${doc.commit}` }, el('code', { text: doc.commit.slice(0, 7) })) : 'unknown');
    const sid = doc.ksi_signal_id || 'unknown';
    add('Inventory', el('code', { text: sid.length > 8 ? `${sid.slice(0, 8)}…` : sid, title: sid }));
}

function pictureItem(p) {
    return el('li', { class: `tc-check tc-check-${p.status}`, 'data-check': p.id },
            statusChip(p.status),
            el('div', { class: 'tc-check-body' },
                el('h3', { text: p.label }),
                el('p', { text: p.detail }),
                (p.as_of || p.source) ? el('p', { class: 'tc-check-meta' },
                    p.as_of ? el('span', {}, 'As of ', when(p.as_of)) : null,
                    p.as_of && p.source ? ' · ' : null,
                    p.source ? sourceRef(p.source) : null,
                ) : null,
                p.live ? el('p', { class: 'tc-check-meta tc-live', text: 'Re-checked live in your browser just now.' }) : null,
            ));
}

function renderPicture(doc) {
    const ul = slot('picture');
    for (const p of doc.picture || []) ul.append(pictureItem(p));
}

// ---------------------------------------------------------------------------
// The live queue. The deploy builds the queue, but part of it is driven by
// dates and by evidence that changes between deploys. The page rebuilds that
// part now, from data the deploy published with it, so an empty queue is true
// on the day it is read. Everything else (a pending trust-root change, a
// drifted setting, an unclassified resource) only changes with a deploy.

const DATE_KINDS = ['decision_review_due', 'exception_expiring', 'poam_overdue'];
const RUNTIME_KINDS = ['runtime_diverged', 'runtime_unassessed', 'runtime_stale'];
const DAY = 24 * HOUR;

export function liveQueue(doc, now, live = {}) {
    const lq = doc.live_queue;
    const deployed = doc.decisions_pending || [];
    if (!lq || !lq.why_yours) return deployed; // published before the live queue existed
    const today = new Date(now).toISOString().slice(0, 10);
    const windows = doc.freshness_windows_hours || {};
    const rebuilt = new Set([...DATE_KINDS, 'vulnerability_evidence_stale', ...(live.runtime ? RUNTIME_KINDS : [])]);
    const out = deployed.filter((d) => !rebuilt.has(d.kind));
    const item = (kind, id, title, extra = {}) => ({ kind, id, title, why_yours: lq.why_yours[kind], since: null, due: null, refs: [], ...extra });

    for (const p of lq.poam_due || []) {
        if (p.due < today) out.push(item('poam_overdue', p.id, p.title, { due: p.due, refs: ['/.well-known/oscal-poam.json'] }));
    }
    for (const e of doc.decision_log || []) {
        if (!e.review_by) continue;
        if (e.kind === 'policy_exception') {
            // An exception's review date is its expiry.
            const daysLeft = (Date.parse(e.review_by) - Date.parse(today)) / DAY;
            if (daysLeft <= (lq.exception_warning_days ?? 30)) {
                out.push(item('exception_expiring', e.id, `Policy exception ${e.subject}`, { due: e.review_by, refs: e.ticket ? [e.ticket] : [] }));
            }
        } else if (e.review_by <= today) {
            out.push(item('decision_review_due', e.id, `Review due: ${e.subject}`, { due: e.review_by, refs: [e.source] }));
        }
    }
    if (live.runtime) {
        const div = live.runtime.divergence || {};
        const since = live.runtime.emitted_at || null;
        for (const r of div.regressions || []) {
            out.push(item('runtime_diverged', r.ksi_id, `${r.ksi_id} passed at deploy but fails at runtime`, { since, refs: ['/.well-known/ksi-signal-runtime.json'] }));
        }
        const unassessed = (div.unassessed || []).map((u) => u.ksi_id);
        if (unassessed.length) {
            out.push(item('runtime_unassessed', 'runtime-unassessed', `${unassessed.length} KSI(s) not assessed at runtime: ${unassessed.join(', ')}`, { since, refs: ['/.well-known/ksi-signal-runtime.json'] }));
        }
        const age = ageHours(since, now);
        if (age === null || age > (windows.runtime || 26)) {
            out.push(item('runtime_stale', 'runtime-stale', 'The runtime signal is past its freshness window', { since }));
        }
    }
    if (live.vdrReport) {
        // The vulnerability evidence itself, not the job that refreshes it: a
        // failed nightly matters to an AO once the published evidence is stale.
        const age = ageHours(live.vdrReport.emitted_at, now);
        if (age === null || age > (windows.vulnerability_scan || 24)) {
            out.push(item('vulnerability_evidence_stale', 'vdr-stale', 'The published vulnerability evidence is past its freshness window',
                { since: live.vdrReport.emitted_at || null, refs: ['/.well-known/vdr-report.json'] }));
        }
    }
    return out;
}

function getJson(url) {
    return fetch(url, { credentials: 'same-origin', cache: 'no-cache' })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))));
}

function recheckLive(doc) {
    const windows = doc.freshness_windows_hours || {};
    const settled = (pr) => pr.then((v) => v, () => null); // an unreadable source keeps the deploy-time verdict
    Promise.all([
        settled(getJson('/.well-known/ksi-signal-runtime.json')),
        settled(getJson('/.well-known/vdr-status.json')),
        settled(getJson('/.well-known/vdr-report.json')),
    ]).then(([runtime, beacon, vdrReport]) => {
        const now = Date.now();
        for (const [id, data, evaluate, windowHours] of [
            ['runtime', runtime, evaluateRuntime, windows.runtime],
            ['vulnerability_scan', beacon, evaluateNightly, windows.vulnerability_scan],
        ]) {
            const row = ROOT.querySelector(`[data-check="${id}"]`);
            const base = (doc.picture || []).find((p) => p.id === id);
            if (row && base && data && windowHours) row.replaceWith(pictureItem({ ...base, ...evaluate(data, now, windowHours), live: true }));
        }
        if (doc.live_queue) renderQueue(liveQueue(doc, now, { runtime, vdrReport }), true);
    });
}

function renderQueue(items, live = false) {
    const host = slot('queue');
    host.replaceChildren();
    const note = live ? el('p', { class: 'tc-check-meta tc-live', text: 'Re-checked live in your browser just now: review dates, expiries, due dates, and runtime and vulnerability-evidence freshness.' }) : null;
    if (!items.length) {
        host.append(el('div', { class: 'tc-empty' },
            el('p', { class: 'tc-empty-title', text: 'Nothing needs your decision right now.' }),
            el('p', { text: 'Every finding and exception is covered by a recorded decision that is not due for review, and nothing else that would need a person has come up. When that changes, it appears here with the reason it is yours.' })), note);
        return;
    }
    const ol = el('ol', { class: 'tc-queue' });
    for (const d of items) {
        const meta = [];
        if (d.since) meta.push(el('span', {}, 'Since ', when(d.since)));
        if (d.due) meta.push(el('span', {}, `Due ${d.due}`));
        ol.append(el('li', { class: 'tc-queue-item' },
            el('h3', { text: d.title }),
            el('p', { class: 'tc-why' }, el('strong', { text: 'Why it is yours: ' }), d.why_yours),
            meta.length ? el('p', { class: 'tc-check-meta' }, ...meta.flatMap((m, i) => (i ? [' \u00b7 ', m] : [m]))) : null,
            (d.refs || []).length ? el('p', { class: 'tc-check-meta' }, 'See: ',
                ...d.refs.flatMap((r, i) => [i ? ', ' : null, r.startsWith('/') ? link(r, r.replace('/.well-known/', '')) : el('code', { text: r })])) : null,
        ));
    }
    host.append(el('p', { class: 'tc-count' }, `${items.length} item${items.length === 1 ? '' : 's'} awaiting a decision`), ol, note);
}

function sparkline(history) {
    const pts = history.slice(-60);
    if (pts.length < 2) return null;
    const W = 240, H = 40, max = Math.max(1, ...pts.map((h) => h.escalated));
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('class', 'tc-spark');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `Items escalated per day over the last ${pts.length} days`);
    const path = document.createElementNS(NS, 'polyline');
    path.setAttribute('points', pts.map((h, i) => `${(i / (pts.length - 1)) * W},${H - 2 - (h.escalated / max) * (H - 4)}`).join(' '));
    svg.append(path);
    return svg;
}

function renderEscalation(doc) {
    const r = doc.escalation_rate;
    if (!r) return;
    const host = slot('escalation');
    const pct = `${Math.round((r.rate || 0) * 1000) / 10}%`;
    // el() drops null children; a bare append() would print "null".
    const days = (r.history || []).length;
    host.append(el('div', {},
        el('p', { class: 'tc-rate' },
            el('span', { class: 'tc-rate-label', text: 'Escalation rate' }),
            el('span', { class: 'tc-rate-part' }, el('span', { class: 'tc-rate-num', text: String(r.resolved_by_precedent) }), ' settled by precedent'),
            el('span', { class: 'tc-rate-sep', 'aria-hidden': 'true', text: '\u00b7' }),
            el('span', { class: 'tc-rate-part' }, el('span', { class: 'tc-rate-num', text: String(r.escalated) }), ` brought to a person (${pct})`)),
        days >= 7 ? sparkline(r.history) : null,
        el('p', { class: 'tc-check-meta' }, `Measured at the last deploy (`, when(doc.generated_at) || 'time unknown',
            `), unlike the queue above, which is re-checked live. ${r.about}`,
            days >= 7 ? '' : ` A daily trend appears after a week of history (${days} day${days === 1 ? '' : 's'} so far).`),
    ));
}

function renderPolicy(doc) {
    const c = doc.policy_catalog || {};
    const host = slot('policy');
    const card = (title, about, count, body) => el('details', { class: 'tc-policy-card' },
        el('summary', {}, el('span', { class: 'tc-policy-title' }, el('span', { class: 'tc-caret', 'aria-hidden': 'true' }), title), el('span', { class: 'tc-policy-count', text: count }), el('span', { class: 'tc-policy-about', text: about })),
        body);

    const rules = c.immutable?.rules || [];
    host.append(card('Immutable rules', c.immutable?.about, `${rules.length} rules`,
        el('ul', {}, ...rules.map((r) => el('li', {}, el('code', { text: r.id }), ` ${r.title} `, el('span', { class: 'tc-muted', text: `(${(r.severity || '').toLowerCase()}; ${(r.ksi_ids || []).join(', ')})` }))))));

    const th = c.thresholds?.items || [];
    host.append(card('Thresholds', c.thresholds?.about, `${th.length} thresholds`,
        el('dl', { class: 'tc-kv' }, ...th.map((t) => el('div', {}, el('dt', { text: t.name }), el('dd', {}, t.value, ' ', el('span', { class: 'tc-muted' }, '(', el('code', { text: t.source }), ')')))))));

    const regs = c.precedent?.registers || [];
    host.append(card('Precedent', c.precedent?.about, `${regs.reduce((n, r) => n + (r.entries || 0), 0)} register entries`,
        el('ul', {}, ...regs.map((r) => el('li', {}, `${r.name}: ${r.entries} `, el('span', { class: 'tc-muted' }, '(', el('code', { text: r.source }), ')'))))));

    const gates = c.escalation?.gates || [];
    host.append(card('Escalation points', c.escalation?.about, `${gates.length} gates`,
        el('ul', {}, ...gates.map((g) => el('li', {}, el('strong', { text: g.name }), `: stops ${g.stops}; decided by ${g.decided_by}.`)))));
}

// The register key of a vulnerability disposition or exception is long; show
// the advisory or rule it concerns (the full key is in the title and subject).
function shortId(e) {
    if (e.kind === 'vulnerability_disposition') {
        const m = e.id.match(/(CVE-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3})/i);
        if (m) return m[1];
    }
    if (e.kind === 'policy_exception') return e.id.split(':')[0];
    return e.id;
}

function renderRecord(doc) {
    const host = slot('record');
    const log = doc.decision_log || [];
    const gaps = doc.decision_log_gaps || {};
    const missing = Object.values(gaps).reduce((a, b) => a + b, 0);

    const kinds = [...new Set(log.map((e) => e.kind))];
    const select = el('select', { id: 'tc-kind' }, el('option', { value: '', text: `All (${log.length})` }),
        ...kinds.map((k) => el('option', { value: k, text: `${KIND_LABELS[k] || k} (${log.filter((e) => e.kind === k).length})` })));
    host.append(
        el('p', { class: 'tc-count' }, `${log.length} recorded decisions · `,
            missing ? el('strong', { text: `${missing} missing field${missing === 1 ? '' : 's'}` }) : 'every decision attributed, dated and scheduled for review'),
        el('p', { class: 'tc-filter' }, el('label', { for: 'tc-kind', text: 'Show ' }), select),
    );

    const cell = (v, label) => (v ? el('td', { 'data-label': label, text: v }) : el('td', { 'data-label': label }, el('span', { class: 'tc-gap', text: 'not recorded' })));
    const tbody = el('tbody');
    for (const e of log) {
        const reasoning = el('details', { class: 'tc-reason' }, el('summary', { text: e.subject }), el('p', { text: e.reasoning }),
            el('p', { class: 'tc-check-meta' }, 'Source: ', e.source.startsWith('/') ? link(e.source, e.source.replace('/.well-known/', '')) : el('code', { text: e.source })));
        const tr = el('tr', { 'data-kind': e.kind },
            el('th', { scope: 'row' }, el('code', { text: shortId(e), title: e.id })),
            el('td', { 'data-label': 'What' }, el('span', { class: 'tc-muted', text: KIND_LABELS[e.kind] || e.kind }), reasoning),
            el('td', { 'data-label': 'Outcome', text: e.decision }),
            cell(e.decided_by, 'Decided by'), cell(e.decided_on, 'On'),
            e.kind === 'significant_change' ? el('td', { 'data-label': 'Review', class: 'tc-muted', text: e.verified ? 'verified' : 'verification pending' }) : cell(e.review_by, 'Review by'));
        tbody.append(tr);
    }
    const table = el('table', { class: 'tc-table' },
        el('caption', { class: 'visually-hidden', text: 'Recorded human decisions' }),
        el('thead', {}, el('tr', {}, ...['Decision', 'What', 'Outcome', 'Decided by', 'On', 'Review by'].map((h) => el('th', { scope: 'col', text: h })))),
        tbody);
    // About five rows show at once; the rest scroll inside the box. Focusable,
    // so the region scrolls from the keyboard too.
    host.append(el('div', { class: 'tc-table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Recorded decisions (scrolls)' }, table),
        el('p', { class: 'tc-check-meta', text: 'Scroll inside the table for the rest; filter above by kind.' }));
    select.addEventListener('change', () => {
        for (const tr of tbody.rows) tr.hidden = !!select.value && tr.dataset.kind !== select.value;
    });
}

function renderPosture(doc) {
    const host = slot('posture');
    const k = doc.posture?.ksis || {};
    const by = k.by_status || {};
    host.append(el('p', {}, el('strong', { text: `${by.pass || 0} of ${k.total || 0}` }),
        ' Key Security Indicators pass at deploy time',
        Object.keys(by).filter((s) => s !== 'pass').length ? ` (${Object.entries(by).filter(([s]) => s !== 'pass').map(([s, n]) => `${n} ${s}`).join(', ')})` : '',
        '. The runtime check above re-validates them against the live system every day.'));
    const f = doc.posture?.frameworks || {};
    const rows = FRAMEWORKS.filter(([key]) => f[key]);
    if (rows.length) {
        host.append(
            el('p', { text: 'Controls with an implementation statement in the System Security Plan, by framework. This measures documentation coverage, not an assessment result.' }),
            el('dl', { class: 'tc-kv tc-kv-compact' }, ...rows.map(([key, label]) => el('div', {}, el('dt', { text: label }), el('dd', { text: f[key] })))));
        if (f.moderate_implemented) {
            host.append(el('p', { class: 'tc-check-meta', text: `Moderate baseline: ${f.moderate_implemented} implemented by this system, ${f.moderate_inherited} inherited from AWS, ${f.moderate_na} not applicable.` }));
        }
    }
}

function renderArtifacts() {
    const ul = slot('artifacts');
    for (const [file, what] of ARTIFACTS) {
        ul.append(el('li', {}, link(`/.well-known/${file}`, file), ` — ${what}`));
    }
}

function render(doc) {
    renderFacts(doc);
    renderPicture(doc);
    renderQueue(doc.decisions_pending || []);
    recheckLive(doc);
    renderEscalation(doc);
    renderPolicy(doc);
    renderRecord(doc);
    renderPosture(doc);
    renderArtifacts();
}

if (ROOT) {
    const status = slot('status');
    fetch(ROOT.dataset.trustCenter, { credentials: 'same-origin', cache: 'no-cache' })
        .then((r) => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .then((doc) => {
            if (doc.schema !== 'trust-center/1') throw new Error(`unexpected schema ${doc.schema}`);
            render(doc);
            status.hidden = true;
        })
        .catch((err) => {
            status.textContent = `The trust center data could not be loaded (${err.message}). It is published at /.well-known/trust-center.json.`;
            status.classList.add('tc-error');
            renderArtifacts();
        });
}
