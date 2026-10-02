/**
 * Live boundary map: an interactive rendering of /.well-known/boundary-map.json.
 *
 * The map is generated on every deploy by scripts/build-boundary-graph.py from the
 * signed canonical inventory, Terraform state and the operator's classification
 * (docs/boundary/boundary-classification.json), signed, and bound to the build by the
 * reconciliation gate (invariant l). This module lays it out and draws it; it adds
 * nothing to it, and fetches nothing but same-origin files.
 *
 * Interaction: pan/zoom, a health summary, click-to-trace data flows, a detail card for
 * any component or flow, and a text view of the same data for screen readers and for
 * readers who would rather scan a table than a graph.
 */

import cytoscape from '/assets/vendor/cytoscape/cytoscape.esm.min.js';

const ROOT = document.querySelector('[data-boundary-map]');

const FLOW_COLOR = '#2563eb';
const FLAG_COLOR = '#dc2626';

// Layout, in canvas units. Zones run left to right; inside a zone, groups are stacked
// in columns; inside a group, components sit on a grid.
const CELL_W = 190;
const CELL_H = 120;
const GROUP_COLS = 3;
const GROUP_GAP = 90;
const COLUMN_GAP = 150;
const ZONE_GAP = 230;
const GROUP_PAD = 26;
const ZONE_PAD = 48;
const ZONE_ORDER = ['outside', 'system', 'external', 'unclassified'];
const ZONE_COLUMNS = {
    system: [['website', 'compliance', 'watchdog'], ['app', 'audit', 'trust-root']],
    external: [['github', 'sigstore', 'operator-mfa', 'vuln-feeds', 'declared-external']],
};

// Icons are committed with provenance (assets/boundary-map/PROVENANCE.md).
const ICON_BY_TYPE = {
    function: 'aws-lambda', object_store: 'aws-s3', cdn_distribution: 'aws-cloudfront', dns_zone: 'aws-route53',
    tls_certificate: 'aws-acm', event_schedule: 'aws-eventbridge', log_group: 'aws-cloudwatch',
    metric_alarm: 'aws-cloudwatch', identity_provider: 'aws-cognito', iam_role: 'aws-iam', iam_policy: 'aws-iam',
    iam_group: 'aws-iam', oidc_provider: 'aws-iam', kms_key: 'aws-kms', secrets_manager: 'aws-secrets-manager',
    message_queue: 'aws-sqs', api_gateway: 'aws-apigateway', audit_log_trail: 'aws-cloudtrail',
};
const ICON_BY_ID = {
    'ext::github-repo': 'github-repository', 'ext::github-oidc': 'github-platform',
    'ext::sigstore-fulcio': 'sigstore-ca', 'ext::sigstore-rekor': 'rekor-log-entry',
};

const CLASSIFICATION_LABELS = {
    archetype: 'Archetype', data_sensitivity: 'Data sensitivity',
    mission_criticality: 'Mission criticality', internet_reachable: 'Internet reachable',
};
const KIND_LABELS = {
    actor: 'Actor outside the boundary', not_inventoried: 'Declared, not in the inventory',
};

function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? '' : v);
    }
    children.flat().forEach((c) => c !== null && c !== undefined && e.append(c));
    return e;
}

function relativeAge(iso) {
    const hours = (Date.now() - Date.parse(iso)) / 3.6e6;
    if (!Number.isFinite(hours)) return iso;
    if (hours < 1) return 'under an hour ago';
    if (hours < 48) return `${Math.round(hours)} hours ago`;
    return `${Math.round(hours / 24)} days ago`;
}

function cssVar(name, fallback) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function palette() {
    return {
        text: cssVar('--text-primary', '#0f172a'),
        muted: cssVar('--text-muted', '#64748b'),
        border: cssVar('--border-color', '#cbd5e1'),
        page: cssVar('--bg-primary', '#f8f9fa'),
    };
}

function iconFor(node) {
    const name = ICON_BY_ID[node.id] || ICON_BY_TYPE[node.type];
    return name ? `/assets/boundary-map/icons/${name}.svg` : undefined;
}

// ---------------------------------------------------------------------------------
// Layout: positions for every node, and boxes for every group and zone.
// ---------------------------------------------------------------------------------
function layout(snap) {
    const byGroup = new Map();
    snap.nodes.forEach((n) => { if (!byGroup.has(n.group)) byGroup.set(n.group, []); byGroup.get(n.group).push(n); });
    const positions = new Map();
    const boxes = [];
    let zoneX = 0;
    const zones = [...snap.zones].filter((z) => z.key !== 'leveraged')
        .sort((a, b) => ZONE_ORDER.indexOf(a.key) - ZONE_ORDER.indexOf(b.key));
    for (const zone of zones) {
        const groups = snap.groups.filter((g) => g.zone === zone.key && byGroup.has(g.key));
        if (!groups.length) continue;
        const columns = (ZONE_COLUMNS[zone.key] || [[]]).map((col) => col.filter((k) => groups.some((g) => g.key === k)));
        groups.filter((g) => !columns.flat().includes(g.key)).forEach((g) => columns[columns.length - 1].push(g.key));
        let columnX = zoneX;
        let zoneRight = zoneX;
        let zoneBottom = 0;
        for (const col of columns.filter((c) => c.length)) {
            let y = 0;
            let colWidth = 0;
            for (const key of col) {
                const members = byGroup.get(key);
                members.forEach((n, i) => positions.set(n.id, {
                    x: columnX + (i % GROUP_COLS) * CELL_W, y: y + Math.floor(i / GROUP_COLS) * CELL_H,
                }));
                const width = (Math.min(members.length, GROUP_COLS) - 1) * CELL_W;
                const height = (Math.ceil(members.length / GROUP_COLS) - 1) * CELL_H;
                const g = snap.groups.find((x) => x.key === key);
                boxes.push({ id: `group:${key}`, label: g.label, cls: 'group', x1: columnX - GROUP_PAD - 22, y1: y - GROUP_PAD - 22,
                    x2: columnX + width + GROUP_PAD + 22, y2: y + height + GROUP_PAD + 40 });
                y += height + CELL_H + GROUP_GAP;
                colWidth = Math.max(colWidth, width);
            }
            zoneBottom = Math.max(zoneBottom, y - CELL_H - GROUP_GAP + 40);
            zoneRight = columnX + colWidth;
            columnX = zoneRight + CELL_W + COLUMN_GAP;
        }
        boxes.push({ id: `zone:${zone.key}`, label: zone.label, cls: `zone${zone.boundary ? ' boundary' : ''}`,
            x1: zoneX - ZONE_PAD - 22, y1: -ZONE_PAD - 40, x2: zoneRight + ZONE_PAD + 22, y2: zoneBottom + ZONE_PAD + GROUP_PAD });
        zoneX = zoneRight + CELL_W + ZONE_GAP;
    }
    return { positions, boxes };
}

function stylesheet(p) {
    return [
        { selector: 'node.resource', style: {
            'shape': 'round-rectangle', 'width': 44, 'height': 44, 'z-index': 10,
            // Icons are drawn for a light ground, so the tile stays white in both themes.
            'background-color': '#ffffff', 'border-width': 1, 'border-color': p.border,
            'background-image': 'data(icon)', 'background-fit': 'contain', 'background-width': '70%', 'background-height': '70%',
            'label': 'data(label)', 'font-size': 10, 'color': p.text, 'text-valign': 'bottom', 'text-margin-y': 4,
            'text-wrap': 'wrap', 'text-max-width': 150, 'text-background-color': p.page, 'text-background-opacity': 0.85,
            'text-background-padding': 1,
        } },
        { selector: 'node.resource[!icon]', style: { 'background-image': 'none' } },
        { selector: 'node.declared', style: { 'border-style': 'dotted', 'border-width': 2, 'background-opacity': 0.3 } },
        { selector: 'node.flagged', style: { 'border-color': FLAG_COLOR, 'border-width': 3, 'border-style': 'dashed' } },
        { selector: 'node.box', style: {
            'shape': 'rectangle', 'width': 'data(w)', 'height': 'data(h)', 'background-opacity': 0,
            'border-width': 1, 'border-style': 'dashed', 'border-color': p.border,
            'label': 'data(label)', 'font-size': 11, 'color': p.muted, 'text-valign': 'top', 'text-halign': 'center',
            'text-margin-y': -4, 'events': 'no', 'z-index': 0,
        } },
        { selector: 'node.zone', style: { 'border-width': 2, 'font-size': 13, 'font-weight': 'bold' } },
        { selector: 'node.zone.boundary', style: { 'border-color': FLAG_COLOR, 'color': FLAG_COLOR } },
        { selector: 'edge.ref', style: {
            'width': 1, 'line-color': p.border, 'target-arrow-color': p.border, 'target-arrow-shape': 'triangle',
            'arrow-scale': 0.6, 'curve-style': 'bezier', 'opacity': 0.6,
        } },
        { selector: 'edge.flow', style: {
            'width': 2.5, 'line-color': FLOW_COLOR, 'target-arrow-color': FLOW_COLOR, 'target-arrow-shape': 'triangle',
            'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 14, 'font-weight': 'bold', 'color': FLOW_COLOR,
            'text-background-color': p.page, 'text-background-opacity': 1, 'text-background-padding': 2,
        } },
        { selector: '.faded', style: { 'opacity': 0.1 } },
        { selector: 'node.resource:selected', style: { 'border-color': FLOW_COLOR, 'border-width': 3 } },
    ];
}

function elements(snap, positions, boxes) {
    const els = boxes.map((b) => ({
        group: 'nodes', classes: `box ${b.cls}`, selectable: false, grabbable: false,
        data: { id: b.id, label: b.label, w: b.x2 - b.x1, h: b.y2 - b.y1 },
        position: { x: (b.x1 + b.x2) / 2, y: (b.y1 + b.y2) / 2 },
    }));
    snap.nodes.forEach((n) => {
        const classes = ['resource'];
        if (n.kind !== 'collected') classes.push('declared');
        if (n.flags && n.flags.length) classes.push('flagged');
        const label = n.flags && n.flags.length ? `${n.name}\n⚠ ${n.flags.join(', ')}` : n.name;
        els.push({ group: 'nodes', classes: classes.join(' '), grabbable: false,
            data: { id: n.id, label, icon: iconFor(n) }, position: positions.get(n.id) });
    });
    snap.edges.forEach((e, i) => els.push({ group: 'edges', classes: 'ref', data: { id: `e${i}`, source: e.source, target: e.target } }));
    snap.flows.forEach((f) => f.hops.forEach(([a, b], i) => els.push({ group: 'edges', classes: 'flow',
        data: { id: `flow:${f.id}:${i}:${a}:${b}`, source: a, target: b, flow: f.id, label: i === 0 ? f.id : '' } })));
    return els;
}

function kv(dl, key, value) {
    if (value === undefined || value === null || value === '') return;
    dl.append(el('dt', { text: key }), el('dd', { text: String(value) }));
}

const TAP_LINK = () => el('a', { href: 'https://github.com/unified-systems-com/tap', rel: 'noopener', text: 'RAMPART on TAP — The Analogy Platform' });

function corroborationLine(report) {
    if (!report || !report.summary) return ['Independently corroborated by ', TAP_LINK(), ' when its report is available.'];
    const s = report.summary;
    const extra = [];
    if (s.tap_only) extra.push(`${s.tap_only} resource${s.tap_only === 1 ? '' : 's'} only TAP sees`);
    if (s.map_only) extra.push(`${s.map_only} TAP did not observe`);
    if (s.relationships_tap_only) extra.push(`${s.relationships_tap_only} relationship${s.relationships_tap_only === 1 ? '' : 's'} the map does not yet draw`);
    return ['Independently corroborated by ', TAP_LINK(),
        `, which collects the account straight from the AWS APIs: ${s.agree} of ${s.in_scope} components agree${extra.length ? `; ${extra.join('; ')}` : ''}. Checked ${relativeAge(report.checked_at)} (`,
        el('a', { href: '/.well-known/boundary-corroboration.json', text: 'report' }), ').'];
}

function init(snap) {
    const byId = new Map(snap.nodes.map((n) => [n.id, n]));
    const groupLabel = new Map(snap.groups.map((g) => [g.key, g.label]));
    const zoneLabel = new Map(snap.zones.map((z) => [z.key, z.label]));
    const flowsThrough = (id) => snap.flows.filter((f) => f.hops.some(([a, b]) => a === id || b === id));
    const { positions, boxes } = layout(snap);

    // --- Chrome: provenance and age ------------------------------------------------
    const generated = snap.generated_at;
    const header = el('div', { class: 'bm-header' },
        el('p', { class: 'bm-attribution' },
            'Generated at deploy from the signed ',
            el('a', { href: '/.well-known/ksi-signal.json', text: 'canonical inventory' }),
            ' and Terraform state; bound to that build and ',
            el('a', { href: '/.well-known/boundary-map.bundle', text: 'signed' }),
            `. Built ${relativeAge(generated)} `, el('time', { datetime: generated, text: `(${generated.replace('+00:00', 'Z')})` }), '.'),
        el('p', { class: 'bm-attribution', 'data-bm-corroboration': '' }, ...corroborationLine(null)),
    );
    // The independent check, loaded separately: the map stands on its own without it.
    fetch('/.well-known/boundary-corroboration.json', { credentials: 'same-origin', cache: 'no-cache' })
        .then((r) => (r.ok ? r.json() : null))
        .then((report) => { if (report) header.querySelector('[data-bm-corroboration]').replaceChildren(...corroborationLine(report)); })
        .catch(() => { /* keep the plain attribution */ });
    const canvas = el('div', { class: 'bm-canvas', role: 'img',
        'aria-label': 'Interactive authorization boundary map. A text view of the same components and data flows follows the map.' });
    const legend = el('aside', { class: 'bm-legend', 'aria-label': 'Boundary health and data flows' });
    const detail = el('aside', { class: 'bm-detail', 'aria-live': 'polite', hidden: true });
    const stage = el('div', { class: 'bm-stage' }, canvas, legend, detail);
    ROOT.replaceChildren(header, stage);

    const cy = cytoscape({
        container: canvas, elements: elements(snap, positions, boxes), style: stylesheet(palette()), layout: { name: 'preset' },
        minZoom: 0.05, maxZoom: 3, boxSelectionEnabled: false, autoungrabify: true,
    });

    // --- Legend: health + flows ---------------------------------------------------
    const h = snap.health;
    const toggle = el('button', { type: 'button', class: 'bm-toggle', 'aria-expanded': 'true', text: 'Hide' });
    const body = el('div', { class: 'bm-legend-body' });
    legend.append(el('div', { class: 'bm-legend-head' }, el('h4', { text: 'Boundary health' }), toggle), body);
    const healthList = el('ul', { class: 'bm-health' });
    [
        [h.unclassified, 'unclassified', 'Inventory components no classification rule places (fails the deploy)'],
        [h.untagged, 'untagged', 'AWS resources carrying no tags at all'],
        [h.classification_tags_incomplete, 'with incomplete classification tags', 'Tagged, but missing some of the six governed classification axes'],
        [h.pending_trust_root_changes, 'trust-root change(s) pending apply', 'Merged changes to the operator-applied bootstrap stack that are not applied yet'],
        [h.flows_with_unmatched_endpoint, 'flow(s) with an unmatched endpoint', 'A data flow whose endpoint matches nothing in this inventory'],
    ].forEach(([count, label, title]) => healthList.append(
        el('li', { class: count ? 'bm-bad' : 'bm-ok', title }, `${count ? '⚠' : '✓'} ${count} ${label}`)));
    healthList.append(el('li', { class: 'bm-info', title: 'Declared in the classification; the inventory has no component for them yet' },
        `• ${h.declared_not_inventoried} declared, not inventoried`));
    body.append(healthList);
    const unmatched = snap.flows.filter((f) => f.unmatched_endpoints.length);
    if (unmatched.length) {
        body.append(el('p', { class: 'bm-note', text:
            `Unmatched: ${unmatched.map((f) => `${f.id} (${f.unmatched_endpoints.join(', ')})`).join('; ')}.` }));
    }

    body.append(el('h4', { text: 'Data flows' }), el('p', { class: 'bm-hint', text: 'Select a flow to trace it.' }));
    const flowList = el('ul', { class: 'bm-flows' });
    let traced = null;
    const clearTrace = () => {
        cy.elements().removeClass('faded');
        flowList.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', 'false'));
        traced = null;
    };
    const trace = (flowId, button) => {
        if (traced === flowId) { clearTrace(); return; }
        clearTrace();
        const path = cy.edges(`[flow = "${flowId}"]`);
        cy.elements().not(path).not(path.connectedNodes()).not('.box').addClass('faded');
        if (button) button.setAttribute('aria-pressed', 'true');
        traced = flowId;
    };
    snap.flows.forEach((f) => {
        const b = el('button', { type: 'button', 'aria-pressed': 'false', onclick: () => { trace(f.id, b); showFlow(f); } },
            el('span', { class: 'bm-flow-id bm-in-table', text: f.id }),
            el('span', { text: f.label + (f.unmatched_endpoints.length ? ' (endpoint not in this inventory)' : '') }));
        flowList.append(el('li', {}, b));
    });
    body.append(flowList);

    // Fit into the area beside the legend while it is open, so it never covers the
    // actors outside the boundary on the left.
    const fit = () => {
        const pad = 24;
        const left = body.hidden ? pad : legend.offsetLeft + legend.offsetWidth + pad;
        const bb = cy.nodes('.zone').boundingBox();
        const w = cy.width() - left - pad;
        const hgt = cy.height() - 2 * pad;
        if (w <= 0 || hgt <= 0 || !bb.w) { cy.fit(cy.nodes('.zone'), pad); return; }
        const z = Math.min(w / bb.w, hgt / bb.h);
        cy.zoom(z);
        cy.pan({ x: left - bb.x1 * z + (w - bb.w * z) / 2, y: pad - bb.y1 * z + (hgt - bb.h * z) / 2 });
    };
    body.append(el('p', { class: 'bm-actions' },
        el('button', { type: 'button', onclick: () => { clearTrace(); fit(); }, text: 'Reset view' })));
    toggle.addEventListener('click', () => {
        const open = toggle.getAttribute('aria-expanded') === 'true';
        body.hidden = open;
        toggle.setAttribute('aria-expanded', String(!open));
        toggle.textContent = open ? 'Show' : 'Hide';
        fit();
    });
    if (window.matchMedia('(max-width: 768px)').matches) toggle.click();
    fit();

    // --- Detail card ---------------------------------------------------------------
    const openDetail = (title, fill) => {
        const dl = el('dl');
        fill(dl);
        const close = el('button', { type: 'button', class: 'bm-close', 'aria-label': 'Close details', text: '✕',
            onclick: () => { detail.hidden = true; } });
        detail.replaceChildren(el('div', { class: 'bm-detail-head' }, el('h4', { text: title }), close), dl);
        detail.hidden = false;
    };
    const showNode = (n) => openDetail(n.name, (dl) => {
        kv(dl, 'Kind', KIND_LABELS[n.kind] || (n.type || '').replace(/_/g, ' '));
        kv(dl, 'Inventory id', n.kind === 'collected' ? n.id : undefined);
        kv(dl, 'Group', groupLabel.get(n.group));
        kv(dl, 'Zone', zoneLabel.get(n.zone));
        kv(dl, 'Function', n.function);
        kv(dl, 'Why', n.why);
        if (n.flags) kv(dl, '⚠ Flags', n.flags.join(', '));
        Object.entries(n.classification || {}).forEach(([k, v]) => kv(dl, CLASSIFICATION_LABELS[k] || k, v));
        kv(dl, 'Region', n.region);
        kv(dl, 'Managed by', n.managed_by);
        if (n.findings) kv(dl, 'Findings', `${n.findings.total} (${n.findings.open} open, ${n.findings.blocking} blocking, ${n.findings.kev} KEV)`);
        const flows = flowsThrough(n.id);
        if (flows.length) kv(dl, 'Data flows', flows.map((f) => `${f.id} — ${f.label}`).join('; '));
    });
    const showFlow = (f) => openDetail(`Flow ${f.id}: ${f.label}`, (dl) => {
        kv(dl, 'Protocol / port', f.protocol);
        kv(dl, 'Authentication', f.auth);
        kv(dl, 'Encryption', f.encryption);
        kv(dl, 'Data', f.data);
        kv(dl, 'Note', f.note);
        if (f.unmatched_endpoints.length) kv(dl, 'Not in this inventory', f.unmatched_endpoints.join(', '));
    });
    cy.on('tap', 'node.resource', (evt) => showNode(byId.get(evt.target.id())));
    cy.on('tap', 'edge.flow', (evt) => {
        const f = snap.flows.find((x) => x.id === evt.target.data('flow'));
        const button = [...flowList.querySelectorAll('button')].find((b) => b.firstChild.textContent === f.id);
        trace(f.id, button);
        showFlow(f);
    });
    cy.on('tap', (evt) => { if (evt.target === cy) { clearTrace(); detail.hidden = true; } });

    new MutationObserver(() => cy.style(stylesheet(palette())))
        .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    renderTextView(snap, byId);
}

// The same data as a document: every component by zone and group, then the flow table.
function renderTextView(snap, byId) {
    const host = document.querySelector('[data-boundary-map-text]');
    if (!host) return;
    const parts = [];
    snap.zones.filter((z) => z.key !== 'leveraged').forEach((z) => {
        const groups = snap.groups.filter((g) => g.zone === z.key);
        if (!groups.length) return;
        parts.push(el('h5', { text: z.label }));
        const ul = el('ul');
        groups.forEach((g) => {
            const names = snap.nodes.filter((n) => n.group === g.key)
                .map((n) => n.name + (n.flags ? ` (⚠ ${n.flags.join(', ')})` : ''));
            ul.append(el('li', {}, el('strong', { text: `${g.label}: ` }), names.join(', ')));
        });
        parts.push(ul);
    });
    if (snap.leveraged) {
        parts.push(el('h5', { text: `Leveraged: ${snap.leveraged.name} (${snap.leveraged.package_id}, ${snap.leveraged.status})` }),
            el('p', { text: `${snap.leveraged.services.join(', ')}. ${snap.leveraged.why || ''}` }));
    }
    const table = el('table', { class: 'bm-flow-table' },
        el('caption', { text: 'Data flows' }),
        el('thead', {}, el('tr', {}, ...['ID', 'Path', 'Protocol / port', 'Authentication', 'Encryption', 'Data'].map((t) => el('th', { scope: 'col', text: t })))));
    const tbody = el('tbody');
    snap.flows.forEach((f) => {
        const path = [f.hops[0] && byId.get(f.hops[0][0]), ...f.hops.map(([, b]) => byId.get(b))]
            .filter(Boolean).map((n) => n.name).filter((name, i, arr) => arr.indexOf(name) === i).join(' → ');
        tbody.append(el('tr', {}, el('th', { scope: 'row', text: f.id }), el('td', { text: path || `(${f.unmatched_endpoints.join(', ')} not in this inventory)` }),
            el('td', { text: f.protocol || '' }), el('td', { text: f.auth || '' }), el('td', { text: f.encryption || '' }), el('td', { text: f.data || '' })));
    });
    table.append(tbody);
    parts.push(table);
    if (snap.fips_modules && snap.fips_modules.length) {
        const fips = el('table', { class: 'bm-flow-table' },
            el('caption', { text: 'Cryptographic modules' }),
            el('thead', {}, el('tr', {}, ...['Module', 'Validation', 'Role', 'Inherited'].map((t) => el('th', { scope: 'col', text: t })))));
        const fb = el('tbody');
        snap.fips_modules.forEach((m) => fb.append(el('tr', {}, el('th', { scope: 'row', text: m.module }),
            el('td', { text: m.validation || '' }), el('td', { text: m.role || '' }), el('td', { text: m.inherited ? 'yes' : 'no' }))));
        fips.append(fb);
        parts.push(fips);
    }
    host.replaceChildren(...parts);
}

if (ROOT) {
    fetch(ROOT.dataset.boundaryMap, { credentials: 'same-origin' })
        .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(init)
        .catch((err) => {
            ROOT.replaceChildren(el('p', { class: 'bm-error', text: `The live map could not be loaded (${err.message}).` }));
        });
}
