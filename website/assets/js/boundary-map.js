/**
 * Live boundary map — a static, interactive rendering of the RAMPART (TAP) export.
 *
 * The snapshot (/assets/boundary-map/boundary-map.json) is produced on the operator's
 * machine by tools/boundary-map/export.py: a local TAP instance collects the system,
 * lays the boundary out using docs/boundary/boundary-classification.json, and the
 * exporter reads back exactly what TAP drew. This module only redraws that snapshot at
 * TAP's positions; it computes no layout and fetches nothing but same-origin files.
 *
 * Interaction: pan/zoom, a health summary, click-to-trace data flows, a detail card for
 * any node or flow, and a text view of the same data for screen readers and for
 * readers who would rather scan a table than a graph.
 */

import cytoscape from '/assets/vendor/cytoscape/cytoscape.esm.min.js';

const ROOT = document.querySelector('[data-boundary-map]');

const FLOW_COLOR = { inTable: '#2563eb', notInTable: '#d97706' };
const FLAG_COLOR = '#dc2626';
const NOT_COLLECTED_KINDS = new Set(['not_collected']);
const TAG_LABELS = {
    Archetype: 'Archetype', DataClassification: 'Data classification', DataSensitivity: 'Data sensitivity',
    InternetReachable: 'Internet reachable', MissionCriticality: 'Mission criticality', Environment: 'Environment',
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
        card: cssVar('--bg-secondary', '#ffffff'),
        page: cssVar('--bg-primary', '#f8f9fa'),
    };
}

function stylesheet(p) {
    return [
        { selector: 'node.resource', style: {
            'shape': 'round-rectangle', 'width': 44, 'height': 44,
            // Icons are dark line art or AWS colour tiles drawn for a light ground, so the
            // tile stays white in both themes; only its border follows the theme.
            'background-color': '#ffffff', 'border-width': 1, 'border-color': p.border,
            'background-image': 'data(icon)', 'background-fit': 'contain', 'background-width': '70%', 'background-height': '70%',
            'label': 'data(label)', 'font-size': 10, 'color': p.text, 'text-valign': 'bottom', 'text-margin-y': 4,
            'text-wrap': 'wrap', 'text-max-width': 150, 'text-background-color': p.page, 'text-background-opacity': 0.85,
            'text-background-padding': 1,
        } },
        { selector: 'node.resource[!icon]', style: { 'background-image': 'none' } },
        // Resources and their labels draw above the zone and group outlines.
        { selector: 'node.resource', style: { 'z-index': 10 } },
        { selector: 'node.declared', style: { 'border-style': 'dotted', 'border-width': 2, 'background-opacity': 0.3 } },
        { selector: 'node.flagged', style: { 'border-color': FLAG_COLOR, 'border-width': 3, 'border-style': 'dashed' } },
        { selector: 'node.box', style: {
            'shape': 'rectangle', 'width': 'data(w)', 'height': 'data(h)', 'background-opacity': 0,
            'border-width': 1, 'border-style': 'dashed', 'border-color': p.border,
            'label': 'data(label)', 'font-size': 11, 'color': p.muted, 'text-valign': 'top', 'text-halign': 'center',
            'text-margin-y': -4, 'events': 'no', 'z-compound-depth': 'bottom', 'z-index': 0,
        } },
        { selector: 'node.zone', style: { 'border-width': 2, 'font-size': 13, 'font-weight': 'bold' } },
        { selector: 'node.zone.boundary', style: { 'border-color': FLAG_COLOR, 'color': FLAG_COLOR } },
        { selector: 'edge.grid', style: {
            'width': 1, 'line-color': p.border, 'target-arrow-color': p.border, 'target-arrow-shape': 'triangle',
            'arrow-scale': 0.6, 'curve-style': 'bezier', 'opacity': 0.7,
        } },
        { selector: 'edge.flow', style: {
            'width': 2.5, 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle',
            'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 14, 'font-weight': 'bold', 'color': 'data(color)',
            'text-background-color': p.page, 'text-background-opacity': 1, 'text-background-padding': 2,
        } },
        { selector: '.faded', style: { 'opacity': 0.1 } },
        { selector: 'node.resource:selected', style: { 'border-color': FLOW_COLOR.inTable, 'border-width': 3 } },
    ];
}

function elements(snap) {
    const els = [];
    snap.zones.forEach((z) => els.push({ group: 'nodes', classes: `box zone${z.boundary ? ' boundary' : ''}`, selectable: false, grabbable: false,
        data: { id: `zone:${z.key}`, label: z.label, w: z.box.w, h: z.box.h }, position: { x: z.box.x + z.box.w / 2, y: z.box.y + z.box.h / 2 } }));
    snap.groups.forEach((g) => els.push({ group: 'nodes', classes: 'box group', selectable: false, grabbable: false,
        data: { id: `group:${g.key}`, label: g.label, w: g.box.w, h: g.box.h }, position: { x: g.box.x + g.box.w / 2, y: g.box.y + g.box.h / 2 } }));
    snap.nodes.forEach((n) => {
        const classes = ['resource'];
        if (n.kind !== 'collected') classes.push('declared');
        if (n.flags && n.flags.length) classes.push('flagged');
        const label = n.flags && n.flags.length ? `${n.name}\n⚠ ${n.flags.join(', ')}` : n.name;
        els.push({ group: 'nodes', classes: classes.join(' '), grabbable: false,
            data: { id: n.id, label, icon: /^icons\/[a-z0-9-]+\.svg$/.test(n.icon || '') ? `/assets/boundary-map/${n.icon}` : undefined }, position: { x: n.x, y: n.y } });
    });
    snap.edges.forEach((e, i) => els.push({ group: 'edges', classes: 'grid', data: { id: `e${i}`, source: e.source, target: e.target } }));
    snap.flows.forEach((f) => f.hops.forEach(([a, b], i) => els.push({ group: 'edges', classes: 'flow',
        data: { id: `flow:${f.id}:${i}:${a}:${b}`, source: a, target: b, flow: f.id, label: i === 0 ? f.id : '',
            color: f.in_svg ? FLOW_COLOR.inTable : FLOW_COLOR.notInTable } })));
    return els;
}

// Only same-origin paths and https links from the snapshot become hrefs, so a tampered
// snapshot cannot smuggle in a javascript: or data: URL.
function safeHref(link) {
    if (typeof link !== 'string') return null;
    if (link.startsWith('/') && !link.startsWith('//')) return link;
    try { return new URL(link).protocol === 'https:' ? link : null; } catch { return null; }
}

function kv(dl, key, value) {
    if (value === undefined || value === null || value === '') return;
    dl.append(el('dt', { text: key }), el('dd', { text: String(value) }));
}

function init(snap) {
    const byId = new Map(snap.nodes.map((n) => [n.id, n]));
    const groupLabel = new Map(snap.groups.map((g) => [g.key, g.label]));
    const zoneLabel = new Map(snap.zones.map((z) => [z.key, z.label]));
    const flowsThrough = (id) => snap.flows.filter((f) => f.hops.some(([a, b]) => a === id || b === id));

    // --- Chrome: attribution, snapshot age, controls --------------------------------
    const collected = snap.collected_at;
    const header = el('div', { class: 'bm-header' },
        el('p', { class: 'bm-attribution' },
            'Mapped by ', el('strong', { text: 'RAMPART' }), ' on ',
            el('a', { href: snap.attribution.tap_url, rel: 'noopener', text: 'TAP — The Analogy Platform' }),
            `. Snapshot collected ${relativeAge(collected)} `, el('time', { datetime: collected, text: `(${collected.replace('+00:00', 'Z')})` }), '.'),
    );
    const canvas = el('div', { class: 'bm-canvas', role: 'img',
        'aria-label': 'Interactive authorization boundary map. A text view of the same components and data flows follows the map.' });
    const legend = el('aside', { class: 'bm-legend', 'aria-label': 'Boundary health and data flows' });
    const detail = el('aside', { class: 'bm-detail', 'aria-live': 'polite', hidden: true });
    const stage = el('div', { class: 'bm-stage' }, canvas, legend, detail);
    ROOT.replaceChildren(header, stage);

    const cy = cytoscape({
        container: canvas, elements: elements(snap), style: stylesheet(palette()), layout: { name: 'preset' },
        minZoom: 0.05, maxZoom: 3, boxSelectionEnabled: false, autoungrabify: true,
    });
    // Fit into the area beside the legend panel while it is open, so it never
    // covers the actors outside the boundary on the left.
    const fit = () => {
        const pad = 24;
        const left = body.hidden ? pad : legend.offsetLeft + legend.offsetWidth + pad;
        const bb = cy.nodes('.zone').boundingBox();
        const w = cy.width() - left - pad;
        const h = cy.height() - 2 * pad;
        if (w <= 0 || h <= 0 || !bb.w) { cy.fit(cy.nodes('.zone'), pad); return; }
        const z = Math.min(w / bb.w, h / bb.h);
        cy.zoom(z);
        cy.pan({ x: left - bb.x1 * z + (w - bb.w * z) / 2, y: pad - bb.y1 * z + (h - bb.h * z) / 2 });
    };

    // --- Legend: health + flows ------------------------------------------------------
    const h = snap.health;
    const health = [
        [h.unclassified, 'unclassified', 'Collected, but no classification rule places it'],
        [h.untagged, 'untagged', 'AWS resources carrying no classification tags'],
        [h.certificates_not_issued, 'certificate(s) not issued', 'TLS certificates expired or otherwise not usable'],
        [h.flows_with_unmatched_endpoint, 'flow(s) with an unmatched endpoint', 'A data flow whose endpoint matches no collected node'],
    ];
    const toggle = el('button', { type: 'button', class: 'bm-toggle', 'aria-expanded': 'true', text: 'Hide' });
    const body = el('div', { class: 'bm-legend-body' });
    legend.append(el('div', { class: 'bm-legend-head' }, el('h4', { text: 'Boundary health' }), toggle), body);
    const healthList = el('ul', { class: 'bm-health' });
    health.forEach(([count, label, title]) => healthList.append(
        el('li', { class: count ? 'bm-bad' : 'bm-ok', title }, `${count ? '⚠' : '✓'} ${count} ${label}`)));
    healthList.append(el('li', { class: 'bm-info', title: 'Declared in the classification; TAP has no collector for them' },
        `• ${h.declared_not_collected} declared, not collected`));
    body.append(healthList);
    if (snap.not_seen_in_latest_collection && snap.not_seen_in_latest_collection.length) {
        body.append(el('p', { class: 'bm-note', text:
            `Left off the map: ${snap.not_seen_in_latest_collection.map((g) => `${g.name} (${g.type})`).join(', ')} — no longer present in the latest collection.` }));
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
        button.setAttribute('aria-pressed', 'true');
        traced = flowId;
    };
    snap.flows.forEach((f) => {
        const b = el('button', { type: 'button', 'aria-pressed': 'false', onclick: () => { trace(f.id, b); showFlow(f); } },
            el('span', { class: `bm-flow-id ${f.in_svg ? 'bm-in-table' : 'bm-not-in-table'}`, text: f.id }),
            el('span', { text: f.label + (f.in_svg ? '' : ' (not in the diagram’s flow table)') }));
        flowList.append(el('li', {}, b));
    });
    body.append(flowList);
    const actions = el('p', { class: 'bm-actions' },
        el('button', { type: 'button', onclick: () => { clearTrace(); fit(); }, text: 'Reset view' }));
    body.append(actions);
    toggle.addEventListener('click', () => {
        const open = toggle.getAttribute('aria-expanded') === 'true';
        body.hidden = open;
        toggle.setAttribute('aria-expanded', String(!open));
        toggle.textContent = open ? 'Show' : 'Hide';
        fit();
    });
    if (window.matchMedia('(max-width: 768px)').matches) toggle.click();
    fit();

    // --- Detail card -----------------------------------------------------------------
    const openDetail = (title, fill) => {
        const dl = el('dl');
        fill(dl);
        const close = el('button', { type: 'button', class: 'bm-close', 'aria-label': 'Close details', text: '✕',
            onclick: () => { detail.hidden = true; } });
        detail.replaceChildren(el('div', { class: 'bm-detail-head' }, el('h4', { text: title }), close), dl);
        detail.hidden = false;
    };
    const showNode = (n) => openDetail(n.name, (dl) => {
        kv(dl, 'Type', n.kind === 'actor' ? 'Actor (declared)' : NOT_COLLECTED_KINDS.has(n.kind) ? 'Declared — not collected by TAP' : n.type.replace(/_/g, ' '));
        kv(dl, 'Group', groupLabel.get(n.group));
        kv(dl, 'Zone', zoneLabel.get(n.zone));
        if (n.flags) kv(dl, '⚠ Flags', n.flags.join(', '));
        kv(dl, 'Why', n.why);
        Object.entries(n.tags || {}).forEach(([k, v]) => kv(dl, TAG_LABELS[k] || k, v));
        kv(dl, 'Region', n.region);
        const flows = flowsThrough(n.id);
        if (flows.length) kv(dl, 'Data flows', flows.map((f) => `${f.id} — ${f.label}`).join('; '));
        const href = safeHref(n.link);
        if (href) {
            dl.append(el('dt', { text: 'Open' }), el('dd', {}, el('a', { href, rel: 'noopener', text: href.startsWith('/') ? href : `${new URL(href).host} ↗` })));
        }
    });
    const showFlow = (f) => openDetail(`Flow ${f.id}: ${f.label}`, (dl) => {
        kv(dl, 'Protocol / port', f.protocol);
        kv(dl, 'Authentication', f.auth);
        kv(dl, 'Encryption', f.encryption);
        kv(dl, 'Data', f.data);
        kv(dl, 'Note', f.note);
    });
    cy.on('tap', 'node.resource', (evt) => showNode(byId.get(evt.target.id())));
    cy.on('tap', 'edge.flow', (evt) => {
        const f = snap.flows.find((x) => x.id === evt.target.data('flow'));
        const button = [...flowList.querySelectorAll('button')].find((b) => b.firstChild.textContent === f.id);
        trace(f.id, button);
        showFlow(f);
    });
    cy.on('tap', (evt) => { if (evt.target === cy) { clearTrace(); detail.hidden = true; } });

    // --- Follow the site theme -------------------------------------------------------
    new MutationObserver(() => cy.style(stylesheet(palette())))
        .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    renderTextView(snap, groupLabel, zoneLabel, byId);
}

// The same data as a document: every component by zone and group, then the flow table.
function renderTextView(snap, groupLabel, zoneLabel, byId) {
    const host = document.querySelector('[data-boundary-map-text]');
    if (!host) return;
    const parts = [];
    snap.zones.forEach((z) => {
        parts.push(el('h5', { text: z.label }));
        const ul = el('ul');
        snap.groups.filter((g) => g.zone === z.key).forEach((g) => {
            const names = snap.nodes.filter((n) => n.group === g.key)
                .map((n) => n.name + (n.flags ? ` (⚠ ${n.flags.join(', ')})` : '') + (n.kind === 'not_collected' ? ' (not collected)' : ''));
            ul.append(el('li', {}, el('strong', { text: `${g.label}: ` }), names.join(', ')));
        });
        parts.push(ul);
    });
    const table = el('table', { class: 'bm-flow-table' },
        el('caption', { text: 'Data flows' }),
        el('thead', {}, el('tr', {}, ...['ID', 'Path', 'Protocol / port', 'Authentication', 'Encryption', 'Data'].map((t) => el('th', { scope: 'col', text: t })))));
    const tbody = el('tbody');
    snap.flows.forEach((f) => {
        const path = [f.hops[0] && byId.get(f.hops[0][0]), ...f.hops.map(([, b]) => byId.get(b))]
            .filter(Boolean).map((n) => n.name).filter((name, i, arr) => arr.indexOf(name) === i).join(' → ');
        tbody.append(el('tr', {}, el('th', { scope: 'row', text: f.id }), el('td', { text: path }),
            el('td', { text: f.protocol || '' }), el('td', { text: f.auth || '' }), el('td', { text: f.encryption || '' }), el('td', { text: f.data || '' })));
    });
    table.append(tbody);
    host.replaceChildren(...parts, table);
}

if (ROOT) {
    fetch(ROOT.dataset.boundaryMap, { credentials: 'same-origin' })
        .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(init)
        .catch((err) => {
            ROOT.replaceChildren(el('p', { class: 'bm-error', text: `The live map could not be loaded (${err.message}). The reference diagram below is unaffected.` }));
        });
}
