// =============================================================================
// LIVE TRUST DASHBOARD
// =============================================================================
// Fetches the deploy-time KSI signal, the runtime KSI signal, and the OSCAL
// SSP from /.well-known/ on page load and renders all three in human-readable
// form. Falls back gracefully when any artifact is unreachable (e.g., when
// viewed locally before the site is deployed).
//
// All consumers of this dashboard ultimately read the same JSON the page
// fetches; the dashboard is presentational. The JSON is the source of truth.
// =============================================================================

(function () {
    'use strict';

    var ARTIFACTS = {
        ksi: '/.well-known/ksi-signal.json',
        ksiBundle: '/.well-known/ksi-signal.bundle',
        ksiRuntime: '/.well-known/ksi-signal-runtime.json',
        oscal: '/.well-known/oscal-ssp.json',
        schema: '/.well-known/ksi-signal.schema.json',
    };

    function escape(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function el(id) { return document.getElementById(id); }

    function setText(id, text) {
        var node = el(id);
        if (node) node.textContent = text;
    }

    function setHTML(id, html) {
        var node = el(id);
        if (node) node.innerHTML = html;
    }

    function fetchJSON(url) {
        return fetch(url, { cache: 'no-cache' }).then(function (resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + url);
            return resp.json();
        });
    }

    // ---- Trust status overview -------------------------------------------

    function renderStatus(ksi, runtime, oscal) {
        // Card 1: signed?
        var signed = ksi && ksi.provenance && ksi.provenance.attestation;
        var signedCard = el('status-signed');
        if (signedCard) {
            signedCard.className = 'status-card ' + (signed ? 'is-good' : 'is-warn');
            signedCard.querySelector('.status-value').textContent = signed ? 'signed' : 'unsigned';
            var attUrl = signed && ksi.provenance.attestation.url;
            signedCard.querySelector('.status-detail').innerHTML = signed
                ? 'Sigstore bundle: <a href="' + escape(attUrl) + '">' + escape(attUrl.replace(/^https?:\/\//, '')) + '</a>'
                : 'No attestation in this signal.';
        }

        // Card 2: last deploy
        var deployCard = el('status-deploy');
        if (deployCard) {
            if (ksi && ksi.emitted_at) {
                deployCard.className = 'status-card is-good';
                deployCard.querySelector('.status-value').textContent = formatRelative(ksi.emitted_at);
                deployCard.querySelector('.status-detail').textContent = ksi.emitted_at;
            } else {
                deployCard.className = 'status-card is-bad';
                deployCard.querySelector('.status-value').textContent = 'unknown';
                deployCard.querySelector('.status-detail').textContent = 'deploy-time signal not reachable';
            }
        }

        // Card 3: last runtime check
        var runtimeCard = el('status-runtime');
        if (runtimeCard) {
            if (runtime && runtime.emitted_at) {
                runtimeCard.className = 'status-card is-good';
                runtimeCard.querySelector('.status-value').textContent = formatRelative(runtime.emitted_at);
                runtimeCard.querySelector('.status-detail').textContent = runtime.emitted_at;
            } else {
                runtimeCard.className = 'status-card is-warn';
                runtimeCard.querySelector('.status-value').textContent = '—';
                runtimeCard.querySelector('.status-detail').textContent = 'runtime signal not yet emitted';
            }
        }

        // Card 4: drift between deploy and runtime
        var driftCard = el('status-drift');
        if (driftCard) {
            var verdict = divergenceVerdict(ksi, runtime);
            driftCard.className = 'status-card ' + verdict.cls;
            driftCard.querySelector('.status-value').textContent = verdict.value;
            driftCard.querySelector('.status-detail').textContent = verdict.detail;
        }
    }

    // The runtime emitter computes the deploy-vs-runtime comparison itself and
    // records it in the SIGNED signal, so prefer that verdict: it is the one
    // the deploy gate acts on, it is tamper-evident, and it separates a
    // resource that regressed from an evaluator that could not look. Recomputing
    // it here from raw validation results cannot make that distinction, because
    // a validation carrying only a resource_read_error is a `fail` like any
    // other -- which is how a missing IAM grant reads as infrastructure drift.
    //
    // compareValidations() below stays as the fallback for signals emitted
    // before the divergence block existed.
    function divergenceVerdict(ksi, runtime) {
        var div = runtime && runtime.divergence;

        if (div && div.status) {
            var regressions = div.regressions || [];
            var unassessed = div.unassessed || [];
            if (div.status === 'diverged') {
                return {
                    cls: 'is-bad',
                    value: 'drift detected',
                    detail: regressions.length + ' KSI(s) passing at deploy time are failing at runtime: ' +
                        regressions.slice(0, 3).map(function (r) { return r.ksi_id; }).join(', ') +
                        (regressions.length > 3 ? ', …' : ''),
                };
            }
            if (div.status === 'degraded') {
                return {
                    cls: 'is-warn',
                    value: 'partly unassessed',
                    detail: 'No drift found, but the runtime evaluator could not reach a verdict on ' +
                        unassessed.length + ' KSI(s). This is an evaluator fault, not drift.',
                };
            }
            if (div.status === 'converged') {
                return {
                    cls: 'is-good',
                    value: 'in sync',
                    detail: 'Runtime evaluation agrees with the published deploy-time verdict across ' +
                        (div.ksis_compared || 0) + ' KSIs.',
                };
            }
        }

        if (ksi && runtime) {
            var d = compareValidations(ksi, runtime);
            return {
                cls: d.matches ? 'is-good' : 'is-bad',
                value: d.matches ? 'in sync' : 'drift detected',
                detail: d.summary + ' (compared in-page; this signal predates the signed divergence verdict)',
            };
        }

        return {
            cls: '',
            value: 'unavailable',
            detail: ksi ? 'runtime signal needed to compare' : 'deploy-time signal needed to compare',
        };
    }

    function formatRelative(iso) {
        var t = Date.parse(iso);
        if (isNaN(t)) return '—';
        var diff = Math.floor((Date.now() - t) / 1000);
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    function compareValidations(ksi, runtime) {
        // Compare the set of validation results that overlap. The deploy gate
        // and runtime emitter evaluate different rule sets (deploy covers
        // everything, runtime covers a subset of cloud config) so we compare
        // by component_ref + result.
        var deployByComp = {};
        (ksi.validations || []).forEach(function (v) {
            (v.component_refs || []).forEach(function (cid) {
                deployByComp[cid] = v.result;
            });
        });
        var runtimeByComp = {};
        (runtime.validations || []).forEach(function (v) {
            (v.component_refs || []).forEach(function (cid) {
                runtimeByComp[cid] = v.result;
            });
        });
        var matches = true;
        var divergent = [];
        Object.keys(runtimeByComp).forEach(function (cid) {
            if (deployByComp[cid] && deployByComp[cid] !== runtimeByComp[cid]) {
                matches = false;
                divergent.push(cid);
            }
        });
        return {
            matches: matches,
            summary: matches
                ? 'deploy and runtime agree on overlapping validations'
                : 'divergent: ' + divergent.slice(0, 3).join(', '),
        };
    }

    // ---- KSI signal panel -------------------------------------------------

    function renderKsiPanel(ksi) {
        if (!ksi) return;

        // Metadata
        var meta = el('ksi-meta');
        if (meta) {
            var att = ksi.provenance && ksi.provenance.attestation;
            var attHtml = att
                ? '<a href="' + escape(att.url) + '">' + escape(att.format) + '</a>'
                : '(none)';
            meta.innerHTML = '' +
                row('signal_id', ksi.signal_id) +
                row('emitted_at', ksi.emitted_at) +
                row('emitter', ksi.emitter) +
                row('csp', ksi.csp) +
                row('system_id', ksi.system_id) +
                row('signal_version', ksi.signal_version) +
                row('source.commit', ksi.provenance && ksi.provenance.source && ksi.provenance.source.commit) +
                row('builder', ksi.provenance && ksi.provenance.builder && ksi.provenance.builder.id) +
                rowRaw('attestation', attHtml);
        }

        // Component summary tags
        var byType = {};
        (ksi.components || []).forEach(function (c) {
            byType[c.type] = (byType[c.type] || 0) + 1;
        });
        var summary = el('ksi-component-summary');
        if (summary) {
            summary.innerHTML = Object.keys(byType).sort().map(function (t) {
                return '<span class="component-tag">' + escape(t) +
                    '<span class="count">' + byType[t] + '</span></span>';
            }).join('');
        }

        // Components grouped by type
        var compHost = el('ksi-components');
        if (compHost) {
            var typeOrder = ['object_store', 'cdn_distribution', 'function',
                             'compute_instance', 'container_image',
                             'npm_package', 'html_artifact', 'hbom_ref'];
            var html = '';
            typeOrder.forEach(function (type) {
                var comps = (ksi.components || []).filter(function (c) { return c.type === type; });
                if (comps.length === 0) return;
                var openAttr = ['object_store', 'cdn_distribution', 'function'].indexOf(type) >= 0 ? ' open' : '';
                html += '<details class="component-section"' + openAttr + '>';
                html += '<summary>' + escape(type) + ' (' + comps.length + ')</summary>';
                html += '<div class="viewer-table-wrap"><table class="viewer-table"><thead><tr>' +
                    '<th>component_id</th><th>identifier</th></tr></thead><tbody>';
                comps.forEach(function (c) {
                    var gid = c.global_id || {};
                    var id = c.native_id || gid.purl || gid.image_digest || gid.sha256 || gid.hbom_ref || '';
                    html += '<tr><td class="wrap">' + escape(c.component_id) + '</td>' +
                            '<td class="wrap">' + escape(id) + '</td></tr>';
                });
                html += '</tbody></table></div></details>';
            });
            compHost.innerHTML = html || '<p class="viewer-loading">No components in this signal.</p>';
        }

        // Validations table
        var valHost = el('ksi-validations');
        if (valHost) {
            var vals = ksi.validations || [];
            if (vals.length === 0) {
                valHost.innerHTML = '<p class="viewer-loading">No validations in this signal.</p>';
            } else {
                var html2 = '<div class="viewer-table-wrap"><table class="viewer-table"><thead><tr>' +
                    '<th>id</th><th>policy</th><th>result</th><th>component_refs</th><th>violations</th>' +
                    '</tr></thead><tbody>';
                vals.forEach(function (v) {
                    var refs = (v.component_refs || []).join(', ');
                    var policy = v.policy ? (v.policy.id + '@' + v.policy.version) : '';
                    var violCount = (v.violations || []).length;
                    var violTxt = violCount === 0 ? '—' : violCount + ' (' +
                        (v.violations || []).slice(0, 2).map(function (x) { return x.type; }).join(', ') +
                        (violCount > 2 ? '...' : '') + ')';
                    html2 += '<tr><td>' + escape(v.validation_id) + '</td>' +
                            '<td class="wrap">' + escape(policy) + '</td>' +
                            '<td><span class="badge badge-' + escape(v.result) + '">' + escape(v.result) + '</span></td>' +
                            '<td class="wrap">' + escape(refs) + '</td>' +
                            '<td class="wrap">' + escape(violTxt) + '</td></tr>';
                });
                html2 += '</tbody></table></div>';
                valHost.innerHTML = html2;
            }
        }
    }

    function row(label, value) {
        if (value == null || value === '') return '';
        return '<dt>' + escape(label) + '</dt><dd>' + escape(String(value)) + '</dd>';
    }

    // Row variant for cases where the value is pre-escaped HTML (e.g., a
    // link). Caller is responsible for escaping any user-controlled text
    // inside `html`.
    function rowRaw(label, html) {
        if (html == null || html === '') return '';
        return '<dt>' + escape(label) + '</dt><dd>' + html + '</dd>';
    }

    // ---- Deploy <-> runtime divergence panel ------------------------------

    function divergenceRows(entries) {
        return entries.map(function (e) {
            var rules = (e.violation_ids || []).map(escape).join(', ') || '—';
            return '<tr>' +
                '<td><code>' + escape(e.ksi_id) + '</code></td>' +
                '<td><span class="badge badge-' + escape(e.deploy_status) + '">' +
                    escape(e.deploy_status) + '</span></td>' +
                '<td><span class="badge badge-' + escape(e.runtime_status) + '">' +
                    escape(e.runtime_status) + '</span></td>' +
                '<td class="wrap">' + rules + '</td>' +
                '</tr>';
        }).join('');
    }

    function divergenceTable(caption, entries) {
        return '<h3>' + escape(caption) + '</h3>' +
            '<div class="viewer-table-wrap"><table class="viewer-table">' +
            '<thead><tr><th>KSI</th><th>deploy</th><th>runtime</th><th>rules</th></tr></thead>' +
            '<tbody>' + divergenceRows(entries) + '</tbody></table></div>';
    }

    function renderDivergencePanel(runtime) {
        var body = el('divergence-body');
        var metaEl = el('divergence-meta');
        if (!body) return;

        if (!runtime) {
            body.innerHTML = '<p class="viewer-note">Runtime signal not reachable, so no comparison is possible.</p>';
            if (metaEl) metaEl.innerHTML = '';
            return;
        }

        var div = runtime.divergence;
        if (!div || !div.status) {
            body.innerHTML = '<p class="viewer-note">This runtime signal carries no divergence verdict. ' +
                'The emitter that produces it has not run since the check was added; the ' +
                '<strong>Drift</strong> card above falls back to comparing validations in-page.</p>';
            if (metaEl) metaEl.innerHTML = '';
            return;
        }

        var against = div.compared_against || {};
        if (metaEl) {
            metaEl.innerHTML =
                row('status', div.status) +
                row('KSIs compared', div.ksis_compared) +
                row('against deploy signal', against.signal_id) +
                row('at commit', against.commit) +
                row('deploy signal emitted', against.emitted_at);
        }

        var regressions = div.regressions || [];
        var unassessed = div.unassessed || [];
        var html = '';

        if (div.status === 'converged') {
            html += '<p class="component-summary">The daily runtime evaluation of the live account agrees ' +
                'with the verdict published at deploy time. No KSI that passed the deploy gate is failing ' +
                'against the running system.</p>';
        }

        if (regressions.length) {
            html += '<p class="component-summary"><strong>These KSIs passed the deploy gate and are failing ' +
                'against the live account.</strong> That is drift in the deployed system, and it blocks the ' +
                'next deploy until it is investigated or explicitly overridden.</p>';
            html += divergenceTable('Regressions', regressions);
        }

        if (unassessed.length) {
            html += '<p class="component-summary">These KSIs could not be evaluated at all &mdash; the ' +
                'runtime evaluator failed to read the resource, typically a missing permission. ' +
                '<strong>This is a fault in the observer, not evidence that anything drifted</strong>, so it ' +
                'is reported separately and does not block deploys. It does mean these controls are ' +
                'currently unverified at runtime.</p>';
            html += divergenceTable('Unassessed', unassessed);
        }

        if (div.unattributed_failures) {
            html += '<p class="viewer-note">' + escape(String(div.unattributed_failures)) +
                ' failing violation(s) carried no KSI mapping, so they are attributed to no indicator above.</p>';
        }

        body.innerHTML = html;
    }

    // ---- OSCAL SSP panel --------------------------------------------------

    var oscalReqs = [];
    var oscalFilters = { status: '', origination: '', search: '' };

    function renderOscalPanel(oscal) {
        if (!oscal || !oscal['system-security-plan']) return;
        var ssp = oscal['system-security-plan'];

        var meta = el('oscal-meta');
        if (meta) {
            var sysChars = ssp['system-characteristics'] || {};
            var sysName = sysChars['system-name'] || '';
            var ksiSrc = '';
            (ssp.metadata && ssp.metadata.props || []).forEach(function (p) {
                if (p.name === 'ksi-signal-source') ksiSrc = p.value;
            });
            meta.innerHTML = '' +
                row('uuid', ssp.uuid) +
                row('oscal-version', ssp.metadata && ssp.metadata['oscal-version']) +
                row('last-modified', ssp.metadata && ssp.metadata['last-modified']) +
                row('system-name', sysName) +
                row('sensitivity', sysChars['security-sensitivity-level']) +
                row('ksi-signal-source', ksiSrc);
        }

        oscalReqs = (ssp['control-implementation'] && ssp['control-implementation']['implemented-requirements']) || [];

        // Status and origination distribution; also drives the filter dropdowns.
        var statusCounts = {}, originCounts = {};
        oscalReqs.forEach(function (r) {
            (r.props || []).forEach(function (p) {
                if (p.name === 'implementation-status') statusCounts[p.value] = (statusCounts[p.value] || 0) + 1;
                if (p.name === 'control-origination') originCounts[p.value] = (originCounts[p.value] || 0) + 1;
            });
        });

        var summary = el('oscal-summary');
        if (summary) {
            var bits = [];
            Object.keys(statusCounts).sort().forEach(function (k) {
                bits.push('<span class="component-tag">' + escape(k) +
                    '<span class="count">' + statusCounts[k] + '</span></span>');
            });
            summary.innerHTML = bits.join('');
        }

        // Populate filter dropdowns from values actually present in the data.
        // This avoids listing OSCAL-valid-but-unused values like "planned"
        // when no control is in that state.
        populateFilter('filter-status', statusCounts);
        populateFilter('filter-origination', originCounts);

        renderOscalTable();
    }

    function populateFilter(selectId, counts) {
        var sel = el(selectId);
        if (!sel) return;
        var current = sel.value;
        var values = Object.keys(counts).sort();
        var html = '<option value="">all</option>';
        values.forEach(function (v) {
            html += '<option value="' + escape(v) + '">' + escape(v) +
                ' (' + counts[v] + ')</option>';
        });
        sel.innerHTML = html;
        // Preserve selection if it still applies after the data refreshed.
        if (current && counts[current]) sel.value = current;
    }

    function renderOscalTable() {
        var host = el('oscal-controls');
        if (!host) return;

        // Don't render the full 263-row table by default; the SSP is large
        // enough to overwhelm a casual reader. Require an active filter
        // (status, origination, or search text) before showing rows.
        var anyFilter = !!(oscalFilters.status || oscalFilters.origination || oscalFilters.search);
        var summaryEl = el('oscal-filter-summary');

        if (!anyFilter) {
            host.innerHTML = '<p class="viewer-loading">Select a status or origination filter, or type a search term, to list control requirements. ' +
                oscalReqs.length + ' total controls in this SSP.</p>';
            if (summaryEl) summaryEl.textContent = '';
            return;
        }

        var filtered = oscalReqs.filter(function (r) {
            var status = '', origin = '';
            (r.props || []).forEach(function (p) {
                if (p.name === 'implementation-status') status = p.value;
                if (p.name === 'control-origination') origin = p.value;
            });
            if (oscalFilters.status && status !== oscalFilters.status) return false;
            if (oscalFilters.origination && origin !== oscalFilters.origination) return false;
            if (oscalFilters.search) {
                var q = oscalFilters.search.toLowerCase();
                var stmt = ((r.statements || [])[0] || {}).remarks || '';
                if (r['control-id'].toLowerCase().indexOf(q) < 0 &&
                    stmt.toLowerCase().indexOf(q) < 0) return false;
            }
            return true;
        });

        if (summaryEl) {
            summaryEl.textContent = 'Showing ' + filtered.length + ' of ' + oscalReqs.length + ' control requirements';
        }

        if (filtered.length === 0) {
            host.innerHTML = '<p class="viewer-loading">No controls match the current filters.</p>';
            return;
        }

        var html = '<div class="viewer-table-wrap"><table class="viewer-table"><thead><tr>' +
            '<th>control</th><th>status</th><th>origin</th><th>statement</th>' +
            '</tr></thead><tbody>';
        filtered.forEach(function (r) {
            var status = '', origin = '';
            (r.props || []).forEach(function (p) {
                if (p.name === 'implementation-status') status = p.value;
                if (p.name === 'control-origination') origin = p.value;
            });
            var stmt = (((r.statements || [])[0] || {}).remarks || '').split('\n\n')[0];
            // Truncate the statement to a reasonable preview length.
            if (stmt.length > 280) stmt = stmt.slice(0, 280) + '…';
            html += '<tr>' +
                '<td>' + escape(r['control-id']) + '</td>' +
                '<td><span class="badge badge-' + escape(status) + '">' + escape(status) + '</span></td>' +
                '<td><span class="origin-badge">' + escape(origin) + '</span></td>' +
                '<td class="detail">' + escape(stmt) + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div>';
        host.innerHTML = html;
    }

    // ---- Initial load -----------------------------------------------------

    function attachFilters() {
        var status = el('filter-status');
        var origin = el('filter-origination');
        var search = el('filter-search');
        if (status) status.addEventListener('change', function () {
            oscalFilters.status = status.value; renderOscalTable();
        });
        if (origin) origin.addEventListener('change', function () {
            oscalFilters.origination = origin.value; renderOscalTable();
        });
        if (search) search.addEventListener('input', function () {
            oscalFilters.search = search.value; renderOscalTable();
        });
    }

    function showError(panelId, message) {
        var host = el(panelId);
        if (host) host.innerHTML = '<p class="viewer-error">' + escape(message) + '</p>';
    }

    document.addEventListener('DOMContentLoaded', function () {
        attachFilters();

        var ksiP = fetchJSON(ARTIFACTS.ksi).catch(function (err) {
            showError('ksi-meta', 'Could not fetch ' + ARTIFACTS.ksi + ' (' + err.message + '). The dashboard renders only when published.');
            return null;
        });
        var runtimeP = fetchJSON(ARTIFACTS.ksiRuntime).catch(function () { return null; });
        var oscalP = fetchJSON(ARTIFACTS.oscal).catch(function (err) {
            showError('oscal-meta', 'Could not fetch ' + ARTIFACTS.oscal + ' (' + err.message + ').');
            return null;
        });

        Promise.all([ksiP, runtimeP, oscalP]).then(function (results) {
            var ksi = results[0], runtime = results[1], oscal = results[2];
            renderStatus(ksi, runtime, oscal);
            renderDivergencePanel(runtime);
            if (ksi) renderKsiPanel(ksi);
            if (oscal) renderOscalPanel(oscal);
        });
    });
})();
