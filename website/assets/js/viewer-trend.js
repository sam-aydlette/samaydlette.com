// Vulnerability-trend chart for the compliance dashboard (viewer.html).
// Externalized from an inline <script> so the page works under a strict
// `script-src 'self'` CSP. Presentational only; the /.well-known/ JSON is the
// source of truth. Failures are swallowed — the chart is non-essential.
(async function () {
    try {
        const r = await fetch('/.well-known/vdr-trend.json');
        if (!r.ok) return;
        const t = await r.json();
        const pts = (t.points || []);
        if (!pts.length) return;
        const last = pts[pts.length - 1];
        document.getElementById('vuln-trend-headline').textContent =
            `Latest (${last.date}): ${last.open_cves} open CVEs · ${last.kev} KEV · ${last.blocking} blocking · ${last.risk_accepted} config findings risk-accepted · ${pts.length} scan(s) on record`;
        const W = 620, H = 200, m = { t: 12, r: 14, b: 28, l: 32 };
        const iw = W - m.l - m.r, ih = H - m.t - m.b;
        const series = [
            { k: 'open_cves', c: '#c0392b', label: 'open CVEs' },
            { k: 'risk_accepted', c: '#7f8c8d', label: 'risk-accepted config' }
        ];
        const maxY = Math.max(5, ...pts.flatMap(p => series.map(s => p[s.k] || 0)));
        const X = i => m.l + (pts.length < 2 ? iw / 2 : iw * i / (pts.length - 1));
        const Y = v => m.t + ih - ih * v / maxY;
        let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="vulnerability trend chart">`;
        svg += `<line x1="${m.l}" y1="${Y(0)}" x2="${W - m.r}" y2="${Y(0)}" stroke="#ccc"/>`;
        svg += `<text x="2" y="${Y(0) + 4}" font-size="10" fill="#888">0</text>`;
        svg += `<text x="2" y="${Y(maxY) + 4}" font-size="10" fill="#888">${maxY}</text>`;
        for (const s of series) {
            const pl = pts.map((p, i) => `${X(i)},${Y(p[s.k] || 0)}`).join(' ');
            svg += `<polyline points="${pl}" fill="none" stroke="${s.c}" stroke-width="2"/>`;
            pts.forEach((p, i) => { svg += `<circle cx="${X(i)}" cy="${Y(p[s.k] || 0)}" r="2.5" fill="${s.c}"/>`; });
        }
        svg += `<text x="${X(0)}" y="${H - 8}" font-size="10" fill="#888">${pts[0].date}</text>`;
        if (pts.length > 1) svg += `<text x="${W - m.r}" y="${H - 8}" font-size="10" fill="#888" text-anchor="end">${last.date}</text>`;
        svg += '</svg>';
        const leg = '<div style="font-size:0.85em;margin-top:4px;">' +
            series.map(s => `<span style="color:${s.c}">&#9632;</span> ${s.label}`).join(' &nbsp; ') + '</div>';
        document.getElementById('vuln-trend-chart').innerHTML = svg + leg;
    } catch (e) { /* dashboard is presentational; ignore */ }
})();
