// Live compliance line for the homepage hero.
//
// Fails closed by construction rather than by error handling. index.html ships the
// link and no claim; this only ever ADDS facts to it. If the fetch fails, the signal
// is stale, or the fields are missing, nothing is written and the shipped line
// stands as an honest link with no numbers. There is no green default to get wrong.
//
// Reads the RUNTIME signal only. Both facts then come from one document and stay
// internally consistent: pairing the deploy-time control count with the runtime
// timestamp would imply a re-verification that did not happen.
//
// `fetchJSON` and a relative-time formatter also exist in viewer.js, which is not an
// ES module and cannot be imported from. The few lines here are deliberately
// duplicated rather than refactoring that file.

const SIGNAL = '/.well-known/ksi-signal-runtime.json';

// The runtime re-validation is a daily EventBridge schedule. Two missed runs means
// something is wedged, and a stale figure is worse than no figure.
const MAX_AGE_MS = 48 * 60 * 60 * 1000;

export class ComplianceStatus {
  constructor() {
    // Every page loads main.js; only the homepage carries the hook.
    this.el = document.querySelector('[data-compliance-status]');
    if (this.el) this.load();
  }

  async load() {
    try {
      const resp = await fetch(SIGNAL, { cache: 'no-cache' });
      if (!resp.ok) return;
      const summary = this.summarise(await resp.json());
      if (summary) this.el.textContent = summary;
    } catch {
      // Unreachable, blocked, or unparseable: leave the shipped line alone.
    }
  }

  // Returns the text to add, or null to stay silent. Null on anything unexpected.
  summarise(signal) {
    const d = signal && signal.divergence;
    if (!d || !Array.isArray(d.regressions) || !Array.isArray(d.unassessed)) return null;

    const total = d.ksis_compared;
    if (!Number.isInteger(total) || total <= 0) return null;

    const passing = total - d.regressions.length - d.unassessed.length;
    if (passing < 0 || passing > total) return null;

    const age = Date.now() - Date.parse(signal.emitted_at);
    if (!Number.isFinite(age) || age < 0 || age > MAX_AGE_MS) return null;

    // The real ratio, whatever it is. A front page that cannot show a dip is not
    // evidence of anything.
    return `${passing}/${total} controls, re-verified ${relative(age)} → `;
  }
}

function relative(ms) {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 3600) return `${Math.max(1, Math.floor(seconds / 60))}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
