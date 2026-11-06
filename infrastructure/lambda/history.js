'use strict';

// =============================================================================
// RUNTIME RUN HISTORY (VER-RPT-PER)
// =============================================================================
// The runtime signal is overwritten on every run, so a period report built
// later could not see a run that was replaced before it. Each signal therefore
// carries a bounded history of run summaries (signal_id, emitted_at, how many
// validations ran, how many failed or were unassessed, the divergence status),
// inside the signed payload, so a reader that verifies today's signal can list
// every run in its period.
//
// The history is carried forward only from a previous signal whose signature
// verifies against this emitter's own key. Anything else (no previous signal,
// unreadable JSON, a bad or missing signature) restarts the history, and the
// first entry says why, so a gap is visible rather than silently papered over
// and nobody can launder a fabricated history through the signing key.
//
// Kept free of AWS-SDK imports so the tests run it under plain node.
// =============================================================================

const crypto = require('crypto');
const { canonicalize } = require('./canonical');

// Daily runs plus one per deploy: comfortably more than a year.
const RUN_HISTORY_LIMIT = 400;

function isInputViolation(v) {
    return v && v.category === 'input';
}

function runSummary(signal) {
    const validations = signal.validations || [];
    return {
        signal_id: signal.signal_id,
        emitted_at: signal.emitted_at,
        validations: validations.length,
        failed: validations.filter((v) => v.result === 'fail').length,
        unassessed: validations.filter((v) => (v.violations || []).some(isInputViolation)).length,
        divergence: (signal.divergence && signal.divergence.status) || 'unknown',
    };
}

// Verify a previously published runtime signal with the signer's recipe:
// canonical JSON with provenance.attestation removed, ECDSA P-256 / SHA-256,
// DER signature (what KMS returns).
function verifySignal(signal, publicKeyPem) {
    try {
        const sig = signal?.provenance?.attestation?.signature;
        if (!sig || !publicKeyPem) return false;
        const body = JSON.parse(JSON.stringify(signal));
        delete body.provenance.attestation;
        return crypto.verify(
            'sha256',
            Buffer.from(canonicalize(body), 'utf8'),
            { key: publicKeyPem, dsaEncoding: 'der' },
            Buffer.from(sig, 'base64'),
        );
    } catch (err) {
        return false;
    }
}

function wellFormed(entry) {
    return entry && typeof entry.signal_id === 'string' && typeof entry.emitted_at === 'string'
        && Number.isInteger(entry.validations) && Number.isInteger(entry.failed)
        && typeof entry.divergence === 'string';
}

// The history to publish with `current`. `previous` is the parsed previous
// signal (or null) and `previousVerified` whether its signature verified.
function nextRunHistory(previous, previousVerified, current, limit = RUN_HISTORY_LIMIT) {
    let carried = [];
    let reset = null;
    if (!previous) {
        reset = 'no previous runtime signal';
    } else if (!previousVerified) {
        reset = 'previous runtime signal did not verify';
    } else if (Array.isArray(previous.run_history)) {
        carried = previous.run_history.filter(wellFormed);
    } else {
        // The last signal before history existed: keep its own run.
        carried = [runSummary(previous)];
    }
    const seen = new Set();
    const entries = [];
    for (const e of [...carried, runSummary(current)]) {
        if (seen.has(e.signal_id)) continue;
        seen.add(e.signal_id);
        entries.push(e);
    }
    if (reset) entries[entries.length - 1].history_reset = reset;
    entries.sort((a, b) => a.emitted_at.localeCompare(b.emitted_at));
    return entries.slice(-limit);
}

module.exports = { RUN_HISTORY_LIMIT, runSummary, verifySignal, nextRunHistory };
