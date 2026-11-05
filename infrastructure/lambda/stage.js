'use strict';

// FRC-CSX-VVK: the deploy invokes the emitter after apply and before it builds
// the SDR, with {stage: <commit SHA>}: the emitter re-validates the deployed
// system against the inventory the deploy is about to publish (staged under
// deploy-staging/<sha>/), and writes its signed signal next to it instead of
// over the published one. Anything but a 40-hex SHA is refused, so an event
// cannot name an arbitrary key.
const STAGE_PREFIX = 'deploy-staging/';
function stageKeys(event) {
    if (event == null || event.stage === undefined) return null;
    if (typeof event.stage !== 'string' || !/^[0-9a-f]{40}$/.test(event.stage)) {
        throw new Error('stage must be a 40-character lowercase hex commit SHA');
    }
    const dir = `${STAGE_PREFIX}${event.stage}/`;
    return { deploySignal: `${dir}ksi-signal.json`, runtimeSignal: `${dir}ksi-signal-runtime.json` };
}

module.exports = { stageKeys, STAGE_PREFIX };
