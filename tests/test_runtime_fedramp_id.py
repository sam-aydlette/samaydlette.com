"""The runtime KSI signal carries the FedRAMP ID (CDS-CSO-FID).

The runtime Lambda (infrastructure/lambda/index.js) builds its signal from the
published deploy signal, so it carries the ID that signal carries: one source,
data/cds/offering.json, through the inventory. The test runs buildRuntimeSignal
under plain node with the AWS SDK and OPA stubbed out; an inventory with no
components makes no AWS call.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO / "infrastructure" / "lambda" / "index.js"
FID = json.loads((REPO / "data" / "cds" / "offering.json").read_text())["fedramp_id"]

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")

HARNESS = r"""
const Module = require('module');
const load = Module._load;
Module._load = function (req, ...rest) {
  if (req.startsWith('@aws-sdk/') || req === '@open-policy-agent/opa-wasm') {
    return new Proxy({}, { get: () => function () {} });
  }
  return load.call(this, req, ...rest);
};
const { buildRuntimeSignal } = require(process.argv[1]);
buildRuntimeSignal(JSON.parse(process.argv[2]), null, null, null, null, 'v',
                   'arn:aws:lambda:us-east-2:000000000000:function:f')
  .then((s) => process.stdout.write(JSON.stringify(s)));
"""


def _runtime_signal(deploy_signal):
    out = subprocess.run(["node", "-e", HARNESS, str(INDEX), json.dumps(deploy_signal)],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_the_runtime_signal_carries_the_deploy_signals_fedramp_id():
    sig = _runtime_signal({"fedramp_id": FID, "components": []})
    assert sig["fedramp_id"] == FID and sig["emitter"] == "runtime"


def test_a_deploy_signal_without_an_id_gives_a_runtime_signal_without_one():
    assert "fedramp_id" not in _runtime_signal({"components": []})
