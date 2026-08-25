"""The published coverage figure must track what the runtime Lambda actually checks.

`inject-figures.py` derives runtime coverage statically, because the runtime signal
is emitted by the AWS schedule and does not exist at build time. That means the
figure encodes a claim about `infrastructure/lambda/index.js` — which component
types it re-validates — in a second place.

A duplicated claim that nothing checks is a claim that goes stale silently, and
this one would go stale in the worst direction: adding a resource type to the
Lambda would make the published figure understate the coverage, while removing one
would make it overstate. So these tests read the Lambda source and assert the two
agree.
"""

import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAMBDA = REPO / "infrastructure" / "lambda" / "index.js"
# A committed, shape-only copy of the inventory: the real ksi-signal.json is a
# build product that does not exist when the unit tests run in CI, so pinning the
# derivation to it meant this file's last test never actually executed there.
INVENTORY_SHAPE = REPO / "tests" / "fixtures" / "clean" / "inventory-shape.json"


def figures_module():
    spec = importlib.util.spec_from_file_location(
        "inject_figures", REPO / "scripts" / "inject-figures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lambda_types():
    """(fully enumerated types, singleton types) as the Lambda actually uses them."""
    src = LAMBDA.read_text()
    enumerated = set(re.findall(r"components\.filter\(\(c\) => c\.type === '([a-z_]+)'\)", src))
    singleton = set(re.findall(r"findComponent\(components,\s*'([a-z_]+)'", src))
    return enumerated, singleton


def test_enumerated_types_match_the_lambda():
    mod = figures_module()
    enumerated, _ = lambda_types()
    assert enumerated, "could not parse any component.filter type from the Lambda"
    assert mod.RUNTIME_ENUMERATED_TYPES == enumerated, (
        "inject-figures.py and the runtime Lambda disagree about which component "
        "types are re-validated in full. Update RUNTIME_ENUMERATED_TYPES."
    )


def test_singleton_types_match_the_lambda():
    mod = figures_module()
    _, singleton = lambda_types()
    assert singleton, "could not parse any findComponent type from the Lambda"
    assert mod.RUNTIME_SINGLETON_TYPES == singleton, (
        "inject-figures.py and the runtime Lambda disagree about which component "
        "types are re-validated as a single instance. Update RUNTIME_SINGLETON_TYPES."
    )


def test_layers_partition_the_inventory():
    """Every component lands in exactly one layer; the denominators must add up."""
    mod = figures_module()
    comps = [{"type": t} for t in
             ["npm_package"] * 5 + ["pypi_package"] * 3 + ["html_artifact"] * 4
             + ["object_store"] * 2 + ["secrets_manager"] + ["cdn_distribution"]
             + ["kms_key"] * 3]
    lay = mod._coverage_layers(comps)
    assert lay["total"] == len(comps)
    assert (lay["deps"] + lay["build_deps"] + lay["content"] + lay["cloud"]
            == lay["total"])
    assert lay["cloud"] == 7           # 2 buckets + 1 secret + 1 cdn + 3 kms
    assert lay["runtime_covered"] == 4  # both buckets, the secret, one cdn
    assert lay["uncovered_types"] == ["kms_key"]


def test_a_new_uncovered_type_lowers_coverage():
    """The figure must fall when the system grows into types nothing re-checks.

    This is the property the whole measure exists for: coverage decaying silently
    as the inventory grows is invisible to the inner loop by construction.
    """
    mod = figures_module()
    before = mod._coverage_layers([{"type": "object_store"}, {"type": "kms_key"}])
    after = mod._coverage_layers([{"type": "object_store"}, {"type": "kms_key"},
                                  {"type": "iam_role"}, {"type": "log_group"}])
    r = lambda l: l["runtime_covered"] / l["cloud"]
    assert r(after) < r(before), "growth into unchecked types must lower the ratio"


def test_derivation_agrees_with_a_realistic_inventory():
    """The partition must hold over the real mix of component types, not just the
    handful the synthetic case above uses.

    `deps` deliberately counts only what SHIPS - build-time packages are
    inventoried but excluded, so they are their own term. Asserting
    deps + content + cloud == total (without build_deps) is the mistake this test
    used to encode, and it went unnoticed because the skipif meant it only ever
    ran on a dev machine that happened to have a build product lying around.
    """
    mod = figures_module()
    lay = mod._coverage_layers(json.loads(INVENTORY_SHAPE.read_text())["components"])
    assert lay["runtime_covered"] > 0
    assert lay["cloud"] >= lay["runtime_covered"]
    assert (lay["deps"] + lay["build_deps"] + lay["content"] + lay["cloud"]
            == lay["total"])
    # build-time packages are a real and large slice of this inventory; if they
    # ever stop being excluded, the published deps figure moves without the thing
    # it measures having changed.
    assert lay["build_deps"] > 0
