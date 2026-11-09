"""The AWS account ID is kept out of everything published (scripts/_redact.py).

The inventory builder writes ACCOUNT in place of the account ID; every consumer
that compares the published inventory with what AWS or Terraform reports
redacts its side the same way; the runtime Lambda fills its own account back in
where it needs a callable ARN; and a publication gate fails the deploy or the
nightly on any twelve-digit number left in a file about to be published.

Account numbers here are the AWS documentation example; this repo is public.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "redaction"
sys.path.insert(0, str(REPO / "scripts"))
import _gates  # noqa: E402
import _redact  # noqa: E402

ACCOUNT = "123456789012"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bks = _load("bks_redact", REPO / "scripts" / "build-ksi-signal.py")
gate = _load("gate_redact", REPO / "scripts" / "check-published-redaction.py")
rc = _load("rc_redact", REPO / "scripts" / "reconcile.py")
bbg = _load("bbg_redact", REPO / "scripts" / "build-boundary-graph.py")
vdr = _load("vdr_redact", REPO / "scripts" / "build-vdr-report.py")
corr = _load("corr_redact", REPO / "tools" / "boundary-map" / "corroborate.py")


# --- the rule ---------------------------------------------------------------

def test_redact_replaces_the_account_in_arns_bare_values_and_keys():
    doc = {"arn": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app",
           "owner": ACCOUNT,
           "policy": json.dumps({"Condition": {"AWS:SourceOwner": ACCOUNT}}),
           ACCOUNT: ["arn:aws:iam::" + ACCOUNT + ":role/x"]}
    out = _redact.redact(doc)
    assert out["arn"] == "arn:aws:lambda:us-east-2:ACCOUNT:function:app"
    assert out["owner"] == "ACCOUNT"
    assert ACCOUNT not in json.dumps(out)
    assert out["ACCOUNT"] == ["arn:aws:iam::ACCOUNT:role/x"]


def test_redact_leaves_other_numbers_and_hashes_alone():
    keep = {"ms": "1730000000000", "eleven": "12345678901", "sha": "a" + "1" * 12 + "b",
            "hex": "0123456789ab", "n": 123456789012}
    assert _redact.redact(keep) == keep
    assert _redact.find(json.dumps(keep)) == ["123456789012"]  # a numeric one still fails the gate


# --- the inventory builder ------------------------------------------------------

def test_the_published_inventory_carries_no_account_id(tmp_path, monkeypatch):
    """Drive the builder's main() over a Terraform state full of account IDs and
    read what it would publish."""
    (tmp_path / "data").mkdir()
    shutil.copy(REPO / "data" / "system-profile.json", tmp_path / "data" / "system-profile.json")
    infra = tmp_path / "infrastructure"
    infra.mkdir()
    arn = f"arn:aws:sns:us-east-2:{ACCOUNT}:alarms"
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_lambda_function", "name": "app", "address": "aws_lambda_function.app",
         "values": {"arn": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app", "function_name": "app",
                    "id": "app"}},
        {"type": "aws_acm_certificate", "name": "site", "address": "aws_acm_certificate.site",
         "values": {"arn": f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/x",
                    "id": f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/x"}},
        {"type": "aws_iam_role", "name": "app", "address": "aws_iam_role.app",
         "values": {"arn": f"arn:aws:iam::{ACCOUNT}:role/app", "name": "app",
                    "assume_role_policy": json.dumps({"Statement": [{"Principal": {"AWS": ACCOUNT}}]})}},
        {"type": "aws_sns_topic", "name": "alarms", "address": "aws_sns_topic.alarms",
         "values": {"arn": arn, "id": arn}},
        {"type": "aws_sns_topic_policy", "name": "alarms", "address": "aws_sns_topic_policy.alarms",
         "values": {"arn": arn, "owner": ACCOUNT,
                    "policy": json.dumps({"Condition": {"StringEquals": {"AWS:SourceOwner": ACCOUNT}}})}},
    ]}}}
    monkeypatch.setattr(bks, "run_terraform", lambda args: state if args[0] == "show" else {})
    monkeypatch.setattr(bks, "build_live_log_groups", lambda _existing: [])
    monkeypatch.setenv("BOOTSTRAP_STATE_JSON", str(tmp_path / "absent.json"))
    monkeypatch.chdir(infra)
    bks.main()
    text = (infra / "ksi-signal.json").read_text()
    assert _redact.find(text) == []
    comps = {c["component_id"]: c for c in json.loads(text)["components"]}
    assert any(c.get("native_id") == "arn:aws:lambda:us-east-2:ACCOUNT:function:app" for c in comps.values())
    # The redacted inventory passes the publication gate.
    assert gate.main(["--root", str(infra)]) == 0


# --- the publication gate -------------------------------------------------------

def test_gate_fails_the_known_bad_fixture_without_printing_the_number(capsys):
    assert gate.main(["--root", str(FIXTURES / "bad")]) == 1
    err = capsys.readouterr().err
    assert "ksi-signal.json: 2 account ID(s)" in err
    assert ACCOUNT not in err


def test_gate_passes_the_known_good_fixture():
    assert gate.main(["--root", str(FIXTURES / "good")]) == 0


def test_gate_scans_the_markdown_rendering_too(tmp_path):
    (tmp_path / "vdr-report.json").write_text("{}")
    (tmp_path / "vdr-report.md").write_text(f"owner {ACCOUNT}\n")
    assert gate.main(["--root", str(tmp_path)]) == 1


def test_gate_fails_closed_when_there_is_nothing_to_scan(tmp_path):
    assert gate.main(["--root", str(tmp_path)]) == 2
    assert gate.main([str(tmp_path / "missing.json")]) == 2


def test_gate_explicit_files_mode(tmp_path):
    good = tmp_path / "a.json"
    good.write_text('{"x": "ACCOUNT"}')
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"x": ACCOUNT}))
    assert gate.main([str(good)]) == 0
    assert gate.main([str(good), str(bad)]) == 1


def _steps(workflow):
    text = (REPO / ".github" / "workflows" / workflow).read_text()
    return [m.group(1).strip() for m in re.finditer(r"^    - name: (.+)$", text, re.M)], text


def _step(text, name):
    body = text[text.index(f"- name: {name}"):]
    return body[:body.find("\n    - name:")]


def _expand(step, take):
    """Basenames a step names, with `for a in x y; do ... "$a.json" ...; done`
    loops expanded. `take(line)` returns the file token a line contributes."""
    names = set()
    loops = list(re.finditer(r"for (\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S))
    for var, items, body in (m.groups() for m in loops):
        for line in body.splitlines():
            tok = take(line)
            if tok and f"${var}" in tok:
                names |= {Path(tok.replace(f"${var}", i)).name for i in items.split()}
    outside = step
    for m in reversed(loops):
        outside = outside[:m.start()] + outside[m.end():]
    for line in outside.splitlines():
        tok = take(line)
        if tok and "$" not in tok:
            names.add(Path(tok).name)
    return names


def _uploaded(line):
    m = re.search(r"aws s3 cp \"?([^\s\"]+)\"?\s+\"?s3://", line)
    return m.group(1) if m else None


def _gate_files(step, cwd):
    """Run the gate step's shell with the scanner replaced by `echo`, in `cwd`,
    and return the basenames it would scan."""
    lines = []
    for line in step.split("run: |", 1)[1].splitlines()[1:]:
        if line.strip() and not line.startswith(" " * 8):
            break  # the block ends where its indentation does
        lines.append(line[8:])
    script = "\n".join(lines)
    script = script.replace("python3 ../scripts/check-published-redaction.py", "echo")
    out = subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=cwd,
                         capture_output=True, text=True, check=True).stdout
    return {Path(t).name for t in out.split()}


def test_deploy_gates_exactly_what_it_publishes(tmp_path):
    names, text = _steps("deploy-with-opa.yml")
    i = names.index("Publication redaction gate (no AWS account ID)")
    assert names[i + 1] == "Publish all signed artifacts to /.well-known/"
    publish = _expand(_step(text, "Publish all signed artifacts to /.well-known/"), _uploaded)
    publish = {n for n in publish if not n.endswith((".bundle", ".tar.gz"))}
    assert {"ksi-signal.json", "vdr-history.json", "trust-center.json", "iiw.csv"} <= publish
    gate_step = _step(text, "Publication redaction gate (no AWS account ID)")
    # Every optional artifact present: the gate scans everything the upload does.
    optional = ("boundary-map", "reconcile-report", "trust-center", "conformance-results", "boundary-corroboration")
    for a in optional:
        (tmp_path / f"{a}.json").write_text("{}")
    assert _gate_files(gate_step, tmp_path) == publish
    # One absent (the operator-run corroboration): it is neither uploaded nor scanned.
    (tmp_path / "boundary-corroboration.json").unlink()
    assert _gate_files(gate_step, tmp_path) == publish - {"boundary-corroboration.json"}
    # Never a directory scan: the deploy downloads live files it does not
    # publish (the runtime signal), and a scan of its working directory read
    # them as its own output and blocked the deploy that would fix them.
    assert "--root" not in gate_step


def test_an_input_the_deploy_downloaded_does_not_block_it(tmp_path):
    """The failure on the first deploy with this gate: the live runtime signal,
    still unredacted because only this deploy can redact its source, sat in the
    working directory. Scanning the files the deploy publishes passes."""
    (tmp_path / "ksi-signal.json").write_text('{"native_id": "arn:aws:lambda:us-east-2:ACCOUNT:function:a"}')
    (tmp_path / "ksi-signal-runtime.json").write_text(json.dumps({"native_id": f"arn:aws:x::{ACCOUNT}:y"}))
    assert gate.main([str(tmp_path / "ksi-signal.json")]) == 0


def test_nightly_gates_exactly_what_it_publishes_and_redacts_the_beacon():
    names, text = _steps("evidence-nightly.yml")
    i = names.index("Publication redaction gate (no AWS account ID)")
    assert names[i + 1] == "Publish VDR + trend to /.well-known/"
    gate_step = text[text.index("- name: Publication redaction gate"):]
    gate_step = gate_step[:gate_step.find("\n    - name:")]
    gated = set(gate_step.split("check-published-redaction.py", 1)[1].split())
    step = text[text.index("- name: Publish VDR + trend to /.well-known/"):]
    step = step[:step.find("\n    - name:")]
    published = set(re.findall(r"^\s*put ([\w.-]+)\s", step, re.M))
    # Expand `for a in x y; do put "$a.json" ...; done` loops.
    for items, body in re.findall(r"for (?:\w+) in ([^;\n]+); do(.*?)\n\s*done", step, re.S):
        for suffix in re.findall(r'put "\$\w+(\.[\w.]+)"', body):
            published |= {i + suffix for i in items.split()}
    assert "vdr-history.json" in published, "loop expansion must see the CR26 reports"
    assert gated == {p for p in published if not p.endswith((".bundle", ".intoto.jsonl"))}
    beacon = text[text.index("- name: Write status beacon"):]
    assert beacon.index("_redact.py vdr-status.json") < beacon.index("cat vdr-status.json")


@pytest.mark.parametrize("signs", [True, False])
def test_the_beacon_publishes_whether_or_not_it_can_be_signed(tmp_path, signs):
    text = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    start = text.index("rm -f vdr-status.bundle", text.index("- name: Write status beacon"))
    end = text.index("        fi\n", start) + len("        fi\n")
    script = "\n".join(line[8:] if line.startswith(" " * 8) else line
                       for line in ("        " + text[start:end]).splitlines())
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cosign = 'touch vdr-status.bundle' if signs else 'exit 1'
    for name, body in (("cosign", cosign), ("aws", 'echo "$4" >> uploads')):
        (bin_dir / name).write_text(f"#!/bin/bash\n{body}\n")
        (bin_dir / name).chmod(0o755)
    (tmp_path / "vdr-status.bundle").write_text("left by an earlier step")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "SITE_BUCKET": "b"}
    subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=tmp_path, env=env, check=True)
    uploaded = (tmp_path / "uploads").read_text().split()
    assert uploaded[0] == "s3://b/.well-known/vdr-status.json"
    assert ("s3://b/.well-known/vdr-status.bundle" in uploaded) is signs


def test_verify_published_runs_the_same_gate():
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert "check-published-redaction.py\" --root \"$work/scan\"" in text


# --- consumers compare on the redacted form ------------------------------------

def test_reconcile_a_matches_redacted_inventory_to_live_arns():
    live = {f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app",
            f"arn:aws:logs:us-east-2:{ACCOUNT}:log-group:/aws/lambda/app"}
    signal = _redact.redact({"components": [
        {"native_id": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app"},
        {"native_id": f"arn:aws:logs:us-east-2:{ACCOUNT}:log-group:/aws/lambda/app:*"}]})
    assert rc.check_a_completeness(signal, live) == []
    # Still exact: a live resource the inventory lacks is reported, by name
    # (the message goes to a public Actions log, so not with the account).
    live.add(f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app-extra")
    assert rc.check_a_completeness(signal, live) == [
        "(a) live resource not in inventory: arn:aws:lambda:us-east-2:ACCOUNT:function:app-extra"]


def test_reconcile_i_finds_live_tags_for_a_redacted_native_id():
    tags = {f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app": {"Archetype": "app-tier"}}
    assert rc._match_live_tags("arn:aws:lambda:us-east-2:ACCOUNT:function:app", tags) == {"Archetype": "app-tier"}


def test_boundary_map_is_unchanged_by_redacting_the_inventory():
    import copy
    from test_build_boundary_graph import CLASSIFICATION, SIGNAL, STATE
    # The role is identified only by its ARN (no Terraform address), so the
    # function->role edge exists only if the inventory's ARN matches the one the
    # function's state names.
    signal = copy.deepcopy(SIGNAL)
    for c in signal["components"]:
        if c["component_id"] == "aws::iam_role::app":
            c["attributes"] = {}
    now = "2026-11-05T00:00:00+00:00"
    plain = bbg.build(signal, CLASSIFICATION, [STATE], {}, None, None, "c", now)
    redacted = bbg.build(_redact.redact(signal), CLASSIFICATION, [STATE], {}, None, None, "c", now)
    assert any({e.get("source"), e.get("target")} == {"aws::function::app", "aws::iam_role::app"}
               for e in plain["edges"]), plain["edges"]
    assert redacted == plain


def test_vdr_resolves_a_finding_that_names_a_full_arn():
    signal = {"components": [{"component_id": "aws::function::app",
                              "native_id": "arn:aws:lambda:us-east-2:ACCOUNT:function:app",
                              "attributes": {"classification": {"archetype": "app-tier"}}}]}
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "ksi-signal.json"
        p.write_text(json.dumps(signal))
        finding = {"resource": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app"}
        assert vdr.resolve_component(finding, vdr.build_component_index(p)) == "aws::function::app"
        assert vdr.resolve_classification(finding, vdr.build_classification_index(p)) == {"archetype": "app-tier"}


def test_corroboration_matches_tap_ids_to_the_redacted_inventory():
    assert corr.normalize_id("lambda_function", f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app") \
        == "arn:aws:lambda:us-east-2:ACCOUNT:function:app"
    assert corr.public_name("arn:aws:lambda:us-east-2:ACCOUNT:function:app") == "function:app"
    assert corr.public_name(f"arn:aws:iam::{ACCOUNT}:role/app") == "app"


def test_gate_event_text_is_redacted_at_the_source():
    assert ACCOUNT not in _gates._clean(f"User: arn:aws:sts::{ACCOUNT}:assumed-role/x is not authorized")


# --- the runtime Lambda fills its own account back in ---------------------------

@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_lambda_fills_its_own_account_into_a_redacted_arn():
    script = """
const a = require(process.argv[1]);
const acct = a.accountOf('arn:aws:lambda:us-east-2:%s:function:opa');
const out = {
  acct,
  filled: a.withAccount('arn:aws:secretsmanager:us-east-2:ACCOUNT:secret:x', acct),
  untouched: a.withAccount('arn:aws:s3:::bucket', acct),
  notArn: a.withAccount('iam-role-policy::r/p', acct),
};
let threw = false;
try { a.accountOf(undefined); } catch (e) { threw = true; }
out.threw = threw;
console.log(JSON.stringify(out));
""" % ACCOUNT
    res = subprocess.run(["node", "-e", script, str(REPO / "infrastructure" / "lambda" / "account.js")],
                         capture_output=True, text=True, check=True)
    out = json.loads(res.stdout)
    assert out == {"acct": ACCOUNT,
                   "filled": f"arn:aws:secretsmanager:us-east-2:{ACCOUNT}:secret:x",
                   "untouched": "arn:aws:s3:::bucket", "notArn": "iam-role-policy::r/p", "threw": True}


def test_lambda_uses_the_fill_in_for_every_arn_it_calls_with():
    src = (REPO / "infrastructure" / "lambda" / "index.js").read_text()
    assert "evaluateSecretRotation(sm, withAccount(secret.native_id, accountOf(invokedFunctionArn)))" in src
    assert "evaluateSecretRotation(sm, secret.native_id)" not in src


def test_policy_hashes_cannot_be_used_to_recover_the_account():
    """The Terraform behind each policy is public, so a hash over a body that
    holds the account ID is an oracle: try every twelve-digit number until it
    matches. The builder hashes the redacted body instead."""
    import hashlib
    body = json.dumps({"Statement": [{"Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}}]})
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_iam_role", "name": "r", "address": "aws_iam_role.r",
         "values": {"arn": f"arn:aws:iam::{ACCOUNT}:role/r", "name": "r", "assume_role_policy": body}},
        {"type": "aws_iam_role_policy", "name": "p", "address": "aws_iam_role_policy.p",
         "values": {"name": "p", "role": "r", "policy": body}},
    ]}}}
    attrs = [c["attributes"] for c in bks.build_cloud_components(state, {})]
    digests = {a.get("trust_policy_sha256") or a.get("policy_document_sha256") for a in attrs}
    assert hashlib.sha256(body.encode()).hexdigest() not in digests
    assert digests == {hashlib.sha256(_redact.redact_text(body).encode()).hexdigest()}


def test_deploy_refreshes_the_runtime_signal_before_verifying_it():
    """The external verifier scans the runtime signal through the CDN. The
    runtime Lambda emits it from the published inventory, so the deploy invokes
    it after publishing and before the invalidation and the verifier; in the
    other order the verifier judged the previous inventory's runtime signal."""
    names, text = _steps("deploy-with-opa.yml")
    order = [names.index(n) for n in ("Publish all signed artifacts to /.well-known/",
                                       "Run Post-Deployment Compliance Check",
                                       "Invalidate CloudFront Cache",
                                       "External verifier smoke test (reciprocity handshake)")]
    assert order == sorted(order)
    step = _step(text, "Run Post-Deployment Compliance Check")
    assert "aws lambda invoke" in step and "if:" not in step.split("run:", 1)[0]
