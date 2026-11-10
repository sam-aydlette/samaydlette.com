"""Security impact analysis (scripts/sia.py, SCN-CSO-EVA).

The SCN type is derived from answers to the governed questions in
data/sia-questions.json, in SCN-CSO-EVA's order, and the declared SCN-Type
must equal it. Each known-bad input below changes the result.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import sia  # noqa: E402

DOC = sia.load_questions()
IAM = {"infrastructure/bootstrap/main.tf": ['+  actions = ["s3:GetObject"]']}
ARTICLE = {"website/pages/article-9.html": ["+<p>An email to a friend about TLS.</p>"]}


def ev(body, changes, author=None):
    return sia.evaluate(DOC, body, changes, author)


def test_a_question_the_diff_touches_must_be_answered_with_a_reason_for_no():
    missing = ev("SCN-Type: adaptive\n\nSIA:\n- pipeline: yes\n", IAM)
    assert any("`access` must be answered" in e for e in missing["errors"])
    bare = ev("SCN-Type: adaptive\n\nSIA:\n- pipeline: yes\n- access: no\n", IAM)
    assert any("`access` is answered no but gives no reason" in e for e in bare["errors"])
    ok = ev("SCN-Type: adaptive\n\nSIA:\n- pipeline: yes\n- access: no (narrows a read)\n", IAM)
    assert ok["errors"] == [] and ok["outcome"] == "adaptive"


def test_the_declared_type_must_equal_the_analysis():
    body = "SIA:\n- access: yes\n"
    assert any("add `SCN-Type: adaptive`" in e for e in ev(body, IAM)["errors"])
    wrong = ev("SCN-Type: routine-recurring\n\n" + body, IAM)
    assert wrong["outcome"] == "adaptive"
    assert any("SCN-Type is `routine-recurring` but the analysis gives `adaptive`" in e for e in wrong["errors"])
    assert ev("SCN-Type: adaptive\n\n" + body, IAM)["errors"] == []
    assert any("not one of" in e for e in ev("SCN-Type: minor\n\n" + body, IAM)["errors"])


def test_a_class_change_cannot_ship_under_scn():
    changes = {"data/system-profile.json": ['-  "impact_level": "Moderate"', '+  "impact_level": "High"']}
    r = ev("SCN-Type: transformative\n\nSIA:\n- class-change: yes\n", changes)
    assert r["outcome"] == "class-change"
    assert any("needs a new assessment" in e for e in r["errors"])
    # Touching the profile without changing the level still has to say so.
    assert any("`class-change` must be answered" in e for e in ev("", changes)["errors"])


@pytest.mark.parametrize("body, changes, outcome", [
    # No security-relevant path, nothing triggered: not significant, no tag needed.
    ("", ARTICLE, "not-significant"),
    # A security-relevant path with every answer no and no recurring category: adaptive.
    ("SCN-Type: adaptive\n\nSIA:\n- access: no (comment only)\n", IAM, "adaptive"),
    # The same, as a recurring category: routine recurring, no tag needed.
    ("SIA:\n- category: vulnerability-remediation\n- access: no (pins a patched version)\n", IAM,
     "routine-recurring"),
    # Any transformative yes outranks every adaptive yes.
    ("SCN-Type: transformative\n\nSIA:\n- access: yes\n- privacy-data: yes\n", IAM, "transformative"),
])
def test_the_outcome_follows_scn_cso_eva(body, changes, outcome):
    r = ev(body, changes)
    assert r["outcome"] == outcome and r["errors"] == [], r["errors"]


def test_only_dependabot_version_changes_are_answered_automatically():
    bump = {".github/workflows/deploy-with-opa.yml": ["-      uses: actions/setup-node@aaa # v6", "+      uses: actions/setup-node@bbb # v7"],
            "infrastructure/lambda/package-lock.json": ['-  "version": "1.0.0"', '+  "version": "1.0.1"']}
    r = ev("Bumps setup-node.", bump, author="dependabot[bot]")
    assert r["outcome"] == "routine-recurring" and r["errors"] == [] and r["category"] == "dependency-update"
    # The same diff from a person must be answered.
    assert ev("Bumps setup-node.", bump, author="someone")["errors"]
    # A Dependabot change to anything but a version reference is not automatic.
    more = {**bump, ".github/workflows/deploy-with-opa.yml": ["+    permissions:", "+      id-token: write"]}
    assert ev("Bumps setup-node.", more, author="dependabot[bot]")["errors"]


def test_line_patterns_ignore_prose_tests_and_comments():
    changes = {"website/pages/article-9.html": ['+resource "aws_iam_role" "x" {'],
               "tests/test_x.py": ['+    "aws_kms_key"'],
               "infrastructure/main.tf": ["+# aws_kms_key is mentioned in a comment"]}
    assert sia.triggered(DOC, changes) == {}
    # The question file names every pattern; its path is what triggers (compliance-engine).
    own = sia.triggered(DOC, {"data/sia-questions.json": ['+  "diff": ["aws_kms_", "aws_iam_"]']})
    assert set(own) == {"compliance-engine"}
    assert "crypto" in sia.triggered(DOC, {"infrastructure/main.tf": ['+resource "aws_kms_key" "k" {']})


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d["questions"][0].update(outcome="minor"), "outcome must be one of"),
    (lambda d: d["questions"].append(dict(d["questions"][0])), "duplicate question id"),
    (lambda d: d["questions"][1]["triggers"].update(diff=["("]), "bad pattern"),
    (lambda d: d.pop("review_by"), "has no review_by"),
])
def test_a_bad_question_file_fails_closed(tmp_path, mutate, msg):
    d = json.loads(sia.QUESTIONS.read_text())
    mutate(d)
    p = tmp_path / "q.json"
    p.write_text(json.dumps(d))
    with pytest.raises(SystemExit, match=msg):
        sia.load_questions(p)


def test_a_malformed_answer_or_unknown_question_fails():
    with pytest.raises(SystemExit, match="cannot read SIA line"):
        sia.parse("SIA:\n- access: maybe\n")
    assert any("`acess` is not a question" in e for e in ev("SCN-Type: adaptive\n\nSIA:\n- acess: yes\n", IAM)["errors"])
    # The block ends at a blank line, so the PR's own bullet lists are not read as answers.
    assert sia.parse("SIA:\n- access: yes\n\n## Changed\n- **thing:** did it\n")[1] == {"access": ("yes", "")}


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_the_script_reads_the_git_diff_between_base_and_head(tmp_path):
    def git(*a):
        return subprocess.run(["git", "-C", str(tmp_path), *a], capture_output=True, text=True, check=True).stdout.strip()
    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (tmp_path / "infrastructure").mkdir()
    (tmp_path / "infrastructure" / "main.tf").write_text("# empty\n")
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (tmp_path / "infrastructure" / "main.tf").write_text('resource "aws_kms_key" "k" {}\n')
    git("commit", "-qam", "head")
    # The script diffs the repository it lives in, so run a copy inside this one.
    shutil.copytree(REPO / "scripts", tmp_path / "scripts")
    (tmp_path / "data").mkdir()
    shutil.copy(sia.QUESTIONS, tmp_path / "data" / "sia-questions.json")
    script = tmp_path / "scripts" / "sia.py"
    env = {**os.environ, "PR_BODY": "SCN-Type: adaptive\n\nSIA:\n- crypto: yes\n- new-component: yes\n"}
    env.pop("GITHUB_STEP_SUMMARY", None)

    def run(e):
        return subprocess.run([sys.executable, str(script), "--base", base, "--head", "HEAD"],
                              cwd=tmp_path, env=e, capture_output=True, text=True, check=False)

    ok = run(env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "## Security impact analysis: adaptive" in ok.stdout
    bad = run({**env, "PR_BODY": "SCN-Type: adaptive\n"})
    assert bad.returncode == 1 and "`crypto` must be answered" in bad.stdout


def test_the_workflow_validates_every_pull_request_into_main():
    text = (REPO / ".github" / "workflows" / "scn-tag.yml").read_text()
    step = text[text.index("- name: Validate the SCN evaluation"):]
    assert "github.event.pull_request.base.ref == 'main'" in step
    assert "PR_BODY: ${{ github.event.pull_request.body }}" in step
    assert 'python3 scripts/sia.py --base "$BASE_SHA" --head "$HEAD_SHA" --author "$PR_AUTHOR"' in step
    assert "${{" not in step.split("run:", 1)[1], "PR text is passed through env, never interpolated into the script"
    assert "not-significant" in text[: text.index("- name: Validate the SCN evaluation")]
