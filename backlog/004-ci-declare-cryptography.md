# Add `cryptography` to the CI test job's pip install line so the six signature-verification tests cannot vanish silently when the GitHub runner image changes.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes, plus: `.github/workflows/deploy-with-opa.yml` L180's install line names `cryptography`; the next CI run of the `test` job still reports the same pass/skip counts as before (267 passed / 6 skipped as of 2026-08-24 — this change must move nothing, and if the counts *do* change, the assumption behind it was wrong and that is the finding); and `requirements-dev.txt`'s block of comments about `cryptography` being "NOT in CI's install list" is rewritten to match the new reality.
OUT OF SCOPE: Pinning `cryptography` to a version — CI leaves `pytest`, `jsonschema`, and `pyyaml` unpinned and `requirements-dev.txt` documents at length why local pinning must mirror CI rather than lead it; pin both or neither, in a separate task. Changing `tests/test_runtime_signature.py`, including turning its `pytest.importorskip("cryptography")` into a hard import — the skip guard is correct defensive style and this task removes the *reason* it fires, not the guard. Adding any other package to the install line. Touching the Lambda packaging install at L879, which is a different job with a different purpose. Adopting hash-pinned dev dependencies. Any change to the deploy job, the gates, or `infrastructure/`.
LANDMINES: Nothing is broken today and it is important not to claim otherwise in the PR — this closes a latent dependency, it does not fix a live gap. The evidence: run 32751942007 reported "267 passed, 6 skipped", identical to a local venv that *does* have `cryptography`, which means the GitHub `ubuntu-latest` runner image is supplying it. An earlier write-up of this asserted CI was skipping those six tests; that was wrong and was corrected in commit `7308ca4`, so do not resurrect the wrong version of the story. The failure mode being closed is silent: if GitHub drops `cryptography` from the runner image, `importorskip` makes the whole module disappear from *collection* and the suite reports one bland skip rather than six missing tests. `requirements-dev.txt` currently carries a long comment block ending "Adding it to the pip install line in `.github/workflows/deploy-with-opa.yml` would close that, but nothing is broken today (out of scope for this change)" — that comment becomes false the moment this lands and must be updated in the same commit. The root `Makefile` and its `make check` / `check-full` targets are on `main` (#305 merged as `e124041`), so the ACCEPTANCE commands above run as written.
---
Diagnosed 2026-08-24 during Session 2; recorded as deferred in `~/.claude/setup/SETUP-LOG.md`.

Small task, and the smallest in this backlog — queued mainly because it is genuinely done in one line and because the reasoning around it has already been got wrong once, so the record is worth having in writing.

`tests/test_runtime_signature.py` guards on `pytest.importorskip("cryptography")`. Six tests sit behind that guard: valid-signature-verifies, tampered-signal-fails, wrong-key-fails, PEM round-trip, pinned canonical form, and attestation-excluded-from-canonical-bytes. `requirements-dev.txt` already declares `cryptography` so a local venv matches CI's *effective* environment. CI's *declared* environment still does not name it.

The change is to L180 of `.github/workflows/deploy-with-opa.yml`:

```
python3 -m pip install --user pytest jsonschema pyyaml cryptography 'ruff==0.15.20' 'mypy==2.1.0'
```

Then rewrite the `cryptography` comment block at the foot of `requirements-dev.txt`, which currently explains that CI does not declare it and that adding it there is out of scope. After this lands, the honest version of that comment is short: it is declared in both places, and the two lists must be changed together.

Verification worth doing rather than assuming: compare the `test` job's summary line before and after. Equal counts is the expected and desired result — it confirms the runner image was indeed already providing the package, and that this change buys insurance rather than coverage.
