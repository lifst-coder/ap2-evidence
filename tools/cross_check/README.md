# cross_check: ap2-evidence against third-party AP2 vectors

Converts other authors' AP2 v0.2 test vectors to `ap2-evidence/1` bundles, verifies them
in-process with this tree's `ap2_evidence`, and compares each verdict with the author's expected
outcome. Output: `docs/cross-implementation.md`, `tools/cross_check/results.json` and the
redistributed fixtures in `tests/fixtures/third-party/`.

Third-party repositories are read as data only: no file from them is imported or executed, and
these scripts never clone or download anything.

## 1. Get the sources

    python tools/cross_check sources

prints, for every source, the `git clone` / `git checkout` commands that put it at its pinned
commit. Run them yourself in one empty directory (say `../xsrc`). `run` refuses a clone that is
at a different commit and warns when it cannot read the commit.

## 2. Run

    python tools/cross_check run --src ../xsrc

From the repository root, with `cryptography` installed (the scripts put `src/` first on the
path, so the verifier under test is this tree's). It writes:

- `tests/fixtures/third-party/<source>/`: bundles, `MANIFEST.json` (origin of each vector,
  author's expectation, options used, our verdict, failing / blocking checks, classification,
  reason code) and the source's licence files, for the sources whose licence allows it;
- `tools/cross_check/results.json`: every row of every source;
- `docs/cross-implementation.md`: the results page, rendered from `results.json` only.

It prints the per-source counts and exits 1 if a row that is not `agree` has no reason code.

## 3. Check (offline)

    python tools/cross_check check

Re-verifies every redistributed bundle against its manifest, checks licence files and the
private-key scan, and checks that `results.json` matches the manifests and renders to exactly
the committed page. `tests/test_third_party.py` runs the same checks under pytest.

## When a row changes

A verifier change that alters a recorded verdict fails `tests/test_third_party.py`. Decide for
each changed row whether the new verdict is right and whether its reason code still fits
(`reasons.py`; add a rule or an entry if needed), then re-run step 2 and review the diff of the
manifests and the page before committing.

## Files

| File | Role |
|---|---|
| `sources.py` | pinned repositories, licences, which groups are redistributed, git commands |
| `convert.py` | one converter per source: bundle, expected outcome, options, notes |
| `mint.py` | deterministic re-signing for vectors shipped only as decoded payloads |
| `run.py` | in-process verification and classification |
| `reasons.py` | reason codes with our position and upstream evidence; fixes log |
| `keyscan.py` | refuses private key material in anything redistributed |
| `pipeline.py`, `page.py`, `check.py`, `layout.py` | writing, rendering, offline checks |
