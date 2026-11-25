# Contributing to ap2-evidence

The most useful contribution right now is a report of a real AP2 bundle that this tool gets wrong. Code contributions are welcome too.

## Reporting a bundle that fails or is judged wrongly

Open an issue with the [Verification failure form](https://github.com/lifst-coder/ap2-evidence/issues/new?template=verification_failure.yml). The minimum is the command you ran and what the same command prints with `--format issue`. Where the tokens came from (AP2 sample scenario, SDK version, or your own implementation) and the check IDs you think are wrong help a lot.

Use test or sandbox tokens only. Mandate tokens and receipts contain payment instrument descriptions, merchant data and buyer data. Never post production tokens or private keys. Public keys are fine.

If you think a forged or tampered bundle comes out VERIFIED, do not open a public issue; follow [SECURITY.md](SECURITY.md).

## Development setup

Python 3.10 or newer.

```
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python -m pytest -q
```

On Windows use `.venv\Scripts\python` in place of `.venv/bin/python`. `ap2-evidence demo` should print a VERIFIED report and exit 0.

On Windows with Python 3.10 to 3.12, an editable install is not importable when the repository path contains non-ASCII characters (Python reads the install's path file in the system code page). The test suite is not affected, because pytest imports from `src` directly; to run the command-line program in that situation, set `PYTHONPATH=src` and use `python -m ap2_evidence`.

## How the code is organised

The package lives in `src/ap2_evidence`. Input parsing (bundle files, SD-JWT tokens, receipts) is separate from verification and from report rendering. Each verification step is a check registered in a single registry under a stable ID (for example `CM09`); a check takes the parsed bundle and returns a result with a status and a short explanation. The report renderers (text, Markdown, JSON, HTML, issue block) only format those results; the plain-language sentence and the suggested next step for each reason code live next to the check registry. Every check ID and what it means is documented in `docs/checks.md`. Wherever the AP2 spec is ambiguous and the code had to pick an interpretation, the choice and the upstream source it is based on are recorded in `docs/spec-notes.md`.

## Rules for checks

- Every check needs at least two tests: one input where it passes, and one forged or tampered input where it fails. A check without a forged test is not accepted.
- Check IDs are stable. Do not renumber or reuse an ID; retire it and add a new one.
- If a change alters what a check means, update `docs/checks.md` in the same pull request.
- Test fixtures must be generated test data, the unmodified official AP2 samples, output of the official SDK made with throwaway keys, or third-party vectors whose licence allows redistribution (with attribution in `NOTICE`). No production tokens, no private keys.
- A change to the verifier should survive its own sabotage: weaken the line you added and confirm a test fails.

## Proposing a change to how the spec is interpreted

Open an issue (or a pull request that updates `docs/spec-notes.md`) that cites the upstream source: the file in google-agentic-commerce/AP2, the line number, and the commit, ideally as a permalink of the form `https://github.com/google-agentic-commerce/AP2/blob/<commit>/<path>#L<line>`. Explain what the current interpretation gets wrong and what bundle it affects. Interpretation changes without an upstream reference are hard to judge and will usually be parked.

## Out of scope for now

- A hosted service or web UI. This is an offline CLI.
- Signature algorithms other than ES256.
- AP2 v0.1 mandate types.

These may be reconsidered if there is clear demand; an issue describing your use case is the way to show it.

## Pull requests

Keep pull requests small and focused. The pull request template lists what is checked before merging. CI runs ruff and mypy once, pytest and a demo smoke test on Linux, Windows and macOS for Python 3.10 to 3.13, the tests again with the oldest supported `cryptography`, a self-test of the GitHub Action, and a package build.

By contributing you agree that your contribution is licensed under the Apache License 2.0, the license of this project.
