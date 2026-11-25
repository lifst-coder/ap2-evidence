# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is 0.x, check IDs, the bundle format and the report schema may still change between minor versions; such changes will be listed here.

## [0.1.0] - 2026-11-25

First public release. Written against AP2 v0.2 (upstream commit `e1ea56d`, identical to tag `v0.2.0` for everything this tool depends on), using the upstream JSON schemas, the encoded sample tokens and the SDK source as the reference for field names and wire format.

### Verifying

- `ap2-evidence verify`: verifies an evidence bundle (checkout mandate chain, payment mandate chain, checkout receipt, payment receipt) and reports `VERIFIED`, `FAILED` or `INCOMPLETE` (exit codes 0, 1, 3; 2 for unreadable input).
- 86 checks with stable IDs covering signatures (ES256), SD-JWT disclosure digests, key binding (`cnf.jwk`, `sd_hash` / `issuer_jwt_hash`), `checkout_hash`, `transaction_id`, `payment.reference`, all ten v0.2 constraint types, amount and payee consistency, receipt `reference`, and the order of events. Withheld constraints fail; other undisclosed digests in a mandate make the verdict `INCOMPLETE`.
- An authentic payment receipt that reports a declined payment gives `VERIFIED - PAYMENT DECLINED`: intact evidence of a decline is not a broken chain. Two authentic receipts that disagree (one success, one error) give `VERIFIED - RECEIPTS DISAGREE`. A receipt whose own signature, required-fields, reference or time check failed never decides the outcome.
- `--trusted-keys` and the role-key flags (`--issuer-key`, `--merchant-key`, `--processor-key`) pin keys; `--require-pinned` treats signatures checked only with keys from inside the bundle as not verified. The verdict line and every signature check state where the key came from.
- Expectations of the party running the verifier (agent key, checkout id, merchant id, total, required constraints, `aud`, `nonce`) are checked when given.
- Spending history can be supplied so that cumulative limits (`payment.budget`, `payment.agent_recurrence`) are evaluated; without it a mandate with such a limit is `INCOMPLETE`.
- `--at` checks validity at a given time; `--skew` sets clock tolerance.
- Several bundles or a folder can be verified in one run, with a summary table, a CSV summary and one report per bundle.

### Getting evidence in

- `ap2-evidence pack` assembles a bundle from loose token files, and imports the folder written by the official AP2 Python samples (`--from-ap2-sample-db`), pairing checkout and payment chains by their hash link.
- Public keys are accepted as JWK, JWKS, PEM public keys and PEM certificates (the certificate chain is not validated). Private key material is refused.

### Reading the result

- Reports lead with the finding, what it means and what to do next, list every broken link in full, group failures that follow from one root cause, and end with a glossary of the terms used.
- Formats: text, Markdown, JSON (fixed by a schema shipped in the package), a standalone HTML page for printing or attaching, and a short `--format issue` block for bug reports.
- Every result that is not a pass has a machine-readable `reason` code, a plain sentence and a suggested next step.
- `ap2-evidence explain CHECK_ID` describes a check; `ap2-evidence inspect` decodes tokens, chains, receipts and bundles without judging them.
- `ap2-evidence demo` with `--tamper amount|receipt|disclosure|key` and `--save-bundle`.

### Integration

- A GitHub Action (`action.yml`) that verifies bundles in CI and fails the job when evidence does not verify.

### Tested against

- Mandates and receipts minted by the official AP2 Python SDK and by the upstream human-not-present card sample, unmodified, with 21 altered variants (`tests/fixtures/upstream-sdk`).
- The six sample tokens from the AP2 documentation.
- Test vectors published by other AP2 implementers; results and every disagreement are in `docs/cross-implementation.md`.
- Deliberate mutations of the verifier, to confirm that the tests fail when a check is weakened.
- Independent adversarial reviews (forgery, downgrade from `FAILED` to `INCOMPLETE`, misleading report text, hostile file names and oversized input); their findings are fixed and covered by `tests/test_audit_findings.py` and `tests/test_adversarial_*.py`.

### Known limits

- ES256 / P-256 only. No `x5c` chain validation, no key discovery, no revocation.
- Chains of exactly one (directly signed closed mandate) or two (open plus closed) segments.
- AP2 v0.1 Intent and Cart mandates and the user-credential (DPC / OpenID4VP) model are not supported.
- Keys are not bound to identities: the tool cannot tell which pinned key belongs to which merchant or issuer.
- A mandate that uses SD-JWT decoy digests inside the mandate object is reported as `INCOMPLETE`, because a decoy cannot be told apart from a withheld claim.
- An open checkout mandate presented with fewer disclosures than were issued makes the payment's reference to it impossible to recompute. The verdict is `INCOMPLETE`, and this cannot be told apart from a payment that refers to a different checkout.
- Replay of one mandate across several payments cannot be seen from one bundle; history figures are taken on the word of whoever runs the verifier.
- Not tested against production traffic.

[0.1.0]: https://github.com/lifst-coder/ap2-evidence/releases/tag/v0.1.0
