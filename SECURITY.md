# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| older   | No        |

## Reporting a vulnerability

Report privately through GitHub: on the repository page go to **Security > Advisories > Report a vulnerability**, or open https://github.com/lifst-coder/ap2-evidence/security/advisories/new directly. There is no email address for reports.

Please include the ap2-evidence version, the command you ran, and a bundle or script that reproduces the problem. Use generated test keys and tokens.

## What counts as a vulnerability

ap2-evidence is a verifier, so the main risk is a wrong "yes". In order of severity:

- Anything that makes a forged or tampered bundle come out VERIFIED.
- Bypassing a signature check, a disclosure digest check, key binding, or a hash binding (checkout_hash, transaction_id, receipt reference).
- A report that says a check passed when it did not run, or that hides a failed check.
- A crash, hang or excessive memory use on crafted input. This is treated as a bug, with lower severity than the items above, but you can still report it privately if you prefer.

## What is not a vulnerability

These are documented limits, not flaws:

- Public keys supplied inside a bundle are self-asserted. A bundle whose keys and signatures were all produced by the same party verifies against those keys. The report states which keys were used and where they came from; deciding whether to trust them is up to the reader.
- There is no revocation checking.
- x5c certificate chains are not validated.

If you think one of these limits should be closed, open a normal feature request.

## Public issues

Never post production tokens, real payment or personal data, or private keys in a public issue, pull request or discussion. Public keys are fine.

## Response

This is a one-person project maintained on a best-effort basis. Expect an acknowledgement within about a week. Fixes for issues that make forged bundles verify get priority over everything else. There is no bug bounty.
