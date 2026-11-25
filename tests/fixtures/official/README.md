# Official AP2 v0.2 sample tokens

These six files are the encoded sample tokens published in the AP2 documentation, copied
verbatim (by `extract_official.py`, not retyped) from:

- Repository: https://github.com/google-agentic-commerce/AP2
- Commit: `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29)
- License: Apache-2.0

| File | Source |
| --- | --- |
| `open_checkout.txt` | `docs/ap2/checkout_mandate.md:244` (open checkout mandate) |
| `closed_checkout.txt` | `docs/ap2/checkout_mandate.md:328` (closed checkout mandate, KB-SD-JWT) |
| `checkout_chain.txt` | `docs/ap2/checkout_mandate.md:494` (open `~~` closed) |
| `open_payment.txt` | `docs/ap2/payment_mandate.md:351` (open payment mandate) |
| `closed_payment.txt` | `docs/ap2/payment_mandate.md:408` (closed payment mandate, KB-SD-JWT) |
| `payment_chain.txt` | `docs/ap2/payment_mandate.md:534` (open `~~` closed) |

Only the encoded tokens are used. The pretty-printed "decoded" JSON next to them in the
upstream docs does not match the tokens in several places (see `docs/spec-notes.md`).

Upstream publishes neither the agent-provider (mandate issuer) public key nor the merchant
public key, and no receipt, so root and merchant signatures cannot be verified and the
example bundle `examples/official-ap2-v0.2-docs.bundle.json` is INCOMPLETE by design.

To regenerate (the clone is only read; nothing in it is executed):

    python tests/fixtures/official/extract_official.py PATH/TO/AP2-CLONE
