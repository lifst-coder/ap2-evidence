# Getting your evidence into ap2-evidence

`ap2-evidence verify` reads one JSON evidence bundle (format: [bundle-format.md](bundle-format.md)).
You never have to write that JSON by hand: `ap2-evidence pack` assembles it from the files you
already have. This page shows how, for the situations people actually end up in.

Every command below is run by the test-suite (`tests/test_docs_commands.py`) from the
repository root against the fixtures in `tests/fixtures/upstream-sdk/`, which were minted by the
official AP2 SDK and sample code (see the README in that folder). The comment at the end of a
command is the exit code it gives there: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE, 2 unreadable input.

Three rules hold everywhere:

- **Tokens are copied byte for byte.** Only surrounding whitespace and newlines are removed.
  Hashes link the artifacts together, so a re-encoded token would break them.
- **Public keys are not put into the bundle** unless you ask for it (`--embed-keys`). Keys inside
  a bundle are self-asserted: whoever passes the bundle on can swap them. `pack` writes keys to a
  separate trusted-keys file (`--keys-out`) that you pin at verify time.
- **Never give a private key.** A JWK with `d` or a PEM `PRIVATE KEY` is refused with exit
  code 2; the key is not echoed.

## I use the official AP2 Python SDK

The SDK (`code/sdk/python/ap2/sdk` in the AP2 repository) gives you every artifact as a string.
Save each string to its own text file, unchanged:

| ap2-evidence file | Where the string comes from in the SDK |
| --- | --- |
| checkout mandate chain | the return value of `MandateClient().present(...)` for the checkout (the `open~~closed` chain the agent sends to the merchant) |
| payment mandate chain | the return value of `MandateClient().present(...)` for the payment (sent to the credentials provider) |
| checkout receipt | the JWT the merchant signs with `jwt_helper.create_jwt(header, ReceiptClient().create_checkout_receipt(...).model_dump(), merchant_key)` |
| payment receipt | the JWT the payment processor signs the same way around `ReceiptClient().create_payment_receipt(...)` |
| mandate issuer key | the public part of `issuer_key` passed to `MandateClient().create(...)` (the user's credential or the agent provider), e.g. `issuer_key.export_public()` |
| merchant key | the public part of the key that signed the `checkout_jwt` and the checkout receipt |
| payment processor key | the public part of the key that signed the payment receipt |
| expected `aud` / `nonce` | the `aud=` and `nonce=` arguments of the two `present(...)` calls |

The agent's own key is not needed: it is inside the open mandates (`cnf.jwk`).

```python
from pathlib import Path

Path("checkout_mandate.txt").write_text(checkout_chain, encoding="ascii")
Path("payment_mandate.txt").write_text(payment_chain, encoding="ascii")
Path("checkout_receipt.jwt").write_text(checkout_receipt_jwt, encoding="ascii")
Path("payment_receipt.jwt").write_text(payment_receipt_jwt, encoding="ascii")
Path("issuer.jwk").write_text(issuer_key.export_public(), encoding="utf-8")  # public only
```

Then pack and verify them as in [I have loose token files and PEM keys](#i-have-loose-token-files-and-pem-keys).
Key files may be a JWK (as `export_public()` writes), a JWKS (`{"keys": [...]}`), a PEM
`PUBLIC KEY`, or a PEM certificate.

## I ran the official sample

The AP2 Python samples (`code/samples/python`) write everything they persist into one folder,
`$TEMP_DB_DIR` (default `.temp-db`): the mandate chains as `chk_<id>.sdjwt` and `pay_<id>.sdjwt`,
the public keys as `*_signing_key.pub`, and the credentials provider's `ap2_token_store.json`.
The samples do not store the receipts the merchant and payment processor return, so a bundle
imported from that folder alone has no receipts and its first verdict is `INCOMPLETE`; the
second pair of commands below adds the receipts. Import the purchase directly:

```bash
ap2-evidence pack --from-ap2-sample-db tests/fixtures/upstream-sdk/samples_hnp_card/temp-db --keys-out sample-keys.json --out sample.bundle.json  # exit 0
ap2-evidence verify sample.bundle.json --trusted-keys sample-keys.json  # exit 3
```

What the import takes and why:

- The checkout and payment chains are paired by their hash links (the payment mandate's
  `transaction_id` is the hash of the checkout). If the folder holds several purchases, the
  import refuses to guess, lists the pairs, and asks for `--checkout chk_<id> --payment pay_<id>`.
- `agent_provider_signing_key.pub` becomes the mandate issuer key,
  `merchant_signing_key.pub` the merchant key, `merchant_payment_processor_signing_key.pub` the
  payment processor key. They are written to `--keys-out`, not into the bundle. Pin them only if
  you trust the folder they came from.
- The `*.pem` files in that folder hold the samples' **private** keys. The import never opens
  them. Do not copy or share them.
- `expected.payment.nonce` comes from the sample's own `ap2_token_store.json`, and the `aud`
  values are the ones the sample servers check (`merchant`, `credential-provider`). They are
  stored in the bundle, so they are self-asserted; the report says so. The checkout nonce is not
  persisted by the samples, so the checkout nonce check is skipped (and not required).
- **Receipts are not persisted by the samples.** That is why the verdict above is `INCOMPLETE`:
  the receipt signatures and references could not be checked. If you kept the receipts the
  merchant and processor returned, add them:

```bash
ap2-evidence pack --from-ap2-sample-db tests/fixtures/upstream-sdk/samples_hnp_card/temp-db --checkout-receipt tests/fixtures/upstream-sdk/samples_hnp_card/checkout_receipt.jwt --payment-receipt tests/fixtures/upstream-sdk/samples_hnp_card/payment_receipt.jwt --keys-out sample-keys.json --out sample.bundle.json --force  # exit 0
ap2-evidence verify sample.bundle.json --trusted-keys sample-keys.json  # exit 0
```

## I have loose token files and PEM keys

One token per text file (UTF-8, or UTF-16 with a BOM as Windows PowerShell 5.1 writes with `>`),
public keys as PEM or JWK, one role flag per key file (repeatable):

```bash
ap2-evidence pack --checkout-mandate tests/fixtures/upstream-sdk/loose/checkout_mandate.txt --payment-mandate tests/fixtures/upstream-sdk/loose/payment_mandate.txt --checkout-receipt tests/fixtures/upstream-sdk/loose/checkout_receipt.jwt --payment-receipt tests/fixtures/upstream-sdk/loose/payment_receipt.jwt --issuer-key tests/fixtures/upstream-sdk/loose/issuer.pem --merchant-key tests/fixtures/upstream-sdk/loose/merchant.pem --processor-key tests/fixtures/upstream-sdk/loose/processor.pem --expect-payment-aud credential-provider --note "order 825ef2c9" --keys-out card-keys.json --out card.bundle.json  # exit 0
ap2-evidence verify card.bundle.json --trusted-keys card-keys.json  # exit 0
```

`pack` prints what it included, what is missing, where the keys went and the exact `verify`
command to run next. The same key files also work directly with `verify`, without a
trusted-keys file:

```bash
ap2-evidence verify card.bundle.json --issuer-key tests/fixtures/upstream-sdk/loose/issuer.pem --merchant-key tests/fixtures/upstream-sdk/loose/merchant.pem --processor-key tests/fixtures/upstream-sdk/loose/processor.pem  # exit 0
```

Key formats:

| Format | Notes |
| --- | --- |
| JWK | EC P-256 public key. Members outside AP2's `jwk.json` are dropped with a note. |
| JWKS | `{"keys": [...]}`; every key gets the role of the flag. |
| PEM `PUBLIC KEY` | SubjectPublicKeyInfo, as `openssl pkey -pubout` writes. |
| PEM `CERTIFICATE` | Only the public key is taken. The certificate itself (dates, issuer, chain, revocation) is **not** validated, and a note says so. |
| trusted-keys file | `{"mandate_issuer": [...], "merchant": [...], "payment_processor": [...]}`, with `--trusted-keys`. |

Only P-256 / ES256 keys exist in AP2 v0.2; other curves, RSA and Ed25519 are refused as
unsupported. A plain JWKS or a single JWK does not say whose key it is, so it is accepted with a
role flag but not as `--trusted-keys`.

## The flow gave me no signed receipt

Some AP2 sample flows do not return a signed receipt at all. The x402 PSP returns a settlement
object such as `{"transaction_id": ..., "status": "SETTLED", ...}`, and the human-present flow
returns the receipt as a plain JSON dict. These are not signed by anyone, so they prove nothing.
`pack` keeps such an object in the bundle as a JSON object (not as a token), so the report can
show what the flow returned:

```bash
ap2-evidence pack --checkout-mandate tests/fixtures/upstream-sdk/loose/checkout_mandate.txt --payment-mandate tests/fixtures/upstream-sdk/loose/payment_mandate.txt --checkout-receipt tests/fixtures/upstream-sdk/loose/checkout_receipt.jwt --payment-receipt tests/fixtures/upstream-sdk/loose/x402_psp_settlement.json --trusted-keys tests/fixtures/upstream-sdk/card/trusted_keys.json --keys-out nr-keys.json --out no-receipt.bundle.json  # exit 0
ap2-evidence verify no-receipt.bundle.json --trusted-keys nr-keys.json  # exit 3
```

`pack` says `this flow produced no signed payment receipt` and that an unsigned receipt proves
nothing; `verify` reports it as `unsigned_receipt` (PR01 SKIP). The verdict is then
`INCOMPLETE`: everything else (mandate signatures, the hash links, the limits) can be
VERIFIED, but nothing signed by the payment processor shows that the payment was executed. That
is the honest answer for such a flow, not a defect of the evidence you gave.

## I know what the transaction should have been

If you are the merchant, the payment processor or a dispute handler, you usually know from your
own records which agent key the user enrolled, the checkout id, your merchant id and the total.
Assert them, and the report checks the evidence against them (checks EX01-EX05). Amounts are in
minor units followed by the currency: `9998 USD` is USD 99.98.

```bash
ap2-evidence verify tests/fixtures/upstream-sdk/card/bundle.json --trusted-keys tests/fixtures/upstream-sdk/card/trusted_keys.json --expect-agent-key tests/fixtures/upstream-sdk/loose/agent.jwk --expect-checkout-id cart_87a50473919f --expect-merchant-id merchant_1 --expect-total 9998 USD --require-constraint payment.amount_range  # exit 0
ap2-evidence verify tests/fixtures/upstream-sdk/card/bundle.json --trusted-keys tests/fixtures/upstream-sdk/card/trusted_keys.json --expect-total 9999 USD  # exit 1
```

`--expect-agent-key` takes the same key file formats as the role-key flags (public keys only).
`--require-constraint TYPE` (repeatable) fails the check if the open mandates do not carry that
constraint; the ten types are listed by `ap2-evidence verify --help`. `--require-pinned` makes
signatures that verify only under keys found inside the bundle count as not verified, so a
bundle that brings its own keys is at best `INCOMPLETE`:

```bash
ap2-evidence verify examples/demo-valid.bundle.json --require-pinned  # exit 3
```

These values are yours, not the bundle's: they are command-line only, `pack` does not store
them, and the report lists which ones were given (`options` in the JSON report).

## The mandate has a budget

A `payment.budget` or `payment.agent_recurrence` constraint limits all payments made under one
open mandate together. One bundle shows one payment, so the tool cannot know what was spent
before; without that, PM39 is a required SKIP and the verdict `INCOMPLETE`. If your records
show the earlier payments, assert them with `--prior-total MINOR_UNITS CURRENCY` (what was
already paid) and `--prior-uses N` (how many payments were already made). Here the budget is
USD 150.00 and this payment is USD 99.98:

```bash
ap2-evidence verify tests/fixtures/upstream-sdk/v_extras_usd/bundle.json --trusted-keys tests/fixtures/upstream-sdk/v_extras_usd/trusted_keys.json  # exit 3
ap2-evidence verify tests/fixtures/upstream-sdk/v_extras_usd/bundle.json --trusted-keys tests/fixtures/upstream-sdk/v_extras_usd/trusted_keys.json --prior-total 5002 USD --prior-uses 0  # exit 0
ap2-evidence verify tests/fixtures/upstream-sdk/v_extras_usd/bundle.json --trusted-keys tests/fixtures/upstream-sdk/v_extras_usd/trusted_keys.json --prior-total 5003 USD --prior-uses 0  # exit 1
```

The report says these figures were supplied by whoever ran the verifier: they are your
assertion, and the result is only as good as your records.

## I have many transactions

Give several bundles, or a folder. Every `*.json` file in the folder that is an evidence bundle
(has `bundle_version`) is verified; other JSON files, such as key files, are listed as skipped.
Add `--recursive` for subfolders. Keys and options given once apply to every bundle.

```bash
ap2-evidence verify tests/fixtures/upstream-sdk/card/bundle.json tests/fixtures/upstream-sdk/tamper/K1_amount_over_cap/bundle.json tests/fixtures/upstream-sdk/tamper/K4b_payment_receipt_ref_random/bundle.json tests/fixtures/upstream-sdk/tamper/K7_error_receipt/bundle.json --trusted-keys tests/fixtures/upstream-sdk/card/trusted_keys.json --out-dir reports --summary-csv summary.csv  # exit 1
ap2-evidence verify tests/fixtures/upstream-sdk/card/bundle.json tests/fixtures/upstream-sdk/x402/bundle.json --format json  # exit 3
```

The summary has one line per bundle (verdict, where the keys came from, FAIL and SKIP counts,
the first failing or unverified check IDs); `--format json` prints it in the form fixed by
`schemas/batch-summary.schema.json`, and `--summary-csv FILE` writes it as CSV. `--out-dir DIR`
writes each bundle's full report in `--format`, and each line of the text summary names its
report file in parentheses. A report is named after the bundle's path inside the folder you
gave; bundles with the same file name in different folders (as above, all `bundle.json`) get
the name of their parent folder in front. The first command prints:

```text
VERDICT     OUTCOME      KEYS    FAIL  SKIP  FILE  (REPORT)  [CHECKS]
VERIFIED    success      pinned     0    14  tests/fixtures/upstream-sdk/card/bundle.json  (card__bundle.report.txt)
FAILED      -            pinned     2    14  tests/fixtures/upstream-sdk/tamper/K1_amount_over_cap/bundle.json  (K1_amount_over_cap__bundle.report.txt)  [failed: PM32, XC01]
FAILED      -            pinned     1    14  tests/fixtures/upstream-sdk/tamper/K4b_payment_receipt_ref_random/bundle.json  (K4b_payment_receipt_ref_random__bundle.report.txt)  [failed: PR04]
VERIFIED    conflicting  pinned     0    14  tests/fixtures/upstream-sdk/tamper/K7_error_receipt/bundle.json  (K7_error_receipt__bundle.report.txt)

4 bundle(s): 2 VERIFIED, 2 FAILED, 0 INCOMPLETE, 0 unreadable. Worst: FAILED (exit code 1)
1 VERIFIED bundle(s) with outcome conflicting: the receipts disagree (both are authentic, one reports success and the other an error); ask the merchant and the payment processor what happened
```

If one report cannot be written, that bundle keeps its verdict, its line says
`report not written: ...`, the other bundles and the CSV are still processed, and the run ends
with exit code 2. The exit code is the worst over all bundles: 2 if any file is unreadable or
any report could not be written, else 1 if any is FAILED, else 3 if any is INCOMPLETE, else 0.
Pinned nonces (`--expect-*-nonce`), `--expect-checkout-id`, `--expect-total`, `--prior-total`
and `--prior-uses` belong to one transaction and are refused in a batch; `--require-pinned`,
`--expect-agent-key`, `--expect-merchant-id` and `--require-constraint` apply to every bundle.
The four bundles above are one transaction made with the card keys and three variants of it:
the first is `VERIFIED` with outcome `success`; K1 (the agent paid more than the user allowed)
and K4b (a receipt that refers to a random mandate) are `FAILED`. K7 is not tampered with: the
payment processor's authentic receipt says Error while the merchant's checkout receipt says
Success, so the evidence is `VERIFIED` but its outcome is not `success` (the receipts disagree;
read the full report in `reports/` before acting on it).

The OUTCOME column is what the receipts claim happened (`success`, `declined`, `conflicting`, `unknown`). It
means something only when the verdict is `VERIFIED`, so the text table shows it only for
VERIFIED rows and `-` otherwise. The JSON summary and the CSV keep the raw value for every row;
ignore it unless `verdict` is `VERIFIED`.

`--out` and `--summary-csv` are replaced if they already exist. `--out-dir` is created only
when there is a report to write, and if it already holds a report of the same name the run stops
before writing anything (exit code 2) unless you add `--force`; use a fresh folder per run.
`pack`, which writes evidence, never replaces a file unless you add `--force`. No output may be
the same file as an input or as another output (compared case-insensitively on Windows).

To find out what a check in the summary means:

```bash
ap2-evidence explain PM32  # exit 0
```
