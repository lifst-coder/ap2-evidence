# Evidence bundle format `ap2-evidence/1`

AP2 v0.2 says that "the Checkout Mandate and Receipt, and Payment Mandate and Receipt can be
brought together to provide a non-repudiable picture of the transaction"
(`docs/ap2/specification.md` "Dispute Evidence"), but it does not define a container for them.
This tool defines one. It is a single UTF-8 JSON object. The machine-readable definition is
`src/ap2_evidence/schemas/bundle.schema.json` (shipped inside the package).

```json
{
  "bundle_version": "ap2-evidence/1",
  "checkout_mandate": "<open SD-JWT>~<disc>~...~<disc>~~<closed KB-SD-JWT>~<disc>~...~<disc>~",
  "payment_mandate": "<same shape>",
  "checkout_receipt": "<compact JWT signed by the merchant>",
  "payment_receipt": "<compact JWT signed by the merchant payment processor>",
  "keys": {
    "mandate_issuer": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..."}],
    "merchant": [],
    "payment_processor": []
  },
  "expected": {
    "checkout": {"aud": "merchant", "nonce": "..."},
    "payment": {"aud": "credential-provider", "nonce": "..."}
  },
  "note": "free text"
}
```

## Members

All members except `bundle_version` are optional. A bundle with nothing verifiable is reported
as FAILED or INCOMPLETE, never as an error.

| Member | Type | Meaning |
| --- | --- | --- |
| `bundle_version` | string | Must be exactly `ap2-evidence/1`. |
| `checkout_mandate` | string | The checkout mandate chain exactly as presented to the merchant. |
| `payment_mandate` | string | The payment mandate chain exactly as presented to the credential provider / processor. |
| `checkout_receipt` | string or object | The Checkout Receipt JWT (see [Receipts](#receipts) for the unsigned forms that are also read). |
| `payment_receipt` | string or object | The Payment Receipt JWT (likewise). |
| `keys` | object | Public keys by role (see below). |
| `expected` | object | Values the closed tokens' `aud` and `nonce` must equal. |
| `note` | string | Free text. Ignored by the verifier. |

Unknown top-level members are ignored with a warning (check B01), and the conclusion names them
with a suggestion ("unknown bundle member 'chekout_mandate' was ignored - did you mean
'checkout_mandate'?"). The JSON schema rejects them, so a producer that validates its output
notices typos. A file whose top-level JSON value is not an object (for example `[1,2,3]`) is
not a bundle at all: the CLI stops with exit code 2.

### Mandate chains

A mandate member holds the SD-JWT chain in the AP2 v0.2 wire form
(upstream `code/sdk/python/ap2/sdk/README.md`, "chain serialization"):

- Segments are joined with `~~`. The trailing `~` of every non-final segment is removed before
  joining, as the upstream SDK does (`code/sdk/python/ap2/sdk/mandate.py:390-400`); the verifier
  restores it.
- Segment 1 is the root SD-JWT signed by the mandate issuer (the user's credential or a trusted
  agent provider). For the human-not-present flow it carries the **open** mandate.
- Segment 2 is the agent-signed **closed** mandate (`typ: kb+sd-jwt`), with its own disclosures.
- A single segment ending in `~` is a directly signed closed mandate (human present). Key-binding
  checks then do not apply.
- More than two segments (agent-to-agent delegation) is outside AP2 v0.2 and is reported as not
  verified.

The chain must be kept **byte for byte as presented**: `sd_hash`, `payment.reference` and the
receipt `reference` are hashes over these exact strings. Re-encoding, re-ordering or dropping
disclosures breaks them.

### Receipts

Receipts are plain compact JWTs (`header.payload.signature`), not SD-JWTs. A receipt member may
also hold a JSON object, or a string holding a JSON object: the unsigned receipt some upstream
sample flows return (the x402 PSP's settlement object, the human-present flow's receipt dict;
the upstream SDK probe `P3_unsigned_receipt_json_string` is the string form). The bundle is still
readable, and the verifier reports it as `unsigned_receipt` (CR01/PR01 required SKIP, so the
verdict is at best INCOMPLETE): an unsigned receipt proves nothing.

The JSON schema describes what the verifier reads, not what a receipt is worth: it accepts all
three forms (compact JWS, JSON object, string holding a JSON object), and the receipt checks
decide what each one shows. Every bundle under `tests/fixtures/` and `examples/` that `verify`
can read validates against the schema (`tests/test_final_review.py`).

### Keys and provenance

`keys` maps a role to an array of EC P-256 public JWKs (members as allowed by upstream
`code/sdk/schemas/ap2/types/jwk.json`; private key member `d` is rejected).

| Role | Verifies |
| --- | --- |
| `mandate_issuer` | Root token of both mandate chains (the user credential / agent provider key). |
| `merchant` | The `checkout_jwt` inside the closed checkout mandate, and the checkout receipt. |
| `payment_processor` | The payment receipt. |

The agent's key is not supplied here: it is taken from `cnf.jwk` of the open mandates, which
the mandate issuer signed.

Keys are matched by the token's `kid` header when it has one (keys without a `kid` are tried
when no key has that `kid`); without a `kid`, every key of the role is tried.

**Provenance.** Keys inside the bundle are *self-asserted*: whoever assembled the bundle chose
them. A forger can sign a fake receipt with their own key and put that key into the bundle.
Keys passed with `--trusted-keys FILE` (same `{"role": [JWK, ...]}` shape) are *pinned* by the
person running the verifier. When `--trusted-keys` has keys for a role, the bundle's keys for
that role are ignored. Every signature check in the report states which provenance was used
(`key_provenance`: `trusted`, `bundle`, or `mandate` for the agent key from `cnf.jwk`), and the
conclusion says so when a verdict rests on bundle-supplied keys.

A plain JWKS (`{"keys": [...]}`) or a single JWK is not accepted for `--trusted-keys`, because it
does not say which role a key has. Give such files with a role flag instead:
`--issuer-key FILE`, `--merchant-key FILE`, `--processor-key FILE` (each repeatable, on
`verify` and `pack`). A role-flag file may be a public JWK, a JWKS, a PEM `PUBLIC KEY`
(SubjectPublicKeyInfo) or a PEM X.509 `CERTIFICATE`; from a certificate only the public key is
taken and the certificate itself (dates, issuer, chain, revocation) is **not** validated. Keys
from role flags are pinned exactly like `--trusted-keys`, and both can be combined. Only EC
P-256 (ES256) keys are supported; other curves, RSA and Ed25519 are refused as unsupported.
Private key material (a JWK with `d`, or a PEM private key) is refused everywhere with exit
code 2 and is never echoed.

**Keys are not bound to identities.** A role key proves only that *some* holder of that role
signed. The tool cannot know which key belongs to which merchant, user or agent provider: if
you pin two merchant keys, either one is accepted for any merchant named in the checkout. Pin
only the keys of the parties to this transaction. Every signature PASS names the key that
verified it (label and RFC 7638 thumbprint), and XC04 warns when the checkout and payment
mandates verified under different mandate-issuer keys.

When a token's `kid` matches none of the keys of its role, all keys of that role are tried;
if none verifies, the check FAILs. It is SKIP only when no key at all was supplied for the
role.

### Expected values

`expected.checkout.aud` / `.nonce` and `expected.payment.aud` / `.nonce` are compared with the
closed tokens' `aud` and `nonce` (checks CM14, CM15, PM14, PM15). Without them those checks are
SKIP and not required. Like bundle keys, values inside the bundle are self-asserted, and the
check detail says so. Pin them instead with `--expect-checkout-aud`, `--expect-checkout-nonce`,
`--expect-payment-aud` and `--expect-payment-nonce` (or `verify_bundle(..., expected=...)`);
pinned values take precedence. AP2 defines no normative `aud` values; the upstream samples use
`merchant` and `credential-provider`.

The bundle's `expected` member holds only these `aud` / `nonce` values. The relying-party
expectations (`--expect-agent-key`, `--expect-checkout-id`, `--expect-merchant-id`,
`--expect-total`, `--require-constraint`; checks EX01-EX05), `--require-pinned` and the payment
history (`--prior-total`, `--prior-uses`; check PM39) are not read from a bundle: they are what
the person running the verifier asserts, so they exist only on the `verify` command line (and
as `verify_bundle(expected=..., history=..., require_pinned=...)`), and `pack` does not store
them. The JSON report records which were given in `options` (`require_pinned`,
`expected_relying_party`, `history_supplied`). See
[getting-evidence-in.md](getting-evidence-in.md#i-know-what-the-transaction-should-have-been).

## Loose files

Instead of a bundle, `ap2-evidence verify --checkout-mandate FILE --payment-mandate FILE
[--checkout-receipt FILE] [--payment-receipt FILE] [--trusted-keys FILE]` reads each token
from its own text file (surrounding whitespace is ignored). Files may be UTF-8 (with or without
a BOM) or UTF-16 with a BOM, which is what Windows PowerShell 5.1 writes with `>`. If the
checkout slot holds a payment mandate (or the other way round), the vct checks say the files
look swapped. Keys can then only come from `--trusted-keys` or the role flags, and expected
`aud`/`nonce` values only from the `--expect-*` flags.

## Building a bundle: `pack`

`ap2-evidence pack --out FILE` writes a bundle from the same loose files (`--checkout-mandate`,
`--payment-mandate`, `--checkout-receipt`, `--payment-receipt`), or from the folder the official
AP2 samples write (`--from-ap2-sample-db DIR`). See [getting-evidence-in.md](getting-evidence-in.md)
for worked examples.

- Tokens are stored byte for byte; only surrounding whitespace is removed.
- Public keys (`--trusted-keys`, role flags, or the sample's `*.pub` files) are **not** written
  into the bundle. `--keys-out FILE` writes them as a trusted-keys file for
  `verify --trusted-keys`. `--embed-keys` additionally puts them into the `keys` member, with a
  warning that keys inside a bundle are self-asserted. Keys without either flag are an error,
  so they are never dropped silently.
- `--expect-checkout-aud` etc. and `--note` go into `expected` and `note`.
- A receipt file that holds a JSON object (or a JSON string of an object) instead of a JWT is an
  unsigned receipt, as some sample flows return. It is stored as a JSON object, with the message
  "this flow produced no signed ... receipt" and that an unsigned receipt proves nothing; the
  receipt checks are then SKIP (`unsigned_receipt`) and the verdict INCOMPLETE.
- `--out` and `--keys-out` are not overwritten unless `--force` is given.
- After writing, `pack` prints what was included, what is missing and the `verify` command to
  run next.

With `--from-ap2-sample-db DIR` only these files are opened: `chk_*.sdjwt`, `pay_*.sdjwt`,
`agent_provider_signing_key.pub` (mandate issuer), `merchant_signing_key.pub` (merchant),
`merchant_payment_processor_signing_key.pub` (payment processor) and `ap2_token_store.json`
(for the payment nonce). The `*.pem` files, which hold the samples' private keys, are never
opened. Checkout and payment chains are paired by their hash links (`transaction_id` of the
closed payment mandate equals `checkout_hash` / the hash of `checkout_jwt` of the closed checkout
mandate); when the folder holds more than one pair, or chains that are not linked, `pack`
refuses to guess and asks for `--checkout ID` / `--payment ID`. `expected.payment.nonce` is
taken from the sample's token store, and `expected.*.aud` are the values the sample servers
check (`merchant`, `credential-provider`); the `note` member says that these come from the
sample itself.

## Batch runs

`verify` accepts several bundle paths and/or folders. A folder contributes every `*.json` file
in it (with `--recursive`, also in subfolders; folder links are not followed, loops are
detected, depth is limited to 32 levels and a run to 10,000 files). JSON files without a
`bundle_version` member found in a folder (for example key files or reports) are listed as
skipped; files named explicitly are always verified. Keys, `--skew`, `--at`, the `aud` flags,
`--require-pinned`, `--expect-agent-key`, `--expect-merchant-id` and `--require-constraint`
apply to every bundle; `--expect-*-nonce`, `--expect-checkout-id`, `--expect-total`,
`--prior-total` and `--prior-uses` are refused because they describe one transaction.

Output:

- stdout: one line per bundle with verdict, outcome (`success`, `declined`, `conflicting`, `unknown`: what the
  receipts claim happened; a declined payment can be VERIFIED evidence of the decline; the
  outcome means nothing unless the verdict is VERIFIED, so the text table shows `-` for other
  verdicts, while the JSON and CSV keep the raw value),
  key trust (`pinned`, `bundle`, `mixed`, `none`),
  FAIL and SKIP counts and the first failing (or, for INCOMPLETE, unverified) check IDs, then a
  totals line. With `--format json` the summary is a JSON object fixed by
  `src/ap2_evidence/schemas/batch-summary.schema.json` (`summary_version` `"1"`; members
  `worst_verdict`, `exit_code`, `counts`, `bundles[]` with `file`, `verdict`, `outcome`, `exit_code`,
  `key_trust`, `pass`/`fail`/`warn`/`skip`, `failing_checks`, `unverified_checks`, `report`,
  `error`, and `skipped[]`). An unreadable file is a row with verdict `ERROR` and its `error`.
- `--summary-csv FILE`: the same rows as CSV (columns as in the JSON rows; cells that a
  spreadsheet would treat as a formula are prefixed with `'`).
- `--out-dir DIR`: one full report per bundle, in `--format`, named after the bundle's path
  inside the folder (`sub__bundle.report.md`). When several bundles would get the same name
  (for example `K1_amount_over_cap/bundle.json` and `K2_payee_swap/bundle.json` given one by
  one), the names of their parent folders are put in front (`K1_amount_over_cap__bundle.report.md`);
  a `-2`, `-3` suffix is the last resort (for example the same file given twice). Each line of
  the text summary then names its report file in parentheses after the bundle path.
  If one report cannot be written (for example a path the file system does not accept), the
  bundle keeps its verdict, its row says `report not written: ...` (in the JSON and CSV in
  `error`, with `report` empty), the remaining bundles and the CSV are still processed, and the
  batch exits with code 2.
- `--out FILE`: the summary instead of stdout.

`--out` and `--summary-csv` are replaced if they exist (they are reports, derived from the
evidence). Existing per-bundle reports in `--out-dir` are not replaced: the run stops with exit
code 2, naming the first one, unless `--force` is given. `--out-dir` and the CSV are created
only when at least one bundle could be read. An output that names an input file or another
output is refused. Symbolic links to folders and Windows junctions are not followed with
`--recursive`, and `--out-dir` inside the scanned folder is never scanned; paths longer than
the Windows MAX_PATH limit are read and written (reports, `--summary-csv`, `--out`, `pack`
outputs) through the `\\?\` form. If none of the given paths exists, or no bundle could be read, the run
stops with exit code 2 and one line on stderr, and writes nothing. `pack` never replaces an
existing file without `--force`.

A single bundle given to `verify` must have a `bundle_version` member: a JSON object without one
(for example a trusted-keys file given by mistake) is refused with exit code 2 and a hint to
use `--trusted-keys` or the role-key flags. (The Python API `verify_bundle` still returns a
FAILED report for such input.) A bundle with a wrong `bundle_version` value is verified and
FAILS check B01.

The exit code is the worst over all bundles: 2 if any file is unreadable or any report could
not be written, else 1 if any is FAILED, else 3 if any is INCOMPLETE, else 0. A single bundle path behaves exactly as without
batch support.

## Errors

Unreadable input ends with exit code 2 and one line on stderr in English that names the file,
the reason (file not found, it is a directory, permission denied, not valid UTF-8, a binary
file, not valid JSON at line L, column C, larger than the limit) and what to check. The
operating system's own (localised) error text is never printed, and characters the console
cannot show are written as backslash escapes instead of failing.

## Limits

- Maximum bundle file size 8 MiB; one mandate chain at most 4 MiB; one compact token at most
  1 MiB; at most 8 segments, 512 disclosures per segment and 64 levels of JSON nesting.
- One key file at most 1 MiB and 64 keys per role. A sample folder at most 2,000 chain files.
- JSON with duplicate object keys, `NaN` or `Infinity` is rejected everywhere (bundle, headers,
  payloads, disclosures).
