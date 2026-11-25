# ap2-evidence

**Find out whether your agent-payment evidence holds up before a dispute finds out for you.**

`ap2-evidence` takes the mandates and receipts of one purchase made by an AI agent under [AP2](https://github.com/google-agentic-commerce/AP2) (Agent Payments Protocol, v0.2) and tells you, in plain words, whether they show that the user authorised that payment, which link is broken if they do not, and what could not be checked.

It runs offline, has one dependency, and is free (Apache-2.0). Independent project, not affiliated with Google, the FIDO Alliance or the AP2 maintainers. Version 0.1, alpha.

## Why this exists

An agent can overspend while every signature is valid. The user allows "up to USD 200 at this merchant", the merchant's checkout says USD 199, and the agent signs a payment of USD 250 with its own, correctly delegated key. A verifier that only checks signatures passes it. This one reports:

```text
VERDICT: FAILED (keys: supplied in bundle, not pinned)
...
  Finding: The agent paid USD 250.00 to Demo Merchant for checkout 'demo-checkout-0001'. The user's
  mandate allowed at most USD 200.00, and the merchant's signed checkout was for USD 199.00.

  What this means: This bundle cannot be used to show that the payment was authorised. The agent the
  user authorised signed this payment itself, so the agent provider cannot claim its agent stayed
  within the user's limit or paid what the merchant's checkout asked for.

  What to do next:
  - Ask the agent provider why its agent approved a payment above the user's limit.
  - Ask the agent provider why the amount paid differs from the merchant's checkout total.
  ...
```

(`...` marks lines left out here.) The report goes on to say where the keys came from, name the two checks that failed (`PM32`, `XC01`) and where to look. "Keys: supplied in bundle" is explained under [Verdicts](#verdicts).

The second reason is timing. Evidence problems show up weeks after the purchase, when someone disputes it, and by then they cannot be repaired: the receipt was never stored, the key has rotated, a withheld part of the mandate is gone. Checking evidence when it is captured costs one command.

## Who it is for

| You are | What you get |
| :-- | :-- |
| Building an integration with AP2, or with UCP (Universal Commerce Protocol) and its AP2 mandate extension: merchant platform, payment provider, agent platform | A check, in CI or by hand, that the evidence your system emits can be verified by someone else. See [Use it in CI](#use-it-in-ci). |
| Handling disputes or risk | A report that leads with what happened, what it means and what to ask for next, in text, Markdown or a printable HTML page. No knowledge of SD-JWT needed. |
| Working on the specification or on another verifier | An independent implementation with [86 documented checks](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/checks.md), [notes on where the spec, schemas and SDK disagree](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/spec-notes.md), and a [cross-implementation results page](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/cross-implementation.md). |

## What it has been tested against

- **Output of the official AP2 SDK and samples, unmodified.** Mandates and receipts minted by the upstream Python SDK and by the upstream human-not-present card sample (commit `e1ea56d`, v0.2.0) verify as `VERIFIED`. Three variants whose mandates carry a cumulative budget are `INCOMPLETE` until the earlier spending is supplied and `VERIFIED` with it, and a variant presented with its constraints redacted is `FAILED`, as it should be. Of 21 altered variants of the card transaction, 20 are reported as `FAILED`. The last one is authentic evidence in which the payment processor's receipt says the payment was declined while the merchant's receipt says the order succeeded; it is reported as `VERIFIED - RECEIPTS DISAGREE`. They are in [tests/fixtures/upstream-sdk](https://github.com/lifst-coder/ap2-evidence/tree/main/tests/fixtures/upstream-sdk) with the scripts that made them.
- **Other people's test vectors.** The tool was run over vectors published by other AP2 implementers. Every disagreement is listed with our position and the evidence in [docs/cross-implementation.md](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/cross-implementation.md). Several of them were bugs here and are fixed.
- **Deliberate sabotage of its own code.** The test suite is checked by mutating the verifier and confirming that a test fails.

**Not tested against production traffic.** To our knowledge nobody has published a production AP2 transaction yet. If you have sandbox or pilot evidence, running it through this tool and [reporting what happens](#something-looks-wrong) is the most useful contribution there is.

## Install

Python 3.10 or newer. With [pipx](https://pipx.pypa.io), one command puts `ap2-evidence` on your PATH:

```bash
pipx install git+https://github.com/lifst-coder/ap2-evidence
```

Without pipx, install into a virtual environment.

macOS and Linux:

```bash
python3 -m venv .venv
```

```bash
.venv/bin/python -m pip install git+https://github.com/lifst-coder/ap2-evidence
```

```bash
source .venv/bin/activate
```

Windows (PowerShell or Command Prompt):

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python -m pip install git+https://github.com/lifst-coder/ap2-evidence
```

On Windows, write `.venv\Scripts\ap2-evidence` wherever the commands below say `ap2-evidence`. That works in every shell and needs no activation script.

Check it:

```bash
ap2-evidence --version
```

Some examples below read files from this repository (`examples/`, `tests/fixtures/`). To run those, get a copy and run them from its root:

```bash
git clone https://github.com/lifst-coder/ap2-evidence
```

## Five-minute tour

**1. A valid purchase.** The demo creates fresh keys, builds a complete AP2 v0.2 transaction in the upstream wire format, and verifies it.

```bash
ap2-evidence demo
```

**2. Four ways it can be wrong.**

```bash
ap2-evidence demo --tamper amount
```

| `--tamper` | What happens | Checks that fail |
| :-- | :-- | :-- |
| `amount` | The agent validly signs USD 250.00 when the user allowed at most USD 200.00 and the checkout total is USD 199.00. Every signature is valid. | `PM32`, `XC01` |
| `receipt` | A validly signed receipt that belongs to a different mandate. | `PR04` |
| `disclosure` | An allowed-merchant entry is swapped after the mandate was issued. | `CM04` (three more follow from it and are shown as consequences) |
| `key` | The closed payment mandate is signed by a key other than the one the user bound. | `PM08` |

**3. A report you can hand to someone.**

```bash
ap2-evidence demo --tamper amount --format html --out report.html
```

Open `report.html` in a browser. It is one self-contained file with no scripts and no network requests, and it prints to PDF. (The command exits with code 1 because the verdict is `FAILED`; the file is written all the same.)

**4. Real output of the official AP2 sample** (run from the root of a clone of this repository):

```bash
ap2-evidence verify tests/fixtures/upstream-sdk/samples_hnp_card/bundle.json --trusted-keys tests/fixtures/upstream-sdk/samples_hnp_card/trusted_keys.json
```

**5. What a check means.**

```bash
ap2-evidence explain PM32
```

## Verdicts

| Verdict | Meaning | Exit code |
| :-- | :-- | :-- |
| `VERIFIED` | Every required check passed. | 0 |
| `VERIFIED - PAYMENT DECLINED` | The evidence is authentic and the payment processor's receipt says the payment was declined. Nothing in it shows money moved. | 0 |
| `VERIFIED - RECEIPTS DISAGREE` | The evidence is authentic, but one receipt reports success and the other an error: money may have moved without an order, or an order may have been placed without payment. The report says which. | 0 |
| `FAILED` | At least one link is broken. The report names it, says what it means and where to look. | 1 |
| `INCOMPLETE` | No check failed, but something required could not be checked: a missing receipt, a missing key, a withheld part of a mandate, a budget with no spending history. The report lists exactly what. It is not a pass. | 3 |

Exit code 2 means the input could not be read (missing file, not JSON, wrong command line).

The two suffixes can follow any verdict (`FAILED - RECEIPTS DISAGREE`, `INCOMPLETE - PAYMENT DECLINED`): they report what the receipts say, the verdict reports whether the evidence holds. A receipt is used for this only when its own signature, required fields, reference and time checks passed. A warning never changes the verdict, but a `VERIFIED` finding lists every warning, so read the finding and not only the first word.

The verdict line always says where the keys came from. `keys: pinned` means you gave the keys to the tool yourself. `keys: supplied in bundle` means they came inside the bundle and are only as trustworthy as whoever assembled it. Add `--require-pinned` to make such signatures count as not verified.

## Verify your own evidence

You never need to write the bundle file by hand. The full guide is [docs/getting-evidence-in.md](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/getting-evidence-in.md).

**You ran the official AP2 sample.** Point `pack` at the folder the sample wrote (`.temp-db`):

```bash
ap2-evidence pack --from-ap2-sample-db .temp-db --keys-out sample-keys.json --out sample.bundle.json
```

It finds the mandate chains, pairs them by their hash link, takes the public keys and the payment nonce, never opens the private key files, and tells you what is missing and what to run next. The samples do not store their receipts, so the verdict is `INCOMPLETE` until you add them with `--checkout-receipt` and `--payment-receipt`.

**You have token files and keys.** Keys can be JWK, JWKS, PEM public keys or PEM certificates.

```bash
ap2-evidence pack --checkout-mandate checkout.txt --payment-mandate payment.txt --checkout-receipt checkout-receipt.jwt --payment-receipt payment-receipt.jwt --issuer-key issuer.pem --merchant-key merchant.pem --processor-key processor.pem --keys-out keys.json --out purchase.bundle.json
```

`pack` does not overwrite an existing bundle or keys file unless you add `--force`. The keys go to `keys.json`, not into the bundle, so that the bundle cannot vouch for itself.

**Then verify, with the keys.**

```bash
ap2-evidence verify purchase.bundle.json --trusted-keys keys.json
```

Leave out what you do not have. A missing artifact or key makes the verdict `INCOMPLETE` and the report says what to ask for. Verifying without `--trusted-keys` gives `INCOMPLETE` too, because no signature of the issuer, merchant or processor can then be checked.

**You know what the purchase should have been.** A merchant or processor usually does. Say so, and the tool checks the evidence against it. Amounts are written in minor units, so `9998 USD` is USD 99.98:

```bash
ap2-evidence verify purchase.bundle.json --trusted-keys keys.json --expect-merchant-id merchant_1 --expect-total 9998 USD --require-constraint payment.amount_range
```

**The mandate has a budget or a use limit.** One bundle shows one payment, so the tool needs to be told what was already spent and how often the mandate was already used. These are your figures, and the report says so:

```bash
ap2-evidence verify purchase.bundle.json --trusted-keys keys.json --prior-total 5002 USD --prior-uses 0
```

Here `5002 USD` says USD 50.02 was already paid under this mandate, and `0` that no earlier payment counts against a use limit. Without these figures, a mandate with a cumulative limit is `INCOMPLETE`, because one payment alone cannot show the limit was respected.

**Many purchases at once.**

```bash
ap2-evidence verify evidence-folder --trusted-keys keys.json --out-dir reports --summary-csv summary.csv
```

One summary line per bundle, one report per bundle in `reports`, and the exit code of the worst result. Reports already in that folder are not replaced unless you add `--force`.

## Use it in CI

If your system emits AP2 evidence, make "someone else can verify it" a test. In a GitHub workflow:

```yaml
- uses: lifst-coder/ap2-evidence@v0.1.0
  with:
    bundles: test-output/evidence
    trusted-keys: test-output/keys.json
    require-pinned: "true"
```

`bundles` takes files or folders separated by spaces or new lines, so paths must not contain spaces.

The job fails when a bundle is `FAILED` or `INCOMPLETE` (set `fail-on-incomplete: "false"` to allow incomplete ones), and the summary appears on the run page. Anywhere else, `ap2-evidence verify` and its exit code do the same.

## What it checks

86 checks with stable IDs. Every result that is not a pass carries a machine-readable reason such as `amount_above_max`, a plain sentence, and a suggested next step. The catalogue is in [docs/checks.md](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/checks.md).

| Family | IDs | Covers |
| :-- | :-- | :-- |
| Bundle | `B01`-`B03` | The bundle is readable, which artifacts are present, supplied keys are valid P-256 keys. |
| Checkout mandate | `CM01`-`CM22`, `CM30`-`CM35` | The chain parses; ES256 only; issuer signature; every disclosure resolves exactly once; nothing is withheld that could hide a limit; the agent key in `cnf.jwk`; the closed mandate is signed by that key and bound to the open one; `aud` and `nonce`; order of events; `checkout_hash` equals the hash of the merchant's signed checkout; merchant signature; checkout status; allowed merchants; allowed line items. |
| Payment mandate | `PM01`-`PM22`, `PM30`-`PM39` | The same chain checks, plus: the payment is for this checkout; amount range; allowed payees; payment instruments; payment initiators; execution date; budget and recurrence (with history); pre-set claims unchanged. |
| Across artifacts | `XC01`-`XC04` | Paid amount equals the checkout total; the payee is the checkout merchant (and is not merely the same id under another name); both mandates bind the same agent key and issuer. |
| Your expectations | `EX01`-`EX05` | The agent key, checkout id, merchant id, total and required constraints you said to expect. |
| Checkout receipt | `CR01`-`CR07` | Parses; merchant signature; required fields; refers to the closed checkout mandate; outcome; not issued before the mandate. |
| Payment receipt | `PR01`-`PR07` | The same for the payment processor's receipt. |

Hostile input (truncated tokens, bad base64, duplicate JSON keys, `alg: none`, oversized or deeply nested data, constraints built to exhaust the CPU) ends as a failed or skipped check or a one-line error. It does not crash or hang.

## What it does not do

- **It does not know whose key a key is.** There is no key discovery in AP2 v0.2. Trust in the issuer's, merchant's and processor's keys has to come from you, and you should pin only the keys of the parties to this transaction.
- **It cannot see what was withheld.** If an open mandate hides a constraint, the verdict is `FAILED`. Any other hidden part makes it `INCOMPLETE`, because a withheld limit and a harmless decoy look the same. Store open mandates with all their disclosures.
- **`INCOMPLETE` is not a mild `FAILED`, and it is not a pass.** Whoever assembles a bundle can sometimes turn a failure into `INCOMPLETE` by leaving things out: presenting a mandate with fewer disclosures than were issued makes the link between payment and checkout impossible to recompute, and that looks the same as a payment that points at a different checkout. The report says so. Treat `INCOMPLETE` as "ask for the missing piece", never as "probably fine".
- **One bundle, one payment.** Use of the same mandate for a second payment is invisible, and the figures you give with `--prior-total` and `--prior-uses` are taken on your word.
- **No revocation**, **no `x5c` certificate chains** (a token relying on one is reported as not verified unless you supply the key), **no delegation chains longer than open plus closed** (a single directly signed mandate, as in the human-present flow, is supported), no algorithms other than ES256, no AP2 v0.1 Intent and Cart mandates.
- **Nothing after the receipts:** delivery, refunds, chargebacks. And nothing outside AP2: the x402 settlement layer, card-network messages.
- **No expiry check against today's date.** Evidence is always expired by the time it is examined, so only the order of events is checked. Use `--at` to test validity at a specific moment.
- **A flow that produced no signed receipt** (the upstream x402 and human-present samples return an unsigned object) is `INCOMPLETE`: an unsigned receipt proves nothing.

A `VERIFIED` verdict means the artifacts are consistent and correctly signed by the keys given. It is not legal advice and not a decision on a dispute.

## Where AP2's prose, schemas and SDK disagree

Building this against the upstream repository turned up places where the specification text, the JSON schemas and the SDK say different things, for example which bytes a receipt `reference` hashes. Each one, the choice this tool makes, and the upstream file and line are in [docs/spec-notes.md](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/spec-notes.md). If you implement AP2 and read one of them differently, please say so.

## Something looks wrong

A bundle that fails when you think it should pass, or passes when it should fail, is the most useful thing you can report. Run the same command with `--format issue`:

```bash
ap2-evidence verify purchase.bundle.json --trusted-keys keys.json --format issue
```

Keep every option you used, the keys in particular. It prints a short block with the version, the verdict and the checks that did not pass. Paste it into a [verification issue](https://github.com/lifst-coder/ap2-evidence/issues/new?template=verification_failure.yml). Use test or sandbox data only: never production tokens, never private keys.

- Considering this for a real system? [Tell us what you need](https://github.com/lifst-coder/ap2-evidence/issues/new?template=evaluation.yml). It takes two minutes and decides what gets built next.
- Other bugs and ideas: [issues](https://github.com/lifst-coder/ap2-evidence/issues/new/choose).
- A forged bundle that comes out `VERIFIED`: report it privately, see [SECURITY.md](https://github.com/lifst-coder/ap2-evidence/blob/main/SECURITY.md).

## Use from Python

```python
import json
from pathlib import Path

from ap2_evidence import load_trusted_keys, verify_bundle

bundle = json.loads(Path("purchase.bundle.json").read_text(encoding="utf-8"))
keys = load_trusted_keys(Path("keys.json").read_text(encoding="utf-8"))
report = verify_bundle(bundle, trusted_keys=keys)

print(report.verdict)  # "VERIFIED", "FAILED" or "INCOMPLETE"
print(report.outcome)  # "success", "declined", "conflicting" or "unknown"
Path("report.html").write_text(report.to_html(), encoding="utf-8")
Path("report.json").write_text(report.to_json(), encoding="utf-8")
```

`verify_bundle` also takes `expected=`, `history=`, `require_pinned=`, `at=` and `skew=`, the counterparts of the command-line options.

Output formats are described in [docs/output-formats.md](https://github.com/lifst-coder/ap2-evidence/blob/main/docs/output-formats.md). The JSON report and the bundle format are fixed by JSON Schemas shipped in the package (`ap2_evidence/schemas/`).

## Development

```bash
python -m venv .venv
```

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

```bash
.venv/bin/python -m pytest -q
```

Lint and type checks: `ruff check .`, `ruff format --check .`, `mypy`. On Windows replace `.venv/bin/python` with `.venv\Scripts\python`. On Windows with Python 3.10 to 3.12, an editable install does not work from a folder whose path contains non-ASCII characters; the tests still run, because they import from `src` directly. See [CONTRIBUTING.md](https://github.com/lifst-coder/ap2-evidence/blob/main/CONTRIBUTING.md).

## License

Apache-2.0. Sample tokens from the AP2 documentation, evidence minted with the AP2 SDK, and test vectors from other projects are included under their own licences; see `NOTICE`.
