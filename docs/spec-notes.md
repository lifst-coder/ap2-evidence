# Spec notes: where upstream disagrees with itself, and what this tool does

AP2 v0.2 is described in three places that do not always agree: the prose specification
(`docs/ap2/*.md`), the JSON schemas (`code/sdk/schemas/**`) and the Python SDK and samples
(`code/sdk/python/ap2/sdk/**`, `code/samples/**`). This page lists every point where
ap2-evidence had to choose, what it chose, and why.

All paths and line numbers refer to github.com/google-agentic-commerce/AP2 at commit
`e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (2026-04-29). The clone is shallow and has no tags,
so it cannot be confirmed that this commit is byte-identical to the `v0.2.0` release; its
`CHANGELOG.md:3-15` records nothing after 0.2.0.

General rule: when prose and SDK disagree and both forms are unambiguous, **accept both and say
in the check detail which form was found**. When accepting both would let a forgery through,
pick the stricter reading and say so.

## A. Receipt `reference`: which bytes are hashed

- Prose: "a hash over the final SD-JWT in the chain. It is calculated in the same manner as
  `sd_hash`" with `_sd_alg` (`docs/ap2/agent_authorization.md:509-513`); repeated in the dispute
  rules (`docs/ap2/specification.md:354-360`). `sd_hash` covers the issuer-signed JWT **and its
  disclosures** (`code/sdk/python/ap2/sdk/sdjwt/common.py:53-57, 170-172`).
- SDK and every sample: SHA-256 of the **leaf issuer-signed JWT only**
  (`code/sdk/python/ap2/sdk/mandate.py:402-417`, `code/sdk/python/ap2/sdk/README.md:103-109`),
  always SHA-256 (`code/sdk/python/ap2/sdk/utils.py:34-36`).

**Choice (CR04/PR04):** both are PASS. The SDK form is reported as "upstream SDK form"; the
prose form (sha-256, or the leaf's `_sd_alg`) as "prose form". Anything else FAILs and the
report shows both expected values. If the reference matches the *open* mandate or the other
closed mandate instead, the detail says so. Both forms bind the agent-signed JWT, so accepting
both does not weaken the link.

## B. Receipt outcome field: `status` vs `result`

- Schemas / SDK / samples: `status` in `Success` / `Error`
  (`code/sdk/schemas/ap2/checkout_receipt.json:8-11`, `payment_receipt.json:8-11`,
  `types/receipt_status.json:7-10`), with `order_id` (checkout) or `psp_confirmation_id` +
  `network_confirmation_id` (payment) required on Success and `error` + `error_description` on
  Error; `payment_id` always (payment).
- Prose Mandate Receipt: `result` in `success` / `error`, `error` required only on error
  (`docs/ap2/agent_authorization.md:503-519`).

**Choice (CR03/PR03, CR05/PR05):** the schema form is the normal case. A receipt with `result`
and no `status` is accepted with a WARN naming the prose form; then only `iss`, `reference` (and
`error` for an error result) are required. Members whose value is `null` count as absent,
because the samples sign `model_dump()` output with `"error": null` on success
(`code/samples/python/src/roles/merchant_agent_mcp/server.py:968-972`). An authentic `Error` /
`error` receipt is a **WARN** (`declined`) on CR05/PR05, not a FAIL: the evidence is intact and
documents a declined step (three independent third-party suites treat it the same way). The
check's `actual` is the machine-readable outcome (`success` or `declined`). Integrity problems
stay FAIL (signature, reference). A receipt whose outcome is `Success` / `success` but whose
`error` or `error_description` is a non-empty value FAILs CR05/PR05 (`success_with_error`);
absent, `null` and `""` count as no error.

Both forms count the same way for the report's `outcome` (`success` / `declined` /
`conflicting`): a receipt counts when its signature, required fields, reference and time checks
passed (CR02/PR02, CR03/PR03, CR04/PR04, CR06/PR06). For the prose form, CR03/PR03 is the
`prose_receipt_form` WARN and, because the prose form defines no `iat`, CR06/PR06 is not
applicable; neither stops the receipt from counting. The issuer plausibility checks CR07/PR07
are WARN only and never part of that gate: a receipt's `iss` is self-declared, and what matters
is which key signed it.

**Unsigned receipts (CR01/PR01).** The official x402 and human-present sample flows return a
plain JSON object as their "receipt". A JSON object in `checkout_receipt` / `payment_receipt`
(or a string holding a JSON object) is a **required SKIP** (`unsigned_receipt`): it proves
nothing, but it is not evidence of tampering either. Other non-string types still FAIL B01.

## C. The pretty-printed JSON in the docs does not match the tokens

The "decoded" JSON next to each sample token contains transcription errors: different `cnf.jwk`
coordinates (`docs/ap2/checkout_mandate.md:228-229`, `docs/ap2/payment_mandate.md:335-336`),
wrong digests and salts (`checkout_mandate.md:184, 219, 272, 311-314`,
`payment_mandate.md:297, 380`), a completely different checkout payload
(`checkout_mandate.md:277-304`) and four bullets instead of three in the card description
(`payment_mandate.md:396`).

**Choice:** only the encoded tokens are used (`tests/fixtures/official/`, extracted by script
from `checkout_mandate.md:244, 328, 494` and `payment_mandate.md:351, 408, 534`). The closed
tokens verify only with the key coordinates in the tokens. With the tokens, all hash vectors in
the test-suite reproduce and no check FAILs.

## D. `vct` values with and without the `.1` suffix

Schema `description`s say e.g. "MUST be 'mandate.checkout'" while `const` is
`mandate.checkout.1` (`code/sdk/schemas/ap2/checkout_mandate.json:15-16`,
`payment_mandate.json:17-18`, `open_checkout_mandate.json:15-16`,
`open_payment_mandate.json:15-16`); the SDK README lists un-suffixed values
(`code/sdk/python/ap2/sdk/README.md:113-118`).

**Choice (CM05/CM11/PM05/PM11):** exact match on the suffixed form, as the normative text
requires ("Implementations MUST match the exact vct string, including the version suffix",
`docs/ap2/specification.md:138-143`). Un-suffixed values FAIL.

## E. Field-name slips

- `allowed_merchants` vs `allowed` (`code/sdk/python/ap2/sdk/README.md:129` vs
  `open_checkout_mandate.json:60-66`): we read `allowed`.
- `checkout_reference` in docstrings (`constraints.py:141-146`, `payment_mandate_chain.py:49-50`)
  vs `conditional_transaction_id` in the schema: we read `conditional_transaction_id`, and compare
  it with the **open checkout mandate** hash as the SDK code does (`constraints.py:157-169`), not
  with `transaction_id` as the docstring claims.
- `mandate.payment.reference` (`security_and_privacy_considerations.md:20-21`) vs
  `payment.reference`: we use `payment.reference`; the longer name is an unknown constraint.
- `kb-sd-jwt` (`docs/ap2/flows.md:149`) vs `kb+sd-jwt`: CM07/PM07 accept `kb-sd-jwt` with a WARN,
  as the SDK accepts both (`code/sdk/python/ap2/sdk/sdjwt/kb_sd_jwt.py:31-32`).

## F. Amount units

- `payment.amount_range` `min`/`max` are integer minor units in the schema
  (`open_payment_mandate.json:131-142`) and in the sample token (`max: 20000`); the doc example
  uses `100.50` (`docs/ap2/payment_mandate.md:183-189`).
- `payment.budget.max` is a `number` without unit (`open_payment_mandate.json:260-263`); the SDK
  multiplies by 100, i.e. treats it as major units (`constraints.py:304-308`).

**Choice:** `amount_range` is minor units and must be an integer; a decimal `max`/`min` makes the
constraint malformed (PM32 FAIL). `budget.max` is read in major units like the SDK, but converted
with the currency's ISO 4217 exponent instead of a fixed 100 (KRW and JPY have 0 decimals, KWD
and BHD 3), using exact decimal arithmetic (the SDK truncates with `int()`). Currencies not in
our exponent table are assumed to have 2 decimals and the detail says so. `payment_amount.amount`
must be a JSON integer; `199.0` is rejected.

## G. `conditional_transaction_id`: which bytes

Prose and schema only say "hash" / "Digest of the associated Open Checkout Mandate"
(`docs/ap2/payment_mandate.md:230-234`, `open_payment_mandate.json:159-162`). The samples compute
the sd_hash form over the open checkout token **with all disclosures as issued**
(`code/samples/python/src/roles/shopping_agent_v2/shopping_agent/mandate_tools.py:392`); the
merchant recomputes it from the first chain segment **as presented**
(`code/samples/python/src/roles/merchant_agent_mcp/server.py:932-935`). The two differ whenever
the agent presents fewer disclosures than were issued, which the spec requires for privacy
(`docs/ap2/specification.md:242-243`).

**Choice (PM31):** PASS if it equals the sd_hash form of the open checkout segment **as
presented** (sha-256, or the payment token's `_sd_alg` as the prose says); PASS with a note if it
equals the hash of the open checkout's issuer-signed JWT only (WARN instead when the open checkout
mandate withholds constraints or claims, see R2). Otherwise:

- if the open checkout segment as presented has digests without a disclosure (entries of an
  allow-list withheld, or any other withheld claim) and is otherwise intact, the hash of the
  token as issued cannot be recomputed, so a mismatch is not evidence of a different checkout:
  **required SKIP** (`reference_unverifiable_withheld`), detail asking for the open checkout
  mandate as issued;
- if nothing is withheld (or the segment is damaged, e.g. a disclosure was swapped, which CM04
  reports), **FAIL** (`reference_mismatch`).

The demo builder computes `conditional_transaction_id` over the token as issued, like upstream
(`DemoBuilder.reference_cti = "sd_hash"`); `"presented"` reproduces a presenter-side reference
over the narrowed token. The upstream-minted `v_redact` fixture stays FAILED (CM34/CM35); its
PM31 is now this SKIP.

## H. `checkout_hash` is never recomputed upstream

The SDK only compares `checkout_hash` with a caller-supplied value
(`code/sdk/python/ap2/sdk/checkout_mandate_chain.py:92-100`) and never verifies the
`checkout_jwt` signature (`:112-125`); the HNP sample merchant passes no expected value
(`merchant_agent_mcp/server.py:880-883`). The spec requires both
(`docs/ap2/specification.md:311-312, 352-353`).

**Choice:** CM31 recomputes `checkout_hash` from the disclosed `checkout_jwt`; CM32 verifies the
merchant signature on it; PM30 compares `transaction_id` with both `checkout_hash` and the
recomputed hash.

## I. Hash algorithm agility

Prose ties `checkout_hash`, `conditional_transaction_id` and `reference` to `_sd_alg`
(`docs/ap2/checkout_mandate.md:26-28`, `payment_mandate.md:232-234`,
`agent_authorization.md:512-513`); the SDK hard-codes SHA-256 for those three
(`code/sdk/python/ap2/sdk/utils.py:34-36`) and honours `_sd_alg` only for disclosure digests,
`sd_hash` and `issuer_jwt_hash` (`common.py:156-182`).

**Choice:** disclosure digests and `sd_hash` / `issuer_jwt_hash` use `_sd_alg` (sha-256, sha-384,
sha-512; anything else FAILs CM04/PM04/CM10/PM10). For `checkout_hash`, `transaction_id`,
`conditional_transaction_id` and receipt `reference`, SHA-256 is tried first and the token's
`_sd_alg` second, and the detail says which one matched. All upstream samples use sha-256.

## J. `constraints` required or optional, and `contains`

Prose: `constraints` OPTIONAL, `cnf` required while open (`agent_authorization.md:437-442`).
Schemas: required, and must contain a `checkout.line_items` / `payment.reference` constraint
(`open_checkout_mandate.json:7-11, 32-34`; `open_payment_mandate.json:7-11, 50-52`). The SDK
does not enforce `contains` and its own tests build open payment mandates without
`payment.reference` (`code/sdk/python/ap2/tests/issuer_jwt_hash_tests.py:48-53`).

**Choice (CM21/PM21):** a missing `constraints` array or a missing `contains` constraint is a
WARN ("the agent was not limited"), not a FAIL; a `constraints` member that is not an array of
objects with a string `type` FAILs. `cnf.jwk` is required on an open mandate (CM06/PM06 FAIL).

## K. `cnf` in a closed mandate

The OpenID4VP example puts `cnf` inside a `mandate.checkout.1` payload
(`agent_authorization.md:198-211`); the closed schema has no `cnf`, and the SDK rejects a terminal
`kb+sd-jwt` whose delegate payload has one (`kb_sd_jwt.py:135-137`).

**Choice (CM12/PM12):** `cnf` in a closed mandate presented as a key-binding hop (two segments)
FAILs, as in the SDK. A directly signed one-segment closed mandate (human present) may carry
`cnf`: it is a root token, and the SDK's root handling (`chain.py:147-159`) has no such rule;
the prose example above is exactly that shape.

## L. Root token shape and `typ`

The doc tokens' root header has `typ: example+sd-jwt`, a library default; the SDK sets no root
`typ` (`code/sdk/python/ap2/sdk/sdjwt/sd_jwt.py:53-59`) and does not check it. No normative value
exists. The prose "Trusted Agent Provider" example has top-level `iss`/`vct`
(`agent_authorization.md:319-327`); SDK tokens do not.

**Choice:** the root `typ` is not checked. Top-level `iss` is optional and only shown in the
evidence section. The mandate object is taken from `delegate_payload` (each element an
array-element disclosure); if a payload has no `delegate_payload` but a top-level `vct`, the
payload itself is treated as the mandate, as the SDK does (`chain.py:160, 175`).

## M. `aud` / `nonce`

Creation requires both (`kb_sd_jwt.py:62-63`); verification requires only `iat` and compares
`aud`/`nonce` only when the verifier supplies expected values (`common.py:300-311`).

**Choice (CM14/CM15/PM14/PM15):** RFC 9901 section 4.3 requires `aud` and `nonce` in a KB-JWT,
and every token the SDK creates has them (all upstream-minted fixtures and the six official doc
tokens do). A closed key-binding token without a non-empty string `aud` / `nonce` therefore
FAILs (`aud_missing` / `nonce_missing`) whether or not an expected value is given. `aud` may also
be a JSON array of strings (RFC 7519); it matches when it contains the expected value. With an
expected value (pinned, or `expected.*` from the bundle) the value is compared; without one the
check is SKIP and not required. KB `iat` is required (CM16/PM16 FAIL without an integer `iat`).

## N. Merchant matching

Prose: the merchant / payee "MUST be present in the allowed array"
(`docs/ap2/payment_mandate.md:85-87`, `checkout_mandate.md:56-58`). Doc examples lack the
required `id` (`checkout_mandate.md:65-66`). SDK: match by `id` when both sides have one, else by
`name` + `website`, both non-empty (`constraints.py:45-66`).

**Choice (CM34, PM33, XC02):** the SDK rule. For `checkout.allowed_merchants` and
`payment.allowed_payees`, only revealed entries count; no revealed entry FAILs (prose:
`checkout_mandate.md:56-58`). When the payee matches by `id` but its `name` or `website`
differs (a payee "Evil Corp" carrying the merchant's id), the verdict still follows the SDK, but
XC02 (against the merchant-signed checkout) and PM33 (against the issuer-signed allowed entry)
WARN with `payee_details_differ`. XC02's `expected` is the merchant-signed description and
`actual` the agent-signed one, so a report can prefer the merchant-signed name.

## N2. Checkout status

UCP defines `incomplete`, `requires_escalation`, `ready_for_complete`, `complete_in_progress`,
`completed`, `canceled`. Every upstream-minted checkout and every official doc token signs
`incomplete` (`merchant_agent_mcp/server.py:733`, `merchant_agent/tools.py:191`). **Choice
(CM33):** `canceled` FAILs (`checkout_canceled`); `incomplete`, `ready_for_complete`,
`complete_in_progress` and `completed` PASS; `requires_escalation` WARNs (`checkout_not_final`);
a value outside UCP's list stays a malformed checkout (FAIL). A canceled checkout does not
block CM34/CM35 (the payload itself is readable).

## O. `payment.allowed_pisps` is not selectively disclosable

`allowed_pisps.allowed` is not marked SD (`open_payment_mandate.json:236-242`) while the other
`allowed` arrays are. **Choice (PM35):** we resolve whatever disclosures are present anyway, so an
SD `allowed_pisps` also works. Matching requires `legal_name`, `brand_name` and `domain_name` to
be equal, as the SDK does (`constraints.py:268-273`). A constraint with no `pisp` in the closed
mandate FAILs (SDK: "Missing PISP in closed mandate").

## P. Human-present (direct) mandates

The HP samples sign the closed mandate directly as a root SD-JWT with no `aud`/`nonce`/`sd_hash`
(`code/samples/python/src/roles/shopping_agent/tools.py:165-176, 207-220`).

**Choice:** a one-segment chain is a directly signed closed mandate. Root checks apply (the
signer is the `mandate_issuer` role); key-binding checks (CM07-CM10, CM14-CM16) and open-mandate
checks are SKIP and **not required**, with a note. Constraint checks then do not apply.

## Q. AP2 v0.1 leftovers

`IntentMandate`, `CartMandate` and a different `PaymentMandate` class survive in
`code/sdk/python/ap2/models/mandate.py:27-203` and the Go samples. **Choice:** not supported; a
`vct` that is not one of the four v0.2 values FAILs the vct checks.

## R. Line items: prose vs SDK (not in the upstream inventory's list, found while implementing)

- Prose (`docs/ap2/checkout_mandate.md:83-105`): the constraint is met when "the maximal flow
  equals the total constraint `items` quantity **and** the total checkout `items` quantity", i.e.
  every requirement must be filled exactly. The prose example says a checkout with only "Red
  Style" is invalid (`:139-143`).
- SDK (`code/sdk/python/ap2/sdk/max_flow_helper.py:14-121`): only checks that every checkout
  unit can be assigned within the requirement quantities; under-filled requirements pass. A
  checkout with only "Red Style" passes.
- SDK: a requirement whose resolved `acceptable_items` is empty is a **wildcard** that accepts any
  item (`max_flow_helper.py:36-44`). After selective disclosure, an array whose entries are all
  undisclosed also resolves to empty, so in the SDK hiding every acceptable item turns the
  requirement into "anything". The prose says an item matches only if it is in the **revealed**
  `acceptable_items` (`checkout_mandate.md:87-88`).

**Choice (CM35):** FAIL when a checkout unit cannot be assigned (both agree). WARN, not FAIL,
when assignment works but a requirement is not completely filled (prose-only rule; failing would
contradict the reference implementation). A **literally empty** `acceptable_items` array is a
wildcard, as in the SDK, and the detail says so; an array whose entries are all **undisclosed**
matches nothing (prose), because otherwise an agent could widen its authority by withholding
disclosures. The tool can tell the two apart because it counts undisclosed `{"...": digest}`
placeholders. An empty checkout (no line items) FAILs a line_items constraint
(`empty_checkout`), as the SDK does (`constraints.py:413-416`).

**Limits.** The assignment is a maximum flow on a bipartite graph. Requirements with identical
acceptable sets are merged and the flow is computed with Dinic's algorithm (only wildcard
requirements: no flow needed). Hard limits keep any bundle fast (the pre-audit Edmonds-Karp took
113 s on a 0.5 MB bundle): at most 1000 checkout lines and 1000 requirements, at most 250 000
lines x requirements, at most 32 `checkout.line_items` constraints per open mandate, and a work
budget of 2 000 000 edges built or scanned for all line-item matching of one bundle. Beyond a
limit CM35 is a **required SKIP** (`too_large`), never PASS; every accepted input finishes in
well under a second.

## R2. Withheld disclosures widen authority (CM22 / PM22)

An open mandate can make any claim selectively disclosable: whole `constraints` elements, the
`constraints` claim itself, or pre-set claims such as `payment_amount` (the upstream SDK's own
tests make `payment_amount` and `payee` SD, `code/sdk/python/ap2/tests/issuer_jwt_hash_tests.py:107-111`).
The agent chooses which disclosures to present (`docs/ap2/specification.md:242-243`) and signs
`sd_hash` over exactly what it presents, so the binding check cannot notice a dropped
disclosure. If a verifier treats a withheld constraint as "no such constraint", the agent can
remove any limit the user set: an amount range, the allowed items, a pre-set amount. RFC 9901
decoy digests (`docs/ap2/security_and_privacy_considerations.md:124-125`) are indistinguishable
from withheld claims.

**Choice (CM22/PM22, required):** for both segments of both chains:

- An undisclosed `{"...": digest}` placeholder inside the open mandate's `constraints` array is
  a constraint the verifier cannot evaluate: **FAIL** (`hidden_constraint`), because "any
  unknown Constraints MUST be treated as failing evaluation"
  (`docs/ap2/agent_authorization.md:465`).
- Any other digest without its disclosure in the mandate object (an `_sd` entry at the mandate
  level, i.e. possibly `constraints` itself or a pre-set claim; an `_sd` entry inside a
  constraint object; an undisclosed element of `delegate_payload` or of another array) is a
  possibly withheld claim: **SKIP, required** (`withheld_claim`), so the verdict is at best
  INCOMPLETE until the mandate is supplied with all disclosures as issued. The same applies to
  the closed mandate object, except for one undisclosed digest at the closed checkout mandate's
  top level when `checkout_jwt` is absent (that is the withheld `checkout_jwt`, reported by
  CM30).
- Undisclosed entries of `allowed` (merchants, payees, instruments, PISPs) and of
  `acceptable_items` are fine: an entry that is not revealed can never be matched, so hiding it
  only **narrows** what is allowed. Details say so. This holds only for a whole hidden entry of
  the allow-list itself, decided by constraint type: `constraints[i].allowed` of
  `checkout.allowed_merchants`, `payment.allowed_payees`, `payment.allowed_payment_instruments`
  or `payment.allowed_pisps`, and `constraints[i].items[j].acceptable_items` of
  `checkout.line_items`. An array that merely has the same name elsewhere (an `allowed` member on
  `payment.amount_range`, or inside an allowed entry) is a withheld claim.
  A hidden property inside a revealed entry is a withheld claim (required SKIP): dropping a
  merchant's `id`, for example, would switch matching from the id to name and website and let
  a different merchant with the same name and website match. Undisclosed digests at the top
  level of the token, outside the mandate object, are treated as withheld claims too.
- Dependent checks say why they could not be performed: pre-set claims (CM18/PM18) and every
  constraint check whose type is not disclosed become required SKIPs blocked by CM22/PM22
  instead of "the open mandate has no such constraint".
- PM31: the issuer-JWT-only form of `conditional_transaction_id` does not bind the checkout
  mandate's disclosures. It still PASSes with a note when the open checkout mandate withholds
  nothing; when CM22 reports withheld constraints or claims it is a **WARN**
  (`issuer_jwt_form_with_withheld`), and CM22 itself catches the widening.

Upstream decoys will therefore make an otherwise valid bundle INCOMPLETE. That is deliberate:
from the bundle alone a decoy and a withheld limit look the same.

## R3. Exactly one mandate object per token

The SDK takes `delegate_payload[0]` as the effective payload and requires exactly one resolved
item in non-terminal tokens (`code/sdk/python/ap2/sdk/sdjwt/chain.py:151, 170-172, 195-199`).
**Choice (CM04/CM10/PM04/PM10):** every segment must resolve to exactly one mandate object; more
than one (or a first element that is not an object) FAILs (`multiple_mandate_objects` /
`no_mandate_object`). Version 0.1.0 picked the item with the expected `vct`; that let an agent
sign a closed token whose first item paid a different amount.

## R4. Non-UCP checkout payloads

AP2 is agnostic to the checkout format (`docs/ap2/specification.md:381-387`). **Choice:** CM33
WARNs when UCP members are missing, but every member that is present and well-typed is still
used: XC01 compares `payment_amount` with `totals[type=total]` whenever `currency` and one
integer total are present, XC02 compares the payee with `merchant` whenever it is an object,
CM35 evaluates `line_items` whenever it is an array. Line items in another shape (the docs'
`product` shape) are a CM33 WARN (`not_ucp`), not a malformed checkout, so CM34 still runs; CM35
FAILs only when a line_items constraint needs `item.id` and it is absent. When the needed members cannot be read at
all, XC01 / XC02 are **required** SKIPs (INCOMPLETE), never "not required": otherwise a
conclusion could state a paid amount next to a different merchant total.

## S. Pre-set claims

Prose: every claim of the open mandate must be unchanged in the closed one
(`agent_authorization.md:461-462`). SDK: checks only `payee` (with merchant matching),
`payment_amount`, `payment_instrument` and `execution_date` (`constraints.py:433-486`).

**Choice (CM18/PM18):** every open-mandate claim other than `vct`, `constraints`, `cnf`, `iat`
and `exp` must appear in the closed mandate with an equal JSON value (stricter than the SDK for
`payee`, which must be identical rather than merely matching by id). Equality is type-strict:
`true`, `1` and `1.0` are three different values (Python's `==` would equate them).

## T. `payment.execution_date`

The SDK compares `execution_date` with `not_before`/`not_after` as plain strings and passes when
the closed mandate has no `execution_date` (`constraints.py:316-345`).

**Choice (PM36):** values are parsed with an explicit RFC 3339 profile and compared as instants:
a full date `YYYY-MM-DD` (midnight UTC) or a date-time `YYYY-MM-DDTHH:MM:SS[.fraction]` with `Z`
or a numeric offset (`T`/`Z` in either case; fractions beyond microseconds truncated). Nothing
else parses: no naive date-times, no basic or week formats, no leap second, no surrounding
whitespace. The result is identical on Python 3.10-3.13 (`datetime.fromisoformat` accepts more
from 3.11 on, which made the verdict version-dependent). If any value does not parse, they are
compared as strings like the SDK and the detail says so. `--at` uses the same profile, or Unix
seconds (`constraints.parse_instant`). A missing `execution_date` PASSes with a note
("absent means immediate", `payment_mandate.json:41-44`).

## U. Budget and recurrence need history

Both are cumulative (`docs/ap2/payment_mandate.md:57-62, 203-208`). The SDK requires a
`MandateContext` with past usage and fails without one (`constraints.py:217-221, 301-302`), and
requires `amount_range` and `budget` whenever `agent_recurrence` is present
(`constraints.py:514-533`).

**Choice:** PM37 checks that this payment alone does not exceed the budget; PM38 checks the
recurrence rule's shape and the SDK's companion-constraint rule. PM39 (required) evaluates the
cumulative limits like the SDK's `MandateContext`, with the history the operator passes to
`verify_bundle(history={"prior_total": {"amount", "currency"}, "prior_uses": n})`: budget FAILs
(`budget_exceeded`) when earlier spend plus this payment exceeds `budget.max`; recurrence FAILs
(`occurrences_exceeded`) when the earlier uses already reach `max_occurrences`. The detail says
the history figure is supplied by whoever ran the verifier. Without the needed history value
PM39 is a **required SKIP** (`history_needed`), so such a bundle is INCOMPLETE; the
upstream-minted `v_extras_*` fixtures are INCOMPLETE without history and VERIFIED with
`prior_total` 0 / `prior_uses` 0. Without a budget or recurrence constraint PM39 does not apply.

## V. Time

The SDK checks `exp`/`iat` against the current time with 300 s skew (`chain.py:272-299`). Dispute
evidence is always expired "now", so that check would always fail.

**Choice:** no wall-clock check by default. CM16/PM16 check that the closed token's `iat` lies in
the open mandate's `iat..exp` (default skew 300 s, `--skew`); CR06/PR06 check that a receipt is
not older than the closed mandate it references. `--at` additionally asserts validity at a given
instant (CM19/PM19): each mandate object's `iat`/`exp`, and each segment JWT's own `iat` and
`exp`, like the SDK (`chain.py:272-299`, which rejects `iat > now + skew`). No ordering is assumed between the two closed mandates or the two receipts:
in the official samples the closed payment mandate (`iat` 1777342370) is older than the closed
checkout mandate (`iat` 1777342376). Chronology rules are not defined upstream, so these checks
are this tool's design.

## W. Algorithms and keys

Prose forbids deterministic signatures for the checkout JWT (`specification.md:154-157`) and
mandates nothing else; the JWK schema, SDK and samples use ES256 / P-256 only
(`types/jwk.json`, `code/sdk/python/ap2/sdk/jwt_helper.py:27`).

**Key selection:** keys are matched by `kid`; when the header's `kid` matches none of the keys supplied for the role, all of that role's keys are tried and a signature that verifies under none of them FAILs (`signature_invalid`). SKIP is only used when the role has no key at all (version 0.1.0 reported an unknown `kid` as SKIP, which let a forged root with an invented `kid` downgrade FAILED to INCOMPLETE).

**Choice:** only ES256 with raw 64-byte `r||s` signatures is verified; `none`, `HS*`, `EdDSA` and
everything else FAIL the algorithm checks. JWKs must follow `types/jwk.json` (members outside
that list, and the private member `d`, are rejected). Root keys come from the bundle or
`--trusted-keys` by `kid`; `x5c` chains are not validated in 0.1 (the SDK supports them,
`chain.py:52-108`), so a root token that needs `x5c` is SKIP unless a key is supplied directly.

**Self-asserted keys.** By default a signature that verifies under a key supplied inside the
bundle PASSes (the provenance is reported). `verify_bundle(require_pinned=True)` turns every
such result into a required SKIP (`key_not_pinned`), so only keys pinned with `--trusted-keys`
can make a bundle VERIFIED. CM08/PM08 (the agent key named in the open mandate's `cnf.jwk`) are
not affected: that key is vouched for by the root signature.

## W2. Relying-party expectations (EX01-EX05)

`verify_bundle(expected=...)` also takes optional top-level members the relying party knows
independently of the bundle: `agent_key` (public JWK; compared with each open mandate's
`cnf.jwk` by RFC 7638 thumbprint), `checkout_id` (merchant-signed checkout `id`), `merchant_id`
(checkout `merchant.id` and closed payment `payee.id`), `total` (checkout total and paid amount)
and `require_constraints` (constraint types the open mandates must carry). Not given: SKIP, not
required (`not_expected`). Given: PASS/FAIL (`agent_key_mismatch`, `checkout_id_mismatch`,
`merchant_id_mismatch`, `total_mismatch`, `constraint_missing`); a required SKIP when the
artifact that states the value is missing. These members are not read from the bundle's own
`expected` member: whoever assembled the bundle could write anything there.

## Y. The User Credential (DPC / OpenID4VP) model

The prose also describes a root that is a pre-issued user credential (e.g. `vct: com.emvco.dpc`
with a top-level `cnf`), with mandates delegated through OpenID4VP `transaction_data`
(`docs/ap2/agent_authorization.md:104-114, 191-228, 251-272`); the SDK's `cnf` lookup falls back
to a top-level `cnf` (`common.py:89-108`). Only truncated examples exist upstream.

**Choice:** not supported in 0.1. The agent key is read only from `cnf.jwk` inside the open
mandate object, which is how every complete upstream sample is built. A chain in the DPC shape
will fail CM06/PM06 (no `cnf.jwk` in the mandate) rather than be half-verified.

## X. Things the SDK does that we deliberately do not

- The SDK's verifier also accepts a trailing plain KB-JWT on the last segment and then insists on
  `expected_aud`/`expected_nonce` (`common.py:123-132`, `mandate.py:225-234`) although its README
  says the shape is not accepted (`code/sdk/python/ap2/sdk/README.md:73-79`). We reject a trailing
  KB-JWT (CM01/PM01 FAIL), following the README.
- The SDK tolerates `delegate_payload` items that are base64url disclosure strings or bare digest
  strings (`chain.py:203-227`, `kb_sd_jwt.py:153-205`, "CMWallet format"). We only accept the
  RFC 9901 forms (`{"...": digest}` placeholders and `_sd` arrays); other item types resolve to no
  mandate (CM04/CM10 FAIL).
- RFC 9901 requires that every disclosure be referenced exactly once and that no digest repeat.
  We enforce this ourselves for every segment, including nested `_sd` and `{"...": digest}`
  (CM04/CM10/PM04/PM10). The SDK delegates most of this to the third-party `sd-jwt` library and
  adds its own lenient inline resolution (`chain.py:230-244`); we did not audit whether every SDK
  code path enforces the RFC rule.
