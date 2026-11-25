"""Reason codes for every row that is not a plain ``agree``, with our position and evidence.

A row gets its code from an explicit rule below or, for missing-input cases, from the blocking
checks. A non-agree row without a code is ``UNEXPLAINED``: the run reports it and the tests
fail until a person decides which code (or which new entry) applies.

Paths and line numbers of upstream files refer to google-agentic-commerce/AP2 at commit
e1ea56d; third-party paths refer to the pinned commit of that source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from run import AGREE, AGREE_INCOMPLETE, DISAGREE

UNEXPLAINED = "UNEXPLAINED"


@dataclass(frozen=True)
class Reason:
    """One reason code."""

    code: str
    category: str
    title: str
    position: str
    evidence: tuple[str, ...] = ()


CATEGORIES = {
    "default": "The difference is a default",
    "outside": "The input is outside what an AP2 evidence bundle contains",
    "verdict": "The verdicts mean different things",
    "unimplemented": "We do not implement it",
    "reading": "The authors read the specification differently",
    "partial": "The vector does not carry everything needed (agree with incomplete input)",
}

_REASONS = (
    Reason(
        "skew-default",
        "default",
        "Clock skew: 300 s by default, 0 s in the author's profile",
        "With `--at`, a segment issued 1 s after the instant is within our default skew of 300 s "
        "(the SDK's default). With `skew=0`, the author's setting, we FAIL it (CM19), so the "
        "rows agree once the author's skew is supplied.",
        (
            "AP2 `code/sdk/python/ap2/sdk/sdjwt/chain.py:287, 296` (`now > exp + clock_skew`, "
            "`iat > now + clock_skew`); default `clock_skew_seconds: int = 300` at `:124`",
            'cuichangquan `docs/BUYER_DIRECT_CHECKOUT.md:118` ("no implicit clock/skew")',
            "ap2-evidence `docs/spec-notes.md` section V",
        ),
    ),
    Reason(
        "history-not-supplied",
        "outside",
        "Cumulative budget / recurrence needs the payment history",
        "`payment.budget` and `payment.agent_recurrence` limit the sum of all payments under "
        "a mandate; one bundle holds one payment. Without history PM39 is a required SKIP "
        "(INCOMPLETE). With the author's history (`history=`) these rows agree.",
        (
            "AP2 `docs/ap2/payment_mandate.md:57-62, 203-208`; SDK needs a `MandateContext`, "
            "`code/sdk/python/ap2/sdk/constraints.py:217-221, 301-302`",
            "ap2-evidence `docs/spec-notes.md` section U",
        ),
    ),
    Reason(
        "rp-expectation-not-supplied",
        "outside",
        "Relying-party expectations are not in the bundle",
        "The author's verifier is told the expected agent key, checkout id, merchant id, total "
        "or required constraint types. A bundle does not carry these (whoever assembled it could "
        "write anything); they are verifier options (EX01-EX05). With them supplied the rows "
        "agree.",
        ("ap2-evidence `docs/spec-notes.md` section W2",),
    ),
    Reason(
        "replay-across-bundles",
        "outside",
        "Replay: the same chain presented for two payments",
        "AMEP presents one chain twice and flags both payments. A single bundle is internally "
        "consistent; detecting a second use needs state across bundles (a ledger of mandate "
        "uses), which is outside an offline single-bundle check.",
        (
            "AMEP `packages/conformance/test/fixtures/ap2/*.json` families `*-redeemed-twice*`; "
            "invariant I2 in `interop/ap2/verdicts.json`",
            "AMEP `CHANGELOG.md:91` (the same closed mandate processed twice, AP2 issue #346, "
            '"which the SDK\'s verifier accepts")',
        ),
    ),
    Reason(
        "x402-settlement-layer",
        "outside",
        "x402 / EIP-3009 / settlement layer",
        "The signed AP2 tokens of these cases are byte-identical to those of a valid case. "
        "Apart from the description and Pulse's `inputHash`, the case differs in the x402 "
        "payment payload or requirements, the EIP-3009 authorisation or the settlement record "
        "(some cases also in Pulse's unsigned copy of the AP2 claims). None of that is AP2 "
        "evidence; our INCOMPLETE is the verdict for the valid twin too.",
        ("Pulse `fixtures/v0.3/cases.json` (per-row: the members that differ from the twin)",),
    ),
    Reason(
        "unsigned-claims-copy",
        "outside",
        "Pulse's unsigned copy of the AP2 claims",
        "The signed AP2 tokens are byte-identical to those of a valid case; what changes is "
        "Pulse's unsigned, normalised copy of the mandate or receipt claims (and the hashes it "
        "keeps of them). Only the signed tokens are AP2 evidence, so nothing in the bundle "
        "changes.",
        ("Pulse `fixtures/v0.3/cases.json` (per-row: the members that differ from the twin)",),
    ),
    Reason(
        "host-copy-of-checkout",
        "outside",
        "A second, host-held copy of the checkout",
        "The case gives the host a checkout JWS different from the one inside the closed "
        "mandate. A bundle holds the mandate's own `checkout_jwt` (which verifies); the host's "
        "copy has no place in it.",
        ("cuichangquan `research/stage11/inputs/O2O5_PUBLIC_CASES.json` `host_checkout_jws`",),
    ),
    Reason(
        "placeholder-checkout-signature",
        "outside",
        "The vector's checkout JWT has a placeholder signature",
        "The vector tests only the checkout receipt; the checkout JWT inside its mandate is "
        "signed with the literal string `sig`. With the receipt key supplied for the merchant "
        "role, CM32 checks that JWT and FAILs. A checkout JWT must be merchant-signed in AP2, "
        "so we keep FAILED.",
        (
            'goodmeta `generators/gen_ap2_v02_vectors.py:105-108` (`return f"{hdr}.{pl}.sig"`)',
            'AP2 `docs/ap2/specification.md:126` ("The Merchant MUST provide a merchant-signed '
            'JWT"), `docs/ap2/checkout_mandate.md:30`; the checkout receipt is merchant-signed '
            "too (`docs/ap2/flows.md:76`), hence one `merchant` role for both",
        ),
    ),
    Reason(
        "missing-input-is-incomplete",
        "verdict",
        "A missing artifact is INCOMPLETE, not FAILED",
        "The author rejects when an input needed for a check is absent (a payment mandate; the "
        "open checkout hash for `payment.reference`). We report what we cannot check as a "
        "required SKIP, so the verdict is INCOMPLETE: absence is not evidence of tampering.",
        (
            "kya-bench `src/kya_bench/ap2/verifier.py:143` (`AP2_MANDATE_MISSING`)",
            "goodmeta `vectors/payment-constraints.json` `reference_missing_hash` (SDK message "
            '"open_checkout_hash is required")',
            "ap2-evidence `docs/checks.md` B02",
        ),
    ),
    Reason(
        "x5c",
        "unimplemented",
        "x5c certificate chains",
        "The root key is given only as an x5c chain. We do not validate x5c in 0.1, so the root "
        "signature is a required SKIP (INCOMPLETE) instead of a rejection.",
        (
            "AP2 `code/sdk/python/ap2/sdk/sdjwt/chain.py:52-108` (the SDK supports x5c)",
            "ap2-evidence `docs/spec-notes.md` section W",
        ),
    ),
    Reason(
        "delegation-depth",
        "unimplemented",
        "Chains other than root -> closed mandate",
        "We verify two-segment chains (open mandate, then the closed mandate). Longer chains are "
        "a required SKIP (PM20 `delegation_unsupported`). A chain whose second segment is "
        "another open mandate (typ `kb+sd-jwt+kb`) is not payment evidence in our model and "
        "FAILs the closed-mandate checks.",
        (
            "AP2 SDK `code/sdk/python/ap2/sdk/sdjwt/kb_sd_jwt.py:31-32, 138-139` (intermediate "
            "`kb+sd-jwt+kb` hops carry `cnf`; the SDK accepts multi-hop chains)",
            "goodmeta `vectors/chain.json` `valid_payment_3hop`; AP2 PR #369 "
            "`contrib/mandate-corpus/vectors/*.json` (`kb_sd_jwt` is an intermediate hop)",
        ),
    ),
    Reason(
        "kid-is-a-hint",
        "reading",
        "`kid` names a key; it does not decide trust",
        "The token's `kid` is not in the trust list, but the signature verifies under a key "
        "that is. We treat `kid` as a hint (RFC 7515 section 4.1.4) and PASS the signature; the "
        "author rejects an unknown `kid`.",
        (
            "kya-bench `src/kya_bench/ap2/verifier.py:252` (`kid ... is not in the trust list`)",
            "ap2-evidence `docs/spec-notes.md` section W (key selection)",
        ),
    ),
    Reason(
        "exp-boundary",
        "reading",
        "Validity at exactly `exp`",
        "At the instant equal to `exp` the author rejects (RFC 7519 section 4.1.4: not accepted "
        '"on or after" `exp`). We follow the SDK, which rejects only when `now > exp + skew`, '
        "so at `exp` with skew 0 the mandate is still valid.",
        ("AP2 `code/sdk/python/ap2/sdk/sdjwt/chain.py:287`",),
    ),
    Reason(
        "time-claims-not-preset",
        "reading",
        "Closed mandate `exp` different from the open mandate's",
        "The prose says the closed mandate keeps the open mandate's claims unchanged; the author "
        "applies that to `exp`. We, like the SDK, compare pre-set claims other than `vct`, "
        "`constraints`, `cnf`, `iat` and `exp`; a closed mandate may expire earlier.",
        (
            "AP2 `docs/ap2/agent_authorization.md:461-462`; SDK "
            "`code/sdk/python/ap2/sdk/constraints.py:433-486`",
            "ap2-evidence `docs/spec-notes.md` section S",
        ),
    ),
    Reason(
        "undisclosed-acceptable-items",
        "reading",
        "All acceptable items undisclosed",
        "The author leaves this open (SPEC_GAP). The SDK treats an empty resolved "
        "`acceptable_items` as a wildcard; we treat an array whose entries are all undisclosed "
        "as matching nothing (prose), because otherwise withholding disclosures widens authority.",
        (
            "AP2 `code/sdk/python/ap2/sdk/max_flow_helper.py:36-44`; "
            "`docs/ap2/checkout_mandate.md:87-88`",
            "ap2-evidence `docs/spec-notes.md` sections R and R2",
        ),
    ),
    Reason(
        "amount-range-units",
        "reading",
        "`amount_range.max` as a decimal",
        "The author leaves this open (SPEC_GAP). The schema and the sample tokens use integer "
        "minor units; the prose example uses `100.50`. We FAIL a non-integer bound as a "
        "malformed constraint.",
        (
            "AP2 `code/sdk/schemas/ap2/open_payment_mandate.json:131-142`; "
            "`docs/ap2/payment_mandate.md:183-189`",
            "ap2-evidence `docs/spec-notes.md` section F",
        ),
    ),
    Reason(
        "checkout-total-vs-amount",
        "reading",
        "Paid amount different from the checkout total",
        "The author leaves this open (SPEC_GAP): no upstream rule says the payment amount must "
        "equal the merchant-signed checkout total. We FAIL it (XC01); this is our design, stated "
        "as such in the check catalogue.",
        ('ap2-evidence `docs/checks.md` XC01 ("this tool\'s design")',),
    ),
    Reason(
        "non-ucp-line-items",
        "reading",
        "Line items in the documentation's `product` shape",
        "The author leaves this open (SPEC_GAP). A non-UCP checkout is accepted with a WARN, but "
        "a `checkout.line_items` constraint matches on `item.id`; when no line has one, the "
        "constraint cannot be satisfied and CM35 FAILs.",
        (
            "AP2 `docs/ap2/specification.md:381-387` (checkout format agnostic); "
            "`docs/ap2/checkout_mandate.md:291` (`product` example)",
            "ap2-evidence `docs/spec-notes.md` section R4",
        ),
    ),
    Reason(
        "receipt-for-other-mandate",
        "reading",
        "A receipt that references another mandate",
        "The author leaves the payment unresolved because its own receipt is missing. The bundle "
        "presents a receipt for this payment whose `reference` names a different mandate; we "
        "FAIL that link (PR04).",
        ("AP2 `docs/ap2/specification.md:354-360` (Dispute: the reference MUST match)",),
    ),
    Reason(
        "unreferenced-disclosure",
        "reading",
        "An altered disclosure",
        "The author leaves the payment unresolved (signature gap). The altered amount is a "
        "disclosure no signed digest references, which is a modification after signing; we FAIL "
        "it (PM10).",
        ("RFC 9901 (every disclosure must be referenced by a digest in the signed payload)",),
    ),
    Reason(
        "no-key",
        "partial",
        "The vector ships no key for a role",
        "A signature we could check is a required SKIP because the vector provides no public "
        "key for that signer (for example no merchant key for the checkout JWT).",
    ),
    Reason(
        "partial-bundle",
        "partial",
        "The vector holds only part of a transaction",
        "Only a payment mandate, or no receipt: the checks on the absent artifacts are required "
        "SKIPs, so the verdict is INCOMPLETE.",
    ),
)

REASONS = {r.code: r for r in _REASONS}

# (group, id regex, mode or None for both, code); first match wins.
RULES: tuple[tuple[str, str, str | None, str], ...] = (
    ("goodmeta", r"receipts\.checkout_receipt_valid", None, "placeholder-checkout-signature"),
    (
        "goodmeta-decoded",
        r"payment-constraints\.reference_missing_hash",
        None,
        "missing-input-is-incomplete",
    ),
    ("goodmeta-decoded", r".*_absent_required", "bare", "rp-expectation-not-supplied"),
    ("kya-bench", r"ap2-payment-mandate-missing", None, "missing-input-is-incomplete"),
    ("kya-bench", r"ap2-root-key-untrusted", None, "kid-is-a-hint"),
    ("kya-bench", r"ap2-acceptable-items-undisclosed", None, "undisclosed-acceptable-items"),
    ("kya-bench", r"ap2-amount-range-decimal-max", None, "amount-range-units"),
    ("kya-bench", r"ap2-cart-total-mismatch", None, "checkout-total-vs-amount"),
    ("kya-bench", r"ap2-line-item-product-shape", None, "non-ucp-line-items"),
    ("cuichangquan", r"O2O5\.FUTURE_AGENT", "bare", "skew-default"),
    ("cuichangquan", r"O2O5\.EXPIRED", None, "exp-boundary"),
    ("cuichangquan", r"O2O5\.CLOSED_TIME", None, "time-claims-not-preset"),
    ("cuichangquan", r"O2O5\.CHECKOUT_ORIGINAL", None, "host-copy-of-checkout"),
    (
        "cuichangquan",
        r"O2O5\.(WRONG_AGENT_KEY|CHECKOUT_ID|MERCHANT_ID|AMOUNT|CURRENCY|TOTALS)",
        "bare",
        "rp-expectation-not-supplied",
    ),
    ("amep", r".*redeemed-twice.*", None, "replay-across-bundles"),
    ("amep", r"synthetic\.s7-.*", None, "receipt-for-other-mandate"),
    ("amep", r"synthetic\.s8-.*", None, "unreferenced-disclosure"),
    ("pulse", r"invalid-(ap2-x402|x402|eip3009|settlement)-.*", None, "x402-settlement-layer"),
    ("pulse", r"invalid-ap2-.*", None, "unsigned-claims-copy"),
    ("ap2-pr369", r".*", None, "delegation-depth"),
)

# Blocking reasons that explain an INCOMPLETE verdict on their own, in priority order.
_AUTO = (
    ("x5c_unsupported", "x5c", True),
    ("delegation_unsupported", "delegation-depth", True),
    ("history_needed", "history-not-supplied", True),
    ("no_key", "no-key", False),
)


def assign(group: str, vid: str, mode: str, cls: str, blocking: list[str]) -> str | None:
    """Reason code for a row (``None`` for a plain agree)."""
    if cls == AGREE:
        return None
    for g, pattern, m, code in RULES:
        if g == group and (m is None or m == mode) and re.fullmatch(pattern, vid):
            return code
    reasons = {b.split(":", 1)[1] for b in blocking}
    for reason, code, explains_disagreement in _AUTO:
        if reason in reasons and (explains_disagreement or cls == AGREE_INCOMPLETE):
            return code
    if cls == AGREE_INCOMPLETE:
        return "partial-bundle"
    return UNEXPLAINED if cls in (DISAGREE, "stricter") else None


#: Fixes made after the first run, with the vectors that exposed them (rows now agree).
FIXES: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "CM12/PM12: `cnf` in a directly signed closed mandate",
        "We failed a one-segment (human-present) closed mandate that carries `cnf`. The SDK's "
        "terminal-`cnf` rule applies to a key-binding hop (`kb_sd_jwt.py:135-137`), not to a "
        "root token (`chain.py:147-159`); the prose example has exactly this shape "
        "(`agent_authorization.md:198-211`). Now PASS with a note; a `cnf` in a key-binding "
        "closed hop still FAILs.",
        (("kya-bench", "ap2-hp-valid"), ("kya-bench", "ap2-mixed-flows")),
    ),
    (
        "CM35: empty checkout against `checkout.line_items`",
        "A checkout with no line items passed a line_items constraint. The SDK rejects it "
        '("Empty cart does not satisfy line_items constraint", `constraints.py:413-416`); '
        "now FAIL (`empty_checkout`).",
        (("goodmeta-decoded", "checkout-constraints.line_items_empty_cart"),),
    ),
    (
        "CR05/PR05: declined receipts reported as broken evidence",
        "An authentic `Error` receipt FAILed. It documents a declined step and the evidence is "
        "intact; now WARN (`declined`). Integrity problems (signature, reference) and an Error "
        "receipt without its required `error` member still FAIL.",
        (
            ("amep", "sdk.sdk-declined.p1"),
            ("amep", "synthetic.s4-declined.p1"),
            ("amep", "sdk-checkout.sdk-declined.p1"),
            ("goodmeta", "receipts.payment_receipt_error_without_error_code"),
        ),
    ),
    (
        "CM19/PM19: the closed hop's own `iat` against `--at`",
        "With `--at`, only the mandate objects' `iat`/`exp` were compared, not each segment "
        "JWT's own `iat` as the SDK does (`chain.py:296`). Now every segment JWT is checked.",
        (("cuichangquan", "O2O5.FUTURE_AGENT"),),
    ),
    (
        "CM33/CM35: non-UCP line items",
        "Line items in the documentation's `product` shape made the whole checkout malformed "
        "(CM33 FAIL). AP2 is agnostic to the checkout format (`specification.md:381-387`); now "
        "CM33 WARNs (`not_ucp`) and only a `checkout.line_items` constraint that needs `item.id` "
        "FAILs (CM35). The kya-bench row below still differs for that reason "
        "(`non-ucp-line-items`).",
        (("kya-bench", "ap2-line-item-product-shape"),),
    ),
    (
        "PM39: cumulative budget and recurrence",
        "Budget and recurrence were evaluated on this payment alone. They are cumulative; PM39 "
        "now evaluates them with operator-supplied history and is a required SKIP without it.",
        (
            ("kya-bench", "ap2-budget-cumulative-exceeded"),
            ("goodmeta-decoded", "payment-constraints.budget_over"),
            ("goodmeta-decoded", "payment-constraints.recurrence_exceeded"),
            ("amep", "sdk.sdk-budget.p2"),
            ("amep", "synthetic.s6-budget.p2"),
            ("amep", "sdk-checkout.sdk-budget.p2"),
        ),
    ),
    (
        "EX01-EX05: relying-party expectations",
        "Expected agent key, checkout id, merchant id, total and required constraint types "
        "could not be given to the verifier; they are now options (not bundle members).",
        (
            ("cuichangquan", "O2O5.WRONG_AGENT_KEY"),
            ("cuichangquan", "O2O5.CHECKOUT_ID"),
            ("cuichangquan", "O2O5.AMOUNT"),
            ("goodmeta-decoded", "payment-constraints.budget_absent_required"),
        ),
    ),
)
