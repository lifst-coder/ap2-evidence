"""The check catalogue: the single source of truth for check IDs and their meaning.

Every verification run produces exactly one result per entry in
:data:`REGISTRY`. ``docs/checks.md`` is generated from this module
(``python -m ap2_evidence.checksdoc``) and a test keeps the two in sync.
"""

from __future__ import annotations

from dataclasses import dataclass

GROUPS: dict[str, str] = {
    "bundle": "Bundle",
    "checkout_mandate": "Checkout mandate chain",
    "payment_mandate": "Payment mandate chain",
    "cross": "Cross-artifact consistency",
    "checkout_receipt": "Checkout receipt",
    "payment_receipt": "Payment receipt",
}
"""Check families, in report order."""


@dataclass(frozen=True)
class CheckDef:
    """Static description of one check.

    Attributes:
        id: Stable identifier (never reused for a different meaning).
        group: Family key from :data:`GROUPS`.
        title: Short title.
        required: Whether a SKIP of this check makes the verdict INCOMPLETE by default.
            Individual results may override this (e.g. a check that does not apply).
        what: What is checked.
        why: What the check is for in a dispute, worded as its purpose ("Confirms that
            ...") so that it is true whether the check passed or failed. Rendered as
            "What this check is for".
        spec_ref: Upstream document and section the check is based on.
        worst: The most severe status the check can produce: ``FAIL``, ``WARN``
            (advisory checks) or ``SKIP`` (checks that only report unsupported input).
        can_pass: False for purely informational checks that never PASS.
    """

    id: str
    group: str
    title: str
    required: bool
    what: str
    why: str
    spec_ref: str
    worst: str = "FAIL"
    can_pass: bool = True


AA = "docs/ap2/agent_authorization.md"
SPEC = "docs/ap2/specification.md"
CMD = "docs/ap2/checkout_mandate.md"
PMD = "docs/ap2/payment_mandate.md"
SCH = "code/sdk/schemas/ap2"


def _chain_defs(prefix: str, kind: str) -> list[CheckDef]:
    group = f"{kind}_mandate"
    doc = CMD if kind == "checkout" else PMD
    open_vct = f"mandate.{kind}.open.1"
    closed_vct = f"mandate.{kind}.1"
    closed_schema = f"{SCH}/{kind}_mandate.json"
    open_schema = f"{SCH}/open_{kind}_mandate.json"
    k = kind.capitalize()
    return [
        CheckDef(
            f"{prefix}01",
            group,
            f"{k} mandate chain parses",
            True,
            "The token splits into '~~'-joined SD-JWT segments; each segment is a compact JWS "
            "with canonical base64url, JSON-object header and payload (no duplicate keys) and "
            "well-formed disclosures.",
            "Confirms that the token can be read at all. Without this, nothing else can be "
            "checked; a token that does not parse is often a truncated or hand-edited copy.",
            "code/sdk/python/ap2/sdk/README.md (chain serialization); RFC 9901 section 4",
        ),
        CheckDef(
            f"{prefix}02",
            group,
            "Root token algorithm is ES256",
            True,
            "The 'alg' header of the root (issuer-signed) token is ES256. 'none', HMAC (HS*) and "
            "EdDSA are rejected; this version verifies ES256 / P-256 only.",
            "Confirms that the signature algorithm is fixed. Without this, an attacker who can "
            "choose the algorithm could make a forged token 'verify'.",
            f'{SCH}/types/jwk.json (alg ES256); {SPEC} "Payment Mandate" (no deterministic '
            "signatures)",
        ),
        CheckDef(
            f"{prefix}03",
            group,
            "Root token signature (mandate issuer)",
            True,
            "The root token's signature verifies under a key of role 'mandate_issuer' (the user's "
            "credential or the trusted agent provider), matched by 'kid' when present.",
            "Confirms that the mandate comes from the user or their agent provider. Without this, "
            "the open mandate's limits and agent key could have been written by anyone.",
            f'{SPEC} "Modes"; {AA} "Verification and Processing Rules"',
        ),
        CheckDef(
            f"{prefix}04",
            group,
            "Root token disclosures resolve",
            True,
            "Every disclosure of the root segment is referenced exactly once by a digest in the "
            "signed payload (directly or recursively), no digest repeats, _sd_alg is sha-256/384/"
            "512, and delegate_payload resolves to one mandate object.",
            "Confirms that every disclosed part of the open mandate was issued with it. Without "
            "this, a part could have been swapped or added later, e.g. to show a different "
            "allowed merchant.",
            "RFC 9901 section 7.1; code/sdk/python/ap2/sdk/sdjwt/chain.py (delegate_payload)",
        ),
        CheckDef(
            f"{prefix}05",
            group,
            "Open mandate type (vct)",
            True,
            f"The root mandate object's vct is exactly '{open_vct}' (two-segment chain).",
            "Confirms that the open mandate is the type it is presented as. The type (vct) "
            "selects the schema and the meaning of its limits; implementations MUST match the "
            "exact string including the version suffix.",
            f'{SPEC} "Mandate Versioning"; {doc} "Type"',
        ),
        CheckDef(
            f"{prefix}06",
            group,
            "Open mandate binds an agent key (cnf.jwk)",
            True,
            "The open mandate carries cnf.jwk and it is a valid EC P-256 public key with only the "
            "members allowed by AP2 jwk.json.",
            "Confirms that the open mandate names the one agent key allowed to act on it "
            "(cnf.jwk). Without this, any key could sign the closed mandate.",
            f'{SPEC} "Autonomous (Human Not Present)"; {SCH}/types/jwk.json',
        ),
        CheckDef(
            f"{prefix}07",
            group,
            "Closed token type is kb+sd-jwt",
            True,
            "The closed (agent-signed) token's 'typ' header is 'kb+sd-jwt'. The spelling "
            "'kb-sd-jwt' is accepted with a warning, as the upstream SDK does.",
            "Confirms that the closed token is marked as an agent-signed (key-binding) step. "
            "Without this, a root token could be replayed as a closed mandate.",
            "code/sdk/python/ap2/sdk/sdjwt/kb_sd_jwt.py (TYP_TERMINAL)",
        ),
        CheckDef(
            f"{prefix}08",
            group,
            "Closed mandate signed by the bound agent key",
            True,
            "The closed token is ES256 and its signature verifies under the open mandate's "
            "cnf.jwk (key binding / proof of possession).",
            "Confirms that the agent the user authorised - and nobody else - approved this "
            "specific transaction.",
            f'{AA} "Mandate Structure" (Closed); kb_sd_jwt.py verify()',
        ),
        CheckDef(
            f"{prefix}09",
            group,
            "Closed token is bound to the open token (sd_hash)",
            True,
            "The closed token carries exactly one of sd_hash / issuer_jwt_hash, and it equals the "
            "hash of the open segment exactly as presented.",
            "Confirms that the closed mandate was made for this open mandate. Without this, the "
            "agent's signature could be moved onto a different open mandate with other limits.",
            "code/sdk/python/ap2/sdk/sdjwt/common.py verify_binding()",
        ),
        CheckDef(
            f"{prefix}10",
            group,
            "Closed token disclosures resolve",
            True,
            "Every disclosure of the closed segment is referenced exactly once by a digest in the "
            "agent-signed payload, and delegate_payload resolves to one mandate object.",
            "Confirms that every disclosed part of the closed mandate was signed by the agent. "
            "Without this, content could have been swapped after the agent signed it.",
            "RFC 9901 section 7.1",
        ),
        CheckDef(
            f"{prefix}11",
            group,
            "Closed mandate type (vct)",
            True,
            f"The closed mandate object's vct is exactly '{closed_vct}'.",
            "Confirms that the closed token is the mandate it is presented as.",
            f'{SPEC} "Mandate Versioning"; {doc} "Type"',
        ),
        CheckDef(
            f"{prefix}12",
            group,
            "Closed mandate carries no cnf",
            True,
            "A closed mandate presented as a key-binding hop (two segments) has no 'cnf' claim. "
            "A directly signed one-segment mandate may carry cnf (upstream has no such rule for "
            "a root token).",
            "Confirms that the closed mandate cannot be passed on. A cnf there would let the "
            "holder of that key delegate further; AP2 v0.2 closed mandates are terminal.",
            "code/sdk/python/ap2/sdk/sdjwt/kb_sd_jwt.py (a terminal key-binding hop MUST NOT "
            "carry cnf); sdjwt/chain.py (no cnf rule for the root token)",
        ),
        CheckDef(
            f"{prefix}13",
            group,
            "Closed mandate fields and types",
            True,
            f"All fields required by {closed_schema} are present with the right JSON types "
            "(integers for amounts and timestamps).",
            "Confirms that the mandate has every required field with the right type. Without "
            "this, the mandate is ambiguous as evidence.",
            closed_schema,
        ),
        CheckDef(
            f"{prefix}14",
            group,
            "Audience (aud) as expected",
            True,
            "The closed token's 'aud' equals expected.<kind>.aud from the bundle, when given.",
            "Confirms that the agent presented the mandate to the expected recipient (aud), not "
            "to a different verifier.",
            "code/sdk/python/ap2/sdk/sdjwt/common.py verify_expected_claims()",
        ),
        CheckDef(
            f"{prefix}15",
            group,
            "Nonce as expected",
            True,
            "The closed token's 'nonce' equals expected.<kind>.nonce from the bundle, when given.",
            "Confirms that the presentation belongs to the expected verifier session (nonce). "
            "Without this, an old presentation could be replayed.",
            "code/sdk/python/ap2/sdk/sdjwt/common.py verify_expected_claims()",
        ),
        CheckDef(
            f"{prefix}16",
            group,
            "Chronology of open and closed mandate",
            True,
            "The closed token has an integer iat that lies within the open mandate's iat..exp "
            "window (with clock skew), and the open mandate's iat is not after its exp.",
            "Confirms that the agent signed while the user's authorisation was in force: not "
            "before the open mandate was issued and not after it expired.",
            "code/sdk/python/ap2/sdk/sdjwt/chain.py _check_time_claims(); this tool's design",
        ),
        CheckDef(
            f"{prefix}17",
            group,
            "All constraint types are known",
            True,
            "Every constraint in the open mandate has a type defined for this mandate in AP2 v0.2.",
            "Confirms that every limit in the mandate is one this tool understands. Unknown "
            "constraints MUST be treated as failing: the user may have set a limit this verifier "
            "cannot see.",
            f'{AA} "Verification and Processing Rules" step 3',
        ),
        CheckDef(
            f"{prefix}18",
            group,
            "Pre-set claims unchanged",
            True,
            "Every claim the open mandate fixes in advance (anything other than vct, constraints, "
            "cnf, iat, exp) appears unchanged in the closed mandate.",
            "Confirms that the agent did not change anything the user fixed in advance (for "
            "example the payee or the amount).",
            f'{AA} "Verification and Processing Rules" step 2',
        ),
        CheckDef(
            f"{prefix}19",
            group,
            "Valid at the --at instant",
            False,
            "Only with --at: the open mandate's iat..exp window (and any closed exp) contains "
            "the given instant.",
            "Answers 'was this mandate valid at time T?'. Without --at, wall-clock expiry is "
            "deliberately not checked because dispute evidence is always expired now.",
            "code/sdk/python/ap2/sdk/sdjwt/chain.py _check_time_claims()",
        ),
        CheckDef(
            f"{prefix}20",
            group,
            "Chain shape supported",
            True,
            "One segment (directly signed closed mandate) or two segments (open + closed). Longer "
            "chains are agent-to-agent delegation, outside AP2 v0.2, and are not verified.",
            "Confirms that every delegation step in the token is one this tool verifies; steps "
            "it does not verify cannot be part of the proof.",
            f'{SPEC} "Agent-to-Agent Delegation"',
            worst="SKIP",
        ),
        CheckDef(
            f"{prefix}21",
            group,
            "Open mandate fields and types",
            True,
            f"The open mandate's fields have the types required by {open_schema} (constraints "
            "is an array of objects with a string type and well-typed fields, iat/exp "
            "integers, pre-set claims well-formed). A missing constraint that the schema "
            "expects is a warning.",
            "Confirms that the open mandate's limits are well-formed. Without this, they cannot "
            "be evaluated reliably.",
            open_schema,
        ),
        CheckDef(
            f"{prefix}22",
            group,
            "No withheld constraints or claims",
            True,
            "No constraint of the open mandate is withheld (an undisclosed element of the "
            "constraints array FAILs), and no claim of the open or closed mandate object or of "
            "a constraint is withheld (an _sd digest without its disclosure is SKIP: the mandate "
            "must be supplied with all its disclosures as issued). Undisclosed entries of "
            "'allowed' / 'acceptable_items' are fine: they only narrow what is allowed.",
            "Confirms that no limit or claim was withheld from the bundle. Without this, an agent "
            "could drop a disclosure to hide a limit the user set (an amount range, the allowed "
            "items, a pre-set amount) and still bind its signature to what it presents.",
            f'{AA} "Verification and Processing Rules" step 3; RFC 9901 section 4.2.5 (decoys)',
        ),
    ]


_DEFS: list[CheckDef] = [
    CheckDef(
        "B01",
        "bundle",
        "Bundle readable",
        True,
        "The input is a JSON object with bundle_version 'ap2-evidence/1' and members of the "
        "expected types. Unknown members are ignored with a warning.",
        "Confirms that the input is an evidence bundle this tool can read; without this, nothing "
        "can be checked.",
        "docs/bundle-format.md (this tool)",
    ),
    CheckDef(
        "B02",
        "bundle",
        "All four artifacts present",
        True,
        "checkout_mandate, payment_mandate, checkout_receipt and payment_receipt are present.",
        "Confirms that all four documents of the dispute chain are present; each missing one "
        "leaves a link of the chain unproven.",
        f'{SPEC} "Dispute Evidence"',
    ),
    CheckDef(
        "B03",
        "bundle",
        "Supplied keys are valid",
        True,
        "Every key under keys.* (and --trusted-keys) is a P-256 public JWK; roles are "
        "mandate_issuer, merchant, payment_processor.",
        "Confirms that the supplied keys are well-formed public keys; a malformed or private key "
        "signals a careless or manipulated bundle.",
        f"{SCH}/types/jwk.json",
    ),
    *_chain_defs("CM", "checkout"),
    CheckDef(
        "CM30",
        "checkout_mandate",
        "Merchant checkout JWT readable",
        True,
        "The closed checkout mandate discloses checkout_jwt, and it is a compact JWS with alg "
        "ES256 and a JSON-object payload.",
        "Confirms that the merchant's signed statement of what is being sold (the checkout JWT) "
        "is present and readable.",
        f'{CMD} "Mandate Schema"; {SPEC} "Payment Mandate" (no deterministic signatures)',
    ),
    CheckDef(
        "CM31",
        "checkout_mandate",
        "checkout_hash matches the checkout JWT",
        True,
        "checkout_hash equals base64url(SHA-256(ASCII bytes of checkout_jwt)).",
        "Confirms that the agent's signature covers exactly the merchant's checkout shown in the "
        "bundle. Without this, the agent could have approved a different checkout.",
        f'{CMD} "Mandate Schema" (checkout_hash); {SPEC} "Dispute"',
    ),
    CheckDef(
        "CM32",
        "checkout_mandate",
        "Checkout JWT signature (merchant)",
        True,
        "The checkout JWT's signature verifies under a key of role 'merchant'.",
        "Confirms that the merchant itself issued the checkout (items, prices, total).",
        f'{SPEC} "Checkout Mandate" (merchant-signed JWT)',
    ),
    CheckDef(
        "CM33",
        "checkout_mandate",
        "Checkout payload is a UCP Checkout",
        True,
        "The checkout JWT payload has the UCP Checkout members (id, line_items, status, currency, "
        "totals, links) with valid types. A non-UCP payload is a warning and the UCP-dependent "
        "checks are skipped.",
        "Confirms that the checkout is a UCP Checkout, the format the item, merchant and total "
        "checks are defined for.",
        "code/sdk/schemas/ucp/types/checkout.json; " + f'{SPEC} "Checkout Object"',
    ),
    CheckDef(
        "CM34",
        "checkout_mandate",
        "Constraint checkout.allowed_merchants",
        True,
        "The checkout's merchant is among the revealed 'allowed' entries (by id when both have "
        "one, else name + website). No revealed entries fails.",
        "Confirms that the user allowed purchases from this merchant.",
        f'{CMD} "Allowed Merchants"',
    ),
    CheckDef(
        "CM35",
        "checkout_mandate",
        "Constraint checkout.line_items",
        True,
        "Every checkout item can be assigned to a requirement whose revealed acceptable_items "
        "contain its id, within each requirement's quantity (max-flow, as the upstream SDK).",
        "Confirms that the agent bought only items the user allowed, in allowed quantities.",
        f'{CMD} "Line Items"; code/sdk/python/ap2/sdk/max_flow_helper.py',
    ),
    *_chain_defs("PM", "payment"),
    CheckDef(
        "PM30",
        "payment_mandate",
        "transaction_id matches the checkout",
        True,
        "The closed payment mandate's transaction_id equals the closed checkout mandate's "
        "checkout_hash and the hash recomputed from the checkout JWT.",
        "Confirms that the payment was for this checkout and no other.",
        f'{SCH}/payment_mandate.json (transaction_id); {SPEC} "Payment Mandate"',
    ),
    CheckDef(
        "PM31",
        "payment_mandate",
        "Constraint payment.reference",
        True,
        "conditional_transaction_id equals the hash of the open checkout mandate as presented "
        "(sd_hash form; issuer-JWT-only form accepted with a note).",
        "Confirms that the user's payment authorisation is tied to the user's checkout "
        "authorisation.",
        f'{PMD} "Reference"',
    ),
    CheckDef(
        "PM32",
        "payment_mandate",
        "Constraint payment.amount_range",
        True,
        "payment_amount.amount (minor units) is within min..max and its currency equals the "
        "constraint currency.",
        "Confirms that the payment is within the spending limit (amount range) the user set.",
        f'{PMD} "Amount Range"',
    ),
    CheckDef(
        "PM33",
        "payment_mandate",
        "Constraint payment.allowed_payees",
        True,
        "The payee is among the revealed 'allowed' merchants (by id when both have one, else "
        "name + website).",
        "Confirms that the user allowed paying this payee.",
        f'{PMD} "Allowed Payees"',
    ),
    CheckDef(
        "PM34",
        "payment_mandate",
        "Constraint payment.allowed_payment_instruments",
        True,
        "The payment instrument's id is among the revealed 'allowed' instruments.",
        "Confirms that the user allowed this card or account to be used.",
        f'{PMD} "Allowed Payment Instruments"',
    ),
    CheckDef(
        "PM35",
        "payment_mandate",
        "Constraint payment.allowed_pisps",
        True,
        "The closed mandate's pisp matches an 'allowed' PISP (legal_name, brand_name and "
        "domain_name).",
        "Confirms that the user allowed this payment initiation service provider.",
        f'{PMD} "Allowed Payment Initiation Service Providers (PISPs)"',
    ),
    CheckDef(
        "PM36",
        "payment_mandate",
        "Constraint payment.execution_date",
        True,
        "execution_date, when present, is within not_before..not_after.",
        "Confirms that the payment was scheduled inside the date window the user allowed.",
        f'{PMD} "Execution Date"',
    ),
    CheckDef(
        "PM37",
        "payment_mandate",
        "Constraint payment.budget (this payment alone)",
        True,
        "This payment alone does not exceed budget.max (read in major units, as the upstream "
        "SDK does) and the currency matches.",
        "Confirms that this payment alone does not exceed the user's whole budget; a single "
        "payment above it is a clear violation even without the payment history.",
        f'{PMD} "Budget"; code/sdk/python/ap2/sdk/constraints.py BudgetEvaluator',
    ),
    CheckDef(
        "PM38",
        "payment_mandate",
        "Constraint payment.agent_recurrence",
        True,
        "frequency is a defined value, max_occurrences (if any) is a positive integer, and "
        "amount_range and budget constraints accompany it (as the upstream SDK requires).",
        "Confirms that the rule for repeated payments is well-formed; a malformed rule cannot "
        "limit repeated use.",
        f'{PMD} "Agent Recurrence"; code/sdk/python/ap2/sdk/constraints.py',
    ),
    CheckDef(
        "PM39",
        "payment_mandate",
        "Cumulative budget / recurrence",
        True,
        "Earlier spend plus this payment stays within payment.budget, and earlier uses plus this "
        "payment within payment.agent_recurrence max_occurrences. The earlier spend and uses are "
        "not in a bundle: they are supplied by whoever runs the verifier (history); without "
        "them the check is a required SKIP.",
        "Confirms that the user's cumulative limits hold for this payment; a single bundle "
        "cannot show what was already spent under the same open mandate.",
        f'{PMD} "Budget", "Agent Recurrence"; code/sdk/python/ap2/sdk/constraints.py '
        "BudgetEvaluator, AgentRecurrenceEvaluator (MandateContext)",
    ),
    CheckDef(
        "XC01",
        "cross",
        "Paid amount equals the checkout total",
        True,
        "payment_amount (amount and currency) equals the checkout JWT's totals[type=total].amount "
        "and currency.",
        "Confirms that the amount paid equals the total of the merchant's signed checkout.",
        "code/sdk/schemas/ucp/types/checkout.json (totals); this tool's design",
    ),
    CheckDef(
        "XC02",
        "cross",
        "Payee equals the checkout merchant",
        True,
        "The payment mandate's payee matches the checkout JWT's merchant (by id when both have "
        "one, else name + website).",
        "Confirms that the money went to the merchant that sold the goods.",
        f"{SCH}/payment_mandate.json (payee); this tool's design",
    ),
    CheckDef(
        "XC03",
        "cross",
        "Both mandates bind the same agent key",
        False,
        "The open checkout and open payment mandates carry the same cnf.jwk (compared by RFC "
        "7638 thumbprint). Not normative: a warning only.",
        "Flags checkout and payment approved by different agent keys: allowed, but unusual and "
        "worth a look.",
        f'{SPEC} "Autonomous (Human Not Present)"',
        worst="WARN",
    ),
    CheckDef(
        "XC04",
        "cross",
        "Both mandates signed by the same mandate-issuer key",
        False,
        "The root tokens of the checkout and payment mandate chains verified under the same "
        "mandate_issuer key (compared by RFC 7638 thumbprint). Advisory: a warning only.",
        "Flags mandates issued under different issuer keys. The tool cannot tell which key "
        "belongs to which user or agent provider, and two different issuer keys can mean that "
        "the checkout and the payment were authorised by different people (for example one "
        "user's checkout paid with another user's card).",
        f'{SPEC} "Modes"; this tool\'s design',
        worst="WARN",
    ),
]


def _receipt_defs(prefix: str, kind: str) -> list[CheckDef]:
    group = f"{kind}_receipt"
    role = "merchant" if kind == "checkout" else "payment_processor"
    issuer = "merchant" if kind == "checkout" else "merchant payment processor"
    schema = f"{SCH}/{kind}_receipt.json"
    k = kind.capitalize()
    plaus = (
        "iss equals (or has the same host as) the checkout merchant's website."
        if kind == "checkout"
        else "iss equals (or has the same host as) the payment mandate's pisp.domain_name."
    )
    return [
        CheckDef(
            f"{prefix}01",
            group,
            f"{k} receipt parses",
            True,
            "The receipt is a plain compact JWT (not an SD-JWT) with alg ES256 and JSON-object "
            "header and payload.",
            "Confirms that the receipt can be read; a receipt that does not parse proves nothing.",
            f'{schema}; {AA} "Action Authorization" (Verifier-signed JWT)',
        ),
        CheckDef(
            f"{prefix}02",
            group,
            f"{k} receipt signature ({issuer})",
            True,
            f"The receipt's signature verifies under a key of role '{role}'.",
            f"Confirms that the {issuer} issued this receipt.",
            f'{SPEC} "{"Checkout Mandate" if kind == "checkout" else "Payment Mandate"}"',
        ),
        CheckDef(
            f"{prefix}03",
            group,
            f"{k} receipt fields",
            True,
            f"Fields required by {schema} for the receipt's status are present with the right "
            "types (null members tolerated). The prose variant 'result: success|error' is "
            "accepted with a warning.",
            "Confirms that the receipt carries the identifiers needed to match it with the "
            "issuer's records.",
            f'{schema}; {AA} "Action Authorization"',
        ),
        CheckDef(
            f"{prefix}04",
            group,
            f"{k} receipt references the closed mandate",
            True,
            "reference equals SHA-256 of the closed mandate's issuer-signed JWT (upstream SDK "
            "form) or the sd_hash-form hash of the final segment (prose form, noted).",
            "Confirms that the receipt is for this mandate and not for some other transaction.",
            f'{SPEC} "Dispute"; code/sdk/python/ap2/sdk/mandate.py get_closed_mandate_jwt()',
        ),
        CheckDef(
            f"{prefix}05",
            group,
            f"{k} receipt outcome",
            True,
            "Reads the outcome the receipt states (status 'Success' / 'Error', or the prose "
            "form's result 'success' / 'error'). Success passes; an error is a WARN saying the "
            "step was declined; a success that also carries an error FAILs. The outcome is used "
            "for the report's outcome only if the receipt's signature, required fields, "
            "reference and time checks passed.",
            "Confirms that the step was completed; a rejection receipt documents that it did not "
            "happen.",
            f"{SCH}/types/receipt_status.json",
        ),
        CheckDef(
            f"{prefix}06",
            group,
            f"{k} receipt not earlier than the mandate",
            True,
            "The receipt's iat is not earlier than the closed mandate's iat minus the clock skew.",
            "Confirms that the receipt was issued after the mandate it answers; a receipt issued "
            "before the mandate existed cannot be a response to it.",
            "this tool's design (chronology is not defined upstream)",
        ),
        CheckDef(
            f"{prefix}07",
            group,
            f"{k} receipt issuer plausible",
            False,
            f"Advisory: {plaus} A warning only: iss is self-declared, so it does not decide "
            "whether the receipt counts for the report's outcome (that rests on the signature, "
            "required fields, reference and time checks).",
            "Flags a receipt from an unexpected issuer, which deserves a closer look at who "
            "signed it.",
            f"{schema} (iss)",
            worst="WARN",
        ),
    ]


_DEFS.extend(_receipt_defs("CR", "checkout"))
_DEFS.extend(_receipt_defs("PR", "payment"))

_RP = "verify_bundle(expected=...) (this tool; the relying party's own expectations)"
_DEFS.extend(
    [
        CheckDef(
            "EX01",
            "cross",
            "Agent key as expected",
            False,
            "When an expected agent key (public JWK) is given: the cnf.jwk the closed mandates "
            "are bound to has the same RFC 7638 thumbprint.",
            "Confirms that the mandates were closed by the agent the relying party dealt with, "
            "not by another agent holding a valid delegation.",
            _RP,
        ),
        CheckDef(
            "EX02",
            "cross",
            "Checkout id as expected",
            False,
            "When an expected checkout id is given: it equals the id in the merchant-signed "
            "checkout.",
            "Confirms that the evidence is about the checkout the relying party means.",
            _RP,
        ),
        CheckDef(
            "EX03",
            "cross",
            "Merchant id as expected",
            False,
            "When an expected merchant id is given: it equals the merchant id in the checkout and "
            "the payee id in the closed payment mandate.",
            "Confirms that the evidence is about the merchant the relying party means.",
            _RP,
        ),
        CheckDef(
            "EX04",
            "cross",
            "Total as expected",
            False,
            "When an expected total is given: it equals the checkout total and the paid amount "
            "(amount in minor units and currency).",
            "Confirms that the amount is the one the relying party expects.",
            _RP,
        ),
        CheckDef(
            "EX05",
            "cross",
            "Required constraints present",
            False,
            "When required constraint types are given: the open mandates carry a constraint of "
            "each type.",
            "Confirms that the user's mandate actually limited the agent in the ways the relying "
            "party requires (for example an amount range).",
            _RP,
        ),
    ]
)

REGISTRY: dict[str, CheckDef] = {d.id: d for d in _DEFS}
"""All checks, keyed by ID, in report order."""

if len(REGISTRY) != len(_DEFS):  # pragma: no cover - guards against copy/paste errors
    raise RuntimeError("duplicate check id in registry")


# --------------------------------------------------------------------------- reason codes


@dataclass(frozen=True)
class ReasonText:
    """Plain-language wording for one non-PASS reason code.

    Attributes:
        plain: One sentence a reader without SD-JWT knowledge understands; it is shown before
            the technical detail. May contain the placeholders ``{doc}`` (the document the
            check is about), ``{party}`` (who can supply or explain that document),
            ``{signer}`` (whose signature the check verifies) and ``{kind}`` (``checkout`` or
            ``payment``).
        action: A concrete next step for the analyst (same placeholders), or None when the
            result needs no action (e.g. a check that does not apply).
    """

    plain: str
    action: str | None = None


_ASK_AS_ISSUED = "Ask {party} for {doc} exactly as it was issued, with all of its disclosures."
_ASK_COPY = "Ask {party} for a complete, unmodified copy of {doc}."
_ASK_AGENT_LIMIT = (
    "Ask the agent provider why its agent approved this although the user's mandate does not "
    "allow it."
)
_GET_KEY = (
    "Get the {signer}'s public key directly from the {signer} (not from the bundle) and check "
    "again with {keyopt} FILE (or --trusted-keys FILE)."
)

KEY_OPTIONS: dict[str, str] = {
    "mandate_issuer": "--issuer-key",
    "merchant": "--merchant-key",
    "payment_processor": "--processor-key",
}
"""Command-line option that pins a key of each role (same as ``keys.ROLE_FLAGS``)."""

EXPECT_OPTIONS: dict[str, str] = {
    "EX01": "--expect-agent-key FILE",
    "EX02": "--expect-checkout-id ID",
    "EX03": "--expect-merchant-id ID",
    "EX04": "--expect-total MINOR_UNITS CURRENCY",
    "EX05": "--require-constraint TYPE",
}
"""Command-line option that supplies what each EX check compares against."""

HISTORY_OPTIONS: dict[str, str] = {
    "prior_total": "--prior-total MINOR_UNITS CURRENCY",
    "prior_uses": "--prior-uses N",
}
"""Command-line options that supply the payment history PM39 needs."""

UPSTREAM_REPO = "github.com/google-agentic-commerce/AP2"
UPSTREAM_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"


def spec_reference_text(check_id: str) -> str:
    """The check's spec reference, saying that its paths are in the upstream AP2 repository."""
    ref = REGISTRY[check_id].spec_ref
    return (
        f"{ref} (paths are in the upstream AP2 repository {UPSTREAM_REPO} at commit "
        f"{UPSTREAM_COMMIT[:12]}; 'this tool's design' and docs/bundle-format.md refer to "
        "ap2-evidence itself)"
    )


REASONS: dict[str, ReasonText] = {
    # generic codes
    "blocked": ReasonText(
        "This check could not run because an earlier check it depends on did not pass."
    ),
    "missing_artifact": ReasonText("{doc} is not in the bundle.", "Ask {party} for {doc}."),
    "not_applicable": ReasonText("This check does not apply to this input."),
    "no_key": ReasonText(
        "The {signer}'s signature could not be checked because no public key of the {signer} "
        "was supplied.",
        _GET_KEY,
    ),
    "x5c_unsupported": ReasonText(
        "The {signer}'s signature relies on a certificate chain (x5c), which this version cannot "
        "check.",
        "Get the {signer}'s public key itself from a source you trust and re-run with "
        "--trusted-keys.",
    ),
    "internal_error": ReasonText(
        "This check could not be evaluated on this input.",
        "Check {doc} by hand and report the problem to the ap2-evidence maintainers (with test "
        "data only).",
    ),
    "unspecified": ReasonText("This check did not pass.", None),
    # parsing and token structure
    "parse_error": ReasonText(
        "{doc} cannot be read: it is damaged, truncated or not in the expected format.",
        _ASK_COPY,
    ),
    "alg_not_allowed": ReasonText(
        "{doc} uses a signature algorithm this tool does not accept.",
        "Ask {party} why {doc} is not signed with ES256.",
    ),
    "signature_invalid": ReasonText(
        "The {signer}'s signature on {doc} does not verify: another key signed it, or it was "
        "changed after signing.",
        _GET_KEY + " If it still fails, ask the {signer} whether it issued {doc}.",
    ),
    "unreferenced_disclosure": ReasonText(
        "Part of {doc} was replaced or added after it was issued: one of its disclosures matches "
        "nothing the {signer} signed.",
        _ASK_AS_ISSUED,
    ),
    "duplicate_disclosure": ReasonText(
        "{doc} presents the same disclosure twice, which an unmodified token never does.",
        _ASK_AS_ISSUED,
    ),
    "digest_reused": ReasonText(
        "{doc} uses the same digest twice, which a correctly issued token never does.",
        _ASK_AS_ISSUED,
    ),
    "disclosure_kind_mismatch": ReasonText(
        "{doc} is not a well-formed selective-disclosure token.", _ASK_AS_ISSUED
    ),
    "claim_collision": ReasonText(
        "{doc} is not a well-formed selective-disclosure token: a disclosed claim clashes with a "
        "signed one.",
        _ASK_AS_ISSUED,
    ),
    "bad_digest": ReasonText(
        "{doc} is not a well-formed selective-disclosure token.", _ASK_AS_ISSUED
    ),
    "sd_not_array": ReasonText(
        "{doc} is not a well-formed selective-disclosure token.", _ASK_AS_ISSUED
    ),
    "nested_too_deep": ReasonText(
        "{doc} is nested more deeply than this tool evaluates.",
        "Check {doc} by hand or ask {party} why it is nested this deeply.",
    ),
    "unsupported_sd_alg": ReasonText(
        "{doc} uses a hash algorithm for its disclosures that this tool does not support.",
        "Ask {party} which hash algorithm was used and check {doc} by other means.",
    ),
    "unresolvable": ReasonText("The content of {doc} could not be read.", _ASK_AS_ISSUED),
    "no_mandate_object": ReasonText("{doc} contains no readable mandate.", _ASK_AS_ISSUED),
    "multiple_mandate_objects": ReasonText(
        "{doc} contains more than one mandate, so it is unclear which one was approved.",
        "Ask {party} which mandate was actually approved.",
    ),
    "wrong_vct": ReasonText(
        "{doc} is not the type of mandate it is presented as.", "Ask {party} for the right {doc}."
    ),
    "no_cnf_jwk": ReasonText(
        "The open {kind} mandate does not name the agent key allowed to act for the user.",
        _ASK_AS_ISSUED,
    ),
    "invalid_cnf_jwk": ReasonText(
        "The agent key named in the open {kind} mandate is not a valid key.", _ASK_AS_ISSUED
    ),
    "wrong_typ": ReasonText(
        "{doc} is not marked as an agent-signed mandate.", "Ask {party} for the right {doc}."
    ),
    "intermediate_typ": ReasonText(
        "{doc} is marked as an intermediate delegation step, not as the final agent-signed "
        "mandate.",
        "Ask {party} for the final agent-signed {kind} mandate.",
    ),
    "typ_variant": ReasonText(
        "{doc} uses a variant spelling of its token type; it was accepted, as the official SDK "
        "does."
    ),
    "binding_claim_count": ReasonText(
        "The closed {kind} mandate does not name exactly one open mandate it belongs to.",
        _ASK_AS_ISSUED,
    ),
    "binding_mismatch": ReasonText(
        "The closed {kind} mandate was made for a different open mandate than the one in the "
        "bundle, or that open mandate was changed afterwards.",
        "Ask the agent provider for the open {kind} mandate exactly as its agent received it.",
    ),
    "cnf_in_closed": ReasonText(
        "The closed {kind} mandate names a further key that could act on it, which AP2 v0.2 does "
        "not allow.",
        "Ask the agent provider why the closed {kind} mandate delegates further.",
    ),
    "missing_field": ReasonText("{doc} lacks a field it must have.", _ASK_COPY),
    "wrong_type": ReasonText("{doc} has a field with the wrong type of value.", _ASK_COPY),
    "aud_mismatch": ReasonText(
        "{doc} was presented to a different recipient than expected.",
        "Confirm the expected recipient (aud); if it is right, ask the agent provider why the "
        "mandate was made for someone else.",
    ),
    "nonce_mismatch": ReasonText(
        "{doc} belongs to a different session than expected, which can mean it was replayed.",
        "Confirm the expected nonce; if it is right, ask the agent provider why the mandate "
        "carries another one.",
    ),
    "no_expected_value": ReasonText("No expected value was given, so this was not compared."),
    "no_kb_iat": ReasonText("The closed {kind} mandate has no signing time.", _ASK_COPY),
    "iat_not_integer": ReasonText(
        "The closed {kind} mandate has no usable signing time.", _ASK_COPY
    ),
    "signed_before_open": ReasonText(
        "The agent signed the closed {kind} mandate before the user's open mandate was issued.",
        "Ask the agent provider why its agent signed before the user's authorisation existed.",
    ),
    "signed_after_expiry": ReasonText(
        "The agent signed the closed {kind} mandate after the user's open mandate had expired.",
        "Ask the agent provider why its agent acted after the user's authorisation expired.",
    ),
    "open_iat_after_exp": ReasonText(
        "The open {kind} mandate expires before it was issued, so it was never valid.",
        "Ask the mandate issuer why the open {kind} mandate was issued with these dates.",
    ),
    "after_closed_exp": ReasonText(
        "The {kind} mandate had already expired at the time given with --at.",
        "Confirm the --at time; if it is right, the mandate was not valid at that time.",
    ),
    "not_valid_at": ReasonText(
        "The {kind} mandate was not valid at the time given with --at.",
        "Confirm the --at time; if it is right, the mandate was not valid at that time.",
    ),
    "no_at": ReasonText("No --at time was given, so validity at a given time was not checked."),
    "delegation_unsupported": ReasonText(
        "{doc} passes the authority through more than one agent, which this tool does not verify.",
        "Check the extra delegation steps of {doc} by other means.",
    ),
    "unknown_constraint_type": ReasonText(
        "The user's mandate contains a limit of a type this tool does not know, so it cannot "
        "confirm the limit was respected.",
        "Ask the agent provider what the unknown limit means and check it by hand.",
    ),
    "preset_claim_changed": ReasonText(
        "The agent changed a value the user fixed in advance in the open {kind} mandate.",
        "Ask the agent provider why its agent changed a value the user had fixed.",
    ),
    # constraints
    "malformed_constraint": ReasonText(
        "A limit in the user's {kind} mandate is malformed, so it cannot be evaluated.",
        _ASK_AS_ISSUED,
    ),
    "missing_required_constraint": ReasonText(
        "The user's {kind} mandate lacks a limit its schema expects.",
        "Ask the agent provider whether the open {kind} mandate was issued without this limit.",
    ),
    "no_constraints": ReasonText("The user's {kind} mandate contains no limits at all."),
    "hidden_constraint": ReasonText(
        "A limit in the user's {kind} mandate was withheld from the bundle, so it cannot be "
        "checked.",
        "Ask the agent provider for the open {kind} mandate with all of its disclosures as issued.",
    ),
    "withheld_claim": ReasonText(
        "Part of {doc} was withheld from the bundle, so it is unclear whether it limits the agent.",
        "Ask the agent provider for the {kind} mandate with all of its disclosures as issued.",
    ),
    "no_constraint": ReasonText("The user's mandate sets no limit of this type."),
    "none_revealed": ReasonText(
        "The bundle shows none of the entries the user allowed, so it cannot show that this "
        "one was allowed.",
        "Ask the agent provider for the open {kind} mandate with all of its disclosures as issued.",
    ),
    "merchant_not_allowed": ReasonText(
        "The merchant is not one of the merchants the user allowed.", _ASK_AGENT_LIMIT
    ),
    "payee_not_allowed": ReasonText(
        "The payee is not one of the payees the user allowed.", _ASK_AGENT_LIMIT
    ),
    "item_not_acceptable": ReasonText(
        "The checkout contains an item the user did not allow.", _ASK_AGENT_LIMIT
    ),
    "quantity_exceeded": ReasonText(
        "The checkout contains more of an item than the user allowed.", _ASK_AGENT_LIMIT
    ),
    "requirement_unfilled": ReasonText(
        "The checkout does not contain an item the user's mandate requires.", _ASK_AGENT_LIMIT
    ),
    "too_many_lines": ReasonText(
        "The checkout has more lines than this tool evaluates.", "Check the items by hand."
    ),
    "amount_above_max": ReasonText(
        "The payment is larger than the maximum the user allowed.",
        "Ask the agent provider why its agent approved a payment above the user's limit.",
    ),
    "amount_below_min": ReasonText(
        "The payment is smaller than the minimum the user set.", _ASK_AGENT_LIMIT
    ),
    "currency_mismatch": ReasonText(
        "The payment is in a different currency than the user allowed.", _ASK_AGENT_LIMIT
    ),
    "instrument_not_allowed": ReasonText(
        "The payment uses a card or account the user did not allow.", _ASK_AGENT_LIMIT
    ),
    "no_instrument": ReasonText(
        "The payment mandate does not say which card or account was used.", _ASK_COPY
    ),
    "pisp_not_allowed": ReasonText(
        "The payment goes through a payment initiation provider the user did not allow.",
        _ASK_AGENT_LIMIT,
    ),
    "no_pisp": ReasonText(
        "The payment mandate does not name the payment initiation provider the user's limit "
        "refers to.",
        _ASK_COPY,
    ),
    "execution_date_before_window": ReasonText(
        "The payment is scheduled before the dates the user allowed.", _ASK_AGENT_LIMIT
    ),
    "execution_date_after_window": ReasonText(
        "The payment is scheduled after the dates the user allowed.", _ASK_AGENT_LIMIT
    ),
    "malformed_mandate": ReasonText(
        "{doc} has a malformed value that this check needs.", _ASK_COPY
    ),
    "budget_exceeded": ReasonText(
        "This payment alone exceeds the user's whole budget.",
        "Ask the agent provider why its agent approved a payment above the user's budget.",
    ),
    "recurrence_malformed": ReasonText(
        "The user's rule for repeated payments is malformed, so it cannot limit repeated use.",
        _ASK_AS_ISSUED,
    ),
    "recurrence_missing_companion": ReasonText(
        "The user's rule for repeated payments lacks the amount or budget limit it needs.",
        _ASK_AS_ISSUED,
    ),
    "cumulative_unverifiable": ReasonText(
        "Whether the user's total budget or repeat limit was respected depends on the other "
        "payments made under this mandate, which one bundle does not contain.",
        "Ask the agent provider for all other payments made under the same open payment mandate.",
    ),
    # checkout JWT and links between the documents
    "checkout_jwt_missing": ReasonText(
        "The checkout mandate does not contain the merchant's signed checkout.",
        "Ask the agent provider for the checkout mandate including the merchant's signed checkout.",
    ),
    "not_jws": ReasonText("{doc} is not a readable signed token.", _ASK_COPY),
    "payload_not_object": ReasonText("The content of {doc} cannot be read.", _ASK_COPY),
    "hash_mismatch": ReasonText(
        "The checkout the agent approved is not the merchant's checkout shown in the bundle.",
        "Ask the agent provider and the merchant for the checkout the agent actually approved.",
    ),
    "checkout_hash_missing": ReasonText(
        "The checkout mandate does not say which checkout the agent approved.", _ASK_AS_ISSUED
    ),
    "not_ascii": ReasonText(
        "The merchant's signed checkout contains characters that make its fingerprint ambiguous.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "malformed_checkout": ReasonText(
        "The merchant's checkout has malformed parts; only its readable parts were used.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "not_ucp": ReasonText(
        "The merchant's checkout is not in the standard UCP Checkout format; only its readable "
        "parts were used."
    ),
    "no_merchant": ReasonText(
        "The merchant's checkout does not say who the merchant is.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "merchant_unreadable": ReasonText(
        "The merchant cannot be identified from the checkout.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "line_items_unreadable": ReasonText(
        "The purchased items cannot be read from the merchant's checkout.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "transaction_id_mismatch": ReasonText(
        "The payment mandate is for a different checkout than the one in the bundle.",
        "Ask the agent provider which checkout this payment was for.",
    ),
    "checkout_hash_mismatch": ReasonText(
        "The payment mandate and the checkout mandate refer to different checkouts.",
        "Ask the agent provider which checkout this payment was for.",
    ),
    "reference_mismatch": ReasonText(
        "{doc} refers to a different document than the one in the bundle.",
        "Ask {party} for the version of {doc} that belongs to the documents in this bundle.",
    ),
    "issuer_jwt_form_with_withheld": ReasonText(
        "The link between the payment and checkout authorisations can only be confirmed with "
        "the complete open checkout mandate.",
        "Ask the agent provider for the open checkout mandate with all of its disclosures as "
        "issued.",
    ),
    "amount_mismatch": ReasonText(
        "The amount paid differs from the total of the merchant's signed checkout.",
        "Ask the agent provider why the amount paid differs from the merchant's checkout total.",
    ),
    "negative_total": ReasonText(
        "The total of the merchant's checkout is negative.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "no_single_total": ReasonText(
        "The merchant's checkout does not state one total.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "total_unreadable": ReasonText(
        "The total cannot be read from the merchant's checkout.",
        "Ask the merchant for its signed checkout as issued.",
    ),
    "payee_mismatch": ReasonText(
        "The money went to a different payee than the merchant in the signed checkout.",
        "Ask the agent provider why the payee differs from the merchant that sold the goods.",
    ),
    "agent_key_differs": ReasonText(
        "The checkout and the payment were approved by different agent keys.",
        "Ask the agent provider why two different agent keys were used.",
    ),
    "issuer_key_differs": ReasonText(
        "The checkout and payment mandates were issued under different keys, which can mean "
        "that different people authorised them.",
        "Find out who holds each mandate-issuer key before relying on the bundle.",
    ),
    # receipts
    "sd_jwt_receipt": ReasonText(
        "{doc} is in the wrong format (a selective-disclosure token, not a plain signed receipt).",
        "Ask {party} for {doc} as a plain signed receipt.",
    ),
    "conflicting_outcome": ReasonText(
        "{doc} states both success and failure.", "Ask {party} what the outcome actually was."
    ),
    "prose_receipt_form": ReasonText(
        "{doc} uses the form described in the AP2 prose rather than the official SDK; it was "
        "accepted."
    ),
    "rejected": ReasonText(
        "{doc} says the transaction was rejected.",
        "Ask {party} whether the transaction was completed later; this receipt documents a "
        "rejection.",
    ),
    "receipt_before_mandate": ReasonText(
        "{doc} was issued before the mandate it answers existed.",
        "Ask {party} why its receipt predates the mandate.",
    ),
    "issuer_mismatch": ReasonText(
        "{doc} was issued by an unexpected party.", "Check who issued {doc}."
    ),
    # bundle
    "not_object": ReasonText(
        "The input is not an evidence bundle.",
        "Ask whoever supplied the bundle for it in the documented bundle format.",
    ),
    "bad_version": ReasonText(
        "The bundle is not in a format version this tool reads.",
        "Ask whoever supplied the bundle for it in the documented bundle format.",
    ),
    "bad_member_type": ReasonText(
        "An entry of the bundle has the wrong type.",
        "Ask whoever supplied the bundle for it in the documented bundle format.",
    ),
    "too_long": ReasonText(
        "An entry of the bundle is longer than this tool accepts.",
        "Check the bundle by hand; ask whoever supplied it why the entry is this long.",
    ),
    "unknown_member": ReasonText(
        "The bundle contains an entry this tool does not know; it was ignored.",
        "Check the bundle's entry names for typos.",
    ),
    "no_artifacts": ReasonText(
        "The bundle contains none of the four documents.",
        "Ask whoever supplied the bundle for the mandates and receipts.",
    ),
    "invalid_key": ReasonText(
        "A key supplied with the bundle or with --trusted-keys is not a valid public key.",
        "Replace the invalid key with the party's public key from a source you trust.",
    ),
    "unknown_role": ReasonText(
        "A key was supplied for a role this tool does not know; it was ignored.",
        "Check the role names of the supplied keys.",
    ),
    "no_keys": ReasonText(
        "No public keys were supplied, so no signature of the mandate issuer, merchant or "
        "payment processor could be checked.",
        "Get the public keys directly from the mandate issuer, the merchant and the payment "
        "processor and check again with --issuer-key, --merchant-key and --processor-key (or "
        "--trusted-keys FILE).",
    ),
    "key_not_pinned": ReasonText(
        "The {signer}'s signature was not checked with a pinned key (one you gave this tool "
        "with --trusted-keys), as was required.",
        _GET_KEY,
    ),
    # added with the second review round
    "payee_details_differ": ReasonText(
        "The payee in the agent-signed payment mandate has the merchant's id but a different "
        "name or website than the merchant-signed checkout.",
        "Ask the agent provider why the payee's name or website differs from the merchant's "
        "own checkout, and confirm with the merchant who was paid.",
    ),
    "merchant_details_differ": ReasonText(
        "The merchant in the merchant-signed checkout has the id of a merchant the user allowed, "
        "but a different name or website than the user's mandate gives for it.",
        "Confirm with the merchant the user allowed that this checkout is theirs, and ask the "
        "agent provider why the agent accepted a merchant whose name or website differs.",
    ),
    "success_with_error": ReasonText(
        "{doc} says Success but also carries an error code, so its outcome is unclear.",
        "Ask {party} what the outcome of the transaction actually was.",
    ),
    "checkout_canceled": ReasonText(
        "The merchant's signed checkout is marked as canceled.",
        "Ask the merchant whether this checkout was canceled and whether the payment was refunded.",
    ),
    "checkout_not_final": ReasonText(
        "The merchant's signed checkout is not marked as ready or completed.",
        "Ask the merchant whether this checkout was final when the agent approved it.",
    ),
    "reference_unverifiable_withheld": ReasonText(
        "The user's payment authorisation does not match the checkout instructions as they "
        "appear in this bundle. That is what checkout instructions shown with some parts left "
        "out look like, and also what a payment authorisation for a different checkout looks "
        "like; this bundle cannot tell the two apart.",
        "Ask the agent provider for the open checkout mandate exactly as issued, with all of "
        "its disclosures, and check again.",
    ),
    "history_currency_mismatch": ReasonText(
        "The earlier total you supplied is in a different currency than the user's budget, so "
        "the two cannot be added up.",
        "Supply the earlier total in the budget's currency with --prior-total MINOR_UNITS "
        "CURRENCY and check again.",
    ),
    "too_large": ReasonText(
        "A limit in {doc} is too large to evaluate within this tool's limits.",
        "Check this limit of {doc} by hand.",
    ),
    "unsigned_receipt": ReasonText(
        "{doc} is a plain unsigned record, not a signed token, so it proves nothing about who "
        "issued it.",
        "Ask {party} for {doc} as a signed receipt.",
    ),
    "aud_missing": ReasonText(
        "{doc} does not name the recipient it was presented to.",
        "Ask the agent provider why the mandate names no recipient (aud).",
    ),
    "nonce_missing": ReasonText(
        "{doc} carries no session value (nonce), so a replay cannot be ruled out.",
        "Ask the agent provider why the mandate carries no nonce.",
    ),
    # added with the third review round
    "declined": ReasonText(
        "{doc} says the transaction was declined.",
        "Ask {party} what happened to the transaction.",
    ),
    "empty_checkout": ReasonText(
        "The merchant's checkout contains no items, so it cannot match the items the user allowed.",
        "Ask the merchant for its signed checkout with the items that were bought.",
    ),
    "history_needed": ReasonText(
        "The user's mandate sets a cumulative limit (budget or number of uses), and the verifier "
        "was not told what had been spent or used before this payment.",
        "Get what was already spent and how many payments were already made under this "
        "mandate from the mandate issuer's or payment processor's records, and check again "
        "with --prior-total MINOR_UNITS CURRENCY and --prior-uses N.",
    ),
    "occurrences_exceeded": ReasonText(
        "Together with the earlier payments you said were made under this mandate, this "
        "payment is more than the number of payments the user allowed.",
        "Confirm the number of earlier payments with the mandate issuer's or payment "
        "processor's records; if it is right, ask the agent provider why its agent made one "
        "payment too many.",
    ),
    # what the relying party expected (EX checks)
    "not_expected": ReasonText("No expected value was given, so this was not compared."),
    "agent_key_mismatch": ReasonText(
        "The agent key in the mandates is not the agent key you expected.",
        "Ask the agent provider which agent key it uses and why the mandates name another one.",
    ),
    "checkout_id_mismatch": ReasonText(
        "The checkout in the bundle is not the checkout you expected.",
        "Check that you have the bundle for the right order; ask the merchant which checkout "
        "this payment belongs to.",
    ),
    "merchant_id_mismatch": ReasonText(
        "The merchant in the bundle is not the merchant you expected.",
        "Check that you have the bundle for the right merchant; ask the agent provider why the "
        "agent dealt with another merchant.",
    ),
    "total_mismatch": ReasonText(
        "The checkout total is not the total you expected.",
        "Compare the expected total with the merchant's records and ask the merchant which "
        "total it charged.",
    ),
    "constraint_missing": ReasonText(
        "The user's mandate lacks a limit you required it to contain.",
        "Ask the agent provider why the open mandate was issued without this limit.",
    ),
}
"""Plain wording and next step for every reason code (see :class:`ReasonText`)."""

CHECK_REASONS: dict[tuple[str, str], ReasonText] = {
    ("PR05", "declined"): ReasonText(
        "The Payment Receipt says the payment was declined; on its own it shows that no money "
        "moved.",
        "Treat the payment as not made unless the payment processor confirms a later "
        "successful attempt.",
    ),
    ("CR05", "declined"): ReasonText(
        "The Checkout Receipt says the merchant declined or failed the order.",
        "Ask the merchant whether the order was declined and whether any payment for it was "
        "refunded.",
    ),
    ("PM39", "budget_exceeded"): ReasonText(
        "Together with the amount you said was already spent under this mandate, this payment "
        "exceeds the user's budget.",
        "Confirm the earlier spend with the mandate issuer's or payment processor's records; if "
        "it is right, ask the agent provider why its agent approved a payment that takes the "
        "total over the user's budget.",
    ),
    **{
        (f"{p}04", code): ReasonText(
            f"Part of the user's {words} was changed after they were signed.",
            f"Ask the agent provider for the user's original {words}, exactly as they were issued.",
        )
        for p, words in (("CM", "shopping instructions"), ("PM", "payment instructions"))
        for code in ("unreferenced_disclosure", "duplicate_disclosure")
    },
    **{
        (f"{p}10", code): ReasonText(
            f"Part of the agent's signed {k} approval was changed after the agent signed it.",
            f"Ask the agent provider for the agent's original {k} approval, exactly as signed.",
        )
        for p, k in (("CM", "checkout"), ("PM", "payment"))
        for code in ("unreferenced_disclosure", "duplicate_disclosure")
    },
    **{
        (f"{p}08", "signature_invalid"): ReasonText(
            f"The agent's {k} approval was not signed by the agent key the user authorised.",
            f"Ask the agent provider which key signed the agent's {k} approval and why it is "
            "not the agent key the user authorised.",
        )
        for p, k in (("CM", "checkout"), ("PM", "payment"))
    },
    ("PM31", "reference_mismatch"): ReasonText(
        "The user's payment authorisation refers to a different checkout authorisation than the "
        "one in the bundle, or that checkout authorisation was changed.",
        "Ask the agent provider for the open checkout mandate exactly as issued, the one the "
        "payment mandate refers to.",
    ),
    ("PM30", "reference_mismatch"): ReasonText(
        "The payment mandate is for a different checkout than the one in the bundle.",
        "Ask the agent provider which checkout this payment was for.",
    ),
    ("CR04", "reference_mismatch"): ReasonText(
        "The Checkout Receipt is for a different checkout mandate, not the one in this bundle.",
        "Ask the merchant for the Checkout Receipt it issued for this checkout mandate.",
    ),
    ("PR04", "reference_mismatch"): ReasonText(
        "The Payment Receipt is for a different payment mandate, not the one in this bundle.",
        "Ask the payment processor for the Payment Receipt it issued for this payment mandate.",
    ),
    ("CM34", "none_revealed"): ReasonText(
        "The bundle shows none of the merchants the user allowed, so it cannot show that this "
        "merchant was allowed.",
        "Ask the agent provider for the open checkout mandate with all of its disclosures as "
        "issued.",
    ),
    ("PM33", "none_revealed"): ReasonText(
        "The bundle shows none of the payees the user allowed, so it cannot show that this "
        "payee was allowed.",
        "Ask the agent provider for the open payment mandate with all of its disclosures as "
        "issued.",
    ),
    ("PM34", "none_revealed"): ReasonText(
        "The bundle shows none of the cards or accounts the user allowed, so it cannot show "
        "that this one was allowed.",
        "Ask the agent provider for the open payment mandate with all of its disclosures as "
        "issued.",
    ),
    ("CM35", "malformed_checkout"): ReasonText(
        "The items in the merchant's checkout are not readable line items, so the checkout "
        "cannot match the items the user allowed.",
        "Ask the merchant for its signed checkout with the items that were bought.",
    ),
}
"""Wording for (check, reason) pairs where the generic :data:`REASONS` text is too vague."""

WARN_PHRASES: dict[str, str] = {
    "payee_details_differ": "the payee's name or website differs from the merchant's checkout",
    "merchant_details_differ": "the checkout merchant's name or website differs from the "
    "merchant the user allowed",
    "checkout_not_final": "the merchant's checkout was not marked as final",
    "not_ucp": "the merchant's checkout is not in the standard UCP format",
    "issuer_mismatch": "a receipt was issued by an unexpected party",
    "agent_key_differs": "checkout and payment were approved by different agent keys",
    "issuer_key_differs": "the two mandates were signed by different mandate-issuer keys",
    "cumulative_unverifiable": "the user's total budget or repeat limit could not be checked",
    "typ_variant": "a token uses a variant spelling of its type",
    "prose_receipt_form": "a receipt uses an older form",
    "unknown_member": "the file contains an unknown entry that was ignored",
    "unknown_role": "a key for an unknown role was ignored",
    "missing_required_constraint": "the user's mandate lacks a limit its schema expects",
    "aud_missing": "a mandate names no recipient",
    "nonce_missing": "a mandate carries no session value (nonce)",
    "invalid_key": "a supplied key is invalid",
}
"""Short phrases for WARN reasons, used inside a VERIFIED finding ("with 1 warning: ...")."""


def warn_phrase(check_id: str, reason: str | None) -> str:
    """The short phrase for a WARN result (falls back to its plain sentence)."""
    if reason in WARN_PHRASES:
        return WARN_PHRASES[reason]
    rt = reason_text(check_id, reason)
    if rt is not None:
        return rt.plain[:1].lower() + rt.plain[1:].rstrip(".")
    return f"check {check_id} raised a warning"


GENERIC_ACTION = "Look at {id} in the list of all checks and ask {party} about it."
"""Fallback next step for a reason code without its own action."""


def context(check_id: str) -> dict[str, str]:
    """Placeholder values (doc, party, signer, kind) for the wording of ``check_id``."""
    prefix = check_id.rstrip("0123456789")
    num = int(check_id[len(prefix) :] or 0)
    if prefix in ("CM", "PM"):
        kind = "checkout" if prefix == "CM" else "payment"
        if prefix == "CM" and 30 <= num <= 33:
            return {
                "doc": "the merchant's signed checkout",
                "party": "the merchant",
                "signer": "merchant",
                "kind": kind,
            }
        if num >= 30:
            doc = f"the {kind} mandate"
        elif num in (2, 3, 4, 5, 6, 17, 21):
            doc = f"the open {kind} mandate"
        elif num in (7, 8, 9, 10, 11, 12, 13, 14, 15):
            doc = f"the closed {kind} mandate"
        else:
            doc = f"the {kind} mandate"
        signer = "agent" if 7 <= num <= 15 else "mandate issuer"
        return {"doc": doc, "party": "the agent provider", "signer": signer, "kind": kind}
    if prefix in ("CR", "PR"):
        checkout = prefix == "CR"
        return {
            "doc": "the Checkout Receipt" if checkout else "the Payment Receipt",
            "party": "the merchant" if checkout else "the payment processor",
            "signer": "merchant" if checkout else "payment processor",
            "kind": "checkout" if checkout else "payment",
        }
    if prefix == "EX":
        return {
            "doc": "the bundle",
            "party": "the agent provider",
            "signer": "mandate issuer",
            "kind": "checkout",
        }
    if prefix == "XC":
        return {
            "doc": "the payment mandate and the merchant's checkout",
            "party": "the agent provider",
            "signer": "mandate issuer",
            "kind": "payment",
        }
    return {
        "doc": "the evidence bundle",
        "party": "whoever supplied the bundle",
        "signer": "signer",
        "kind": "checkout",
    }


class _Ctx(dict[str, str]):
    def __missing__(self, key: str) -> str:  # an unknown placeholder never raises
        return "{" + key + "}"


def _fill(template: str, ctx: dict[str, str]) -> str:
    text = template.format_map(_Ctx(ctx))
    return text[:1].upper() + text[1:]


def reason_text(check_id: str, reason: str | None) -> ReasonText | None:
    """The filled-in plain wording and action for a result, or None if the code is unknown."""
    if reason is None:
        return None
    rt = CHECK_REASONS.get((check_id, reason)) or REASONS.get(reason)
    if rt is None:
        return None
    ctx = dict(context(check_id), id=check_id)
    role = ctx.get("signer", "").replace(" ", "_")
    ctx["keyopt"] = KEY_OPTIONS.get(role, "--trusted-keys")
    return ReasonText(_fill(rt.plain, ctx), _fill(rt.action, ctx) if rt.action else None)


def generic_action(check_id: str) -> str:
    """The fallback next step for ``check_id``."""
    return _fill(GENERIC_ACTION, dict(context(check_id), id=check_id))


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def checks_markdown() -> str:
    """Render the catalogue as the Markdown document ``docs/checks.md``."""
    lines = [
        "# Check catalogue",
        "",
        "<!-- Generated by `python -m ap2_evidence.checksdoc`; do not edit by hand. -->",
        "",
        "Every report contains exactly one result for each check below. Statuses are PASS, "
        "FAIL, WARN and SKIP. The verdict is FAILED if any check FAILs, otherwise INCOMPLETE "
        "if any *required* check is SKIP, otherwise VERIFIED. WARN never changes the verdict.",
        "",
        '"Required" is the default; a result can be marked not required when the check does '
        "not apply (for example aud/nonce when no expected value was supplied, or key-binding "
        "checks for a directly signed one-segment mandate).",
        "",
        "Spec references are paths in the upstream repository "
        "github.com/google-agentic-commerce/AP2 at commit "
        "e1ea56db72a6385bce3e5c1112b3a56ce60acb43.",
        "",
        "Every non-PASS result also carries a machine-readable `reason` code (listed in "
        "docs/output-formats.md).",
        "",
        f"{len(REGISTRY)} checks.",
        "",
    ]
    for group, label in GROUPS.items():
        lines += [
            f"## {label}",
            "",
            "| ID | Check | Required | Worst | What it checks | What this check is for | "
            "Spec reference |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for d in REGISTRY.values():
            if d.group != group:
                continue
            lines.append(
                f"| {d.id} | {_md(d.title)} | {'yes' if d.required else 'no'} | {d.worst} | "
                f"{_md(d.what)} | {_md(d.why)} | {_md(d.spec_ref)} |"
            )
        lines.append("")
    lines += [
        "## Reason codes in plain words",
        "",
        "Reports put the plain sentence before the technical detail of a non-PASS result and "
        "build the 'What to do next' list from the next steps. In the wording, `{doc}` is the "
        "document the check is about, `{party}` who can supply or explain it, `{signer}` whose "
        "signature the check verifies and `{kind}` is checkout or payment. A code without a "
        "next step needs no action.",
        "",
        "| Reason | Plain wording | Next step |",
        "| --- | --- | --- |",
    ]
    for code, rt in REASONS.items():
        lines.append(f"| `{code}` | {_md(rt.plain)} | {_md(rt.action or '-')} |")
    lines += [
        "",
        "Overrides for specific checks:",
        "",
        "| Check | Reason | Plain wording | Next step |",
        "| --- | --- | --- | --- |",
    ]
    for (cid, code), rt in CHECK_REASONS.items():
        lines.append(f"| {cid} | `{code}` | {_md(rt.plain)} | {_md(rt.action or '-')} |")
    lines.append("")
    return "\n".join(lines)
