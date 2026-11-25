"""Demo transaction builder.

Builds a complete AP2 v0.2 transaction in the upstream wire shape with fresh
throwaway P-256 keys: a merchant-signed UCP checkout JWT, an open checkout
mandate signed by a "mandate issuer" key and closed by the agent key it binds,
the same for the payment mandate, and signed checkout / payment receipts.

:class:`DemoBuilder` exposes every piece of content so tests can change one
thing and check that exactly the right check notices. :func:`build_demo_bundle`
also models four realistic dispute scenarios (``tamper``).
"""

from __future__ import annotations

import copy
import json
import random
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .bundle import BUNDLE_VERSION
from .jose import b64url_encode, hash_b64, public_jwk, sign_es256

TAMPER_MODES: dict[str, str] = {
    "amount": "The agent validly signs a closed payment mandate for USD 250.00, more than the "
    "USD 200.00 the user allowed and more than the USD 199.00 checkout total.",
    "receipt": "The payment processor's receipt is validly signed but belongs to a different "
    "payment mandate (its reference does not match).",
    "disclosure": "After issuance, the allowed-merchant disclosure of the open checkout mandate "
    "is swapped for one naming a different merchant.",
    "key": "The closed payment mandate is signed by a key other than the agent key bound in the "
    "open payment mandate.",
}
"""Supported ``tamper`` values and the dispute scenario each one models."""


class _Auto:
    """Placeholder for values the builder computes (hashes, the checkout JWT)."""

    def __repr__(self) -> str:
        return "AUTO"

    def __copy__(self) -> _Auto:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> _Auto:
        return self


AUTO: Any = _Auto()
"""Sentinel: let :class:`DemoBuilder` fill in the value."""


@dataclass
class SdElem:
    """Mark an array element as selectively disclosable (``{"...": digest}``)."""

    value: Any


@dataclass
class SdProp:
    """Mark an object property as selectively disclosable (``_sd``)."""

    value: Any


class _SdIssuer:
    """Turns content with :class:`SdElem` / :class:`SdProp` markers into payload + disclosures."""

    def __init__(self, rng: random.Random | None) -> None:
        self.rng = rng
        self.disclosures: list[str] = []

    def _salt(self) -> str:
        raw = self.rng.randbytes(16) if self.rng is not None else secrets.token_bytes(16)
        return b64url_encode(raw)

    def _disclose(self, arr: list[Any]) -> str:
        disc = b64url_encode(json.dumps(arr).encode("utf-8"))
        self.disclosures.append(disc)
        return hash_b64(disc, "sha-256")

    def encode(self, node: Any) -> Any:
        if isinstance(node, dict):
            digests: list[str] = []
            rest: dict[str, Any] = {}
            for k, v in node.items():
                if isinstance(v, SdProp):
                    digests.append(self._disclose([self._salt(), k, self.encode(v.value)]))
                else:
                    rest[k] = self.encode(v)
            return {"_sd": digests, **rest} if digests else rest
        if isinstance(node, list):
            out: list[Any] = []
            for e in node:
                if isinstance(e, SdElem):
                    out.append({"...": self._disclose([self._salt(), self.encode(e.value)])})
                else:
                    out.append(self.encode(e))
            return out
        return node


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@dataclass
class DemoKeys:
    """Throwaway keys of all parties of the demo transaction."""

    issuer: ec.EllipticCurvePrivateKey = field(default_factory=_new_key)
    agent: ec.EllipticCurvePrivateKey = field(default_factory=_new_key)
    merchant: ec.EllipticCurvePrivateKey = field(default_factory=_new_key)
    processor: ec.EllipticCurvePrivateKey = field(default_factory=_new_key)
    issuer_kid: str = "demo-agent-provider-key-1"
    merchant_kid: str = "merchant-key-1"
    processor_kid: str = "merchant-payment-processor-key-1"


MERCHANT = {"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"}
ITEM_ID = "supershoe_limited_edition_gold_sneaker_womens_9_0"
INSTRUMENT = {"id": "card_4242", "type": "card", "description": "Card ending 4242"}
PISP = {
    "legal_name": "Demo Payments Ltd.",
    "brand_name": "DemoPay",
    "domain_name": "pay.demo-processor.example",
}


def _strip(seg: str) -> str:
    return seg[:-1] if seg.endswith("~") else seg


def _apply(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overrides.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


@dataclass
class DemoArtifacts:
    """Everything produced by :meth:`DemoBuilder.build`."""

    bundle: dict[str, Any]
    checkout_jwt: str
    open_checkout: str
    closed_checkout: str
    open_payment: str
    closed_payment: str
    checkout_receipt: str
    payment_receipt: str
    open_checkout_as_issued: str = ""
    """The open checkout segment with every disclosure (before :attr:`DemoBuilder.withhold`)."""


class DemoBuilder:
    """Mutable recipe for a demo transaction; change attributes, then call :meth:`build`."""

    def __init__(
        self,
        *,
        keys: DemoKeys | None = None,
        now: int | None = None,
        seed: int | None = None,
    ) -> None:
        """Prepare default content for a valid transaction issued an hour before ``now``."""
        self.keys = keys or DemoKeys()
        self.rng = random.Random(seed) if seed is not None else None
        self.now = int(time.time()) if now is None else now
        self.payment_agent: ec.EllipticCurvePrivateKey | None = None
        t0 = self.now - 3600
        self.t_open = t0
        agent_jwk = public_jwk(self.keys.agent)

        self.checkout_header: dict[str, Any] = {
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.keys.merchant_kid,
        }
        self.checkout_payload: dict[str, Any] = {
            "id": "demo-checkout-0001",
            "merchant": dict(MERCHANT),
            "line_items": [
                {
                    "id": "li_0",
                    "item": {
                        "id": ITEM_ID,
                        "title": "Supershoe Limited Edition Gold Sneaker Womens 9",
                        "price": 19900,
                    },
                    "quantity": 1,
                    "totals": [
                        {"type": "subtotal", "amount": 19900},
                        {"type": "total", "amount": 19900},
                    ],
                }
            ],
            "status": "ready_for_complete",
            "currency": "USD",
            "totals": [{"type": "subtotal", "amount": 19900}, {"type": "total", "amount": 19900}],
            "links": [
                {"type": "privacy_policy", "url": "https://demo-merchant.example/privacy"},
                {"type": "terms_of_service", "url": "https://demo-merchant.example/tos"},
            ],
        }
        self.open_header: dict[str, Any] = {
            "alg": "ES256",
            "typ": "example+sd-jwt",
            "kid": self.keys.issuer_kid,
        }
        self.closed_header: dict[str, Any] = {"alg": "ES256", "typ": "kb+sd-jwt"}

        self.open_checkout: dict[str, Any] = {
            "vct": "mandate.checkout.open.1",
            "constraints": [
                {
                    "type": "checkout.line_items",
                    "items": [
                        {
                            "id": "line_1",
                            "acceptable_items": [
                                SdElem({"id": ITEM_ID, "title": "SuperShoe Limited Edition Gold"})
                            ],
                            "quantity": 1,
                        }
                    ],
                },
                {"type": "checkout.allowed_merchants", "allowed": [SdElem(dict(MERCHANT))]},
            ],
            "cnf": {"jwk": agent_jwk},
            "iat": t0,
            "exp": t0 + 3600,
        }
        self.closed_checkout: dict[str, Any] = {
            "vct": "mandate.checkout.1",
            "checkout_hash": AUTO,
            "checkout_jwt": SdProp(AUTO),
        }
        self.closed_checkout_kb: dict[str, Any] = {
            "iat": t0 + 19,
            "aud": "merchant",
            "nonce": "demo-checkout-nonce-7f3a",
        }
        self.open_payment: dict[str, Any] = {
            "vct": "mandate.payment.open.1",
            "constraints": [
                {"type": "payment.amount_range", "currency": "USD", "max": 20000, "min": 0},
                {"type": "payment.allowed_payees", "allowed": [SdElem(dict(MERCHANT))]},
                {
                    "type": "payment.allowed_payment_instruments",
                    "allowed": [SdElem(dict(INSTRUMENT))],
                },
                {"type": "payment.reference", "conditional_transaction_id": AUTO},
            ],
            "cnf": {"jwk": agent_jwk},
            "iat": t0,
            "exp": t0 + 3600,
        }
        self.closed_payment: dict[str, Any] = {
            "vct": "mandate.payment.1",
            "transaction_id": AUTO,
            "payee": dict(MERCHANT),
            "payment_amount": {"amount": 19900, "currency": "USD"},
            "payment_instrument": dict(INSTRUMENT),
            "pisp": dict(PISP),
        }
        self.closed_payment_kb: dict[str, Any] = {
            "iat": t0 + 13,
            "aud": "credential-provider",
            "nonce": "demo-payment-nonce-2c9d",
        }
        self.closed_checkout_signer: ec.EllipticCurvePrivateKey | None = None
        self.closed_payment_signer: ec.EllipticCurvePrivateKey | None = None
        self.receipt_header: dict[str, dict[str, Any]] = {
            "checkout": {"alg": "ES256", "typ": "JWT", "kid": self.keys.merchant_kid},
            "payment": {"alg": "ES256", "typ": "JWT", "kid": self.keys.processor_kid},
        }
        self.checkout_receipt: dict[str, Any] = {
            "status": "Success",
            "iss": MERCHANT["website"],
            "iat": t0 + 25,
            "reference": AUTO,
            "error": None,
            "error_description": None,
            "order_id": "order-demo-0001",
        }
        self.payment_receipt: dict[str, Any] = {
            "status": "Success",
            "iss": PISP["domain_name"],
            "iat": t0 + 28,
            "reference": AUTO,
            "error": None,
            "error_description": None,
            "payment_id": "pay-demo-0001",
            "psp_confirmation_id": "psp-demo-0001",
            "network_confirmation_id": "net-demo-0001",
        }
        self.checkout_receipt_signer: ec.EllipticCurvePrivateKey | None = None
        self.payment_receipt_signer: ec.EllipticCurvePrivateKey | None = None
        self.expected: dict[str, Any] = {
            "checkout": {"aud": "merchant", "nonce": "demo-checkout-nonce-7f3a"},
            "payment": {"aud": "credential-provider", "nonce": "demo-payment-nonce-2c9d"},
        }
        self.binding: dict[str, str] = {"checkout": "sd_hash", "payment": "sd_hash"}
        """Per chain: ``sd_hash`` (default) or ``issuer_jwt_hash`` binding of the closed token."""
        self.reference_form: dict[str, str] = {"checkout": "sdk", "payment": "sdk"}
        """Per receipt: ``sdk`` (SHA-256 of the leaf JWT) or ``prose`` (sd_hash form)."""
        self.direct_payment = False
        """Make the payment mandate a directly signed closed mandate (human present)."""
        self.withhold: dict[str, Callable[[list[Any]], bool]] = {}
        """Per chain: drop open-mandate disclosures (decoded arrays) for which this returns True,
        as an agent withholding them would; everything downstream binds to what is presented."""
        self.payment_issuer: tuple[ec.EllipticCurvePrivateKey, str] | None = None
        """Sign the open payment mandate with this (key, kid) instead of the issuer key."""
        self.reference_cti = "sd_hash"
        """Form of payment.reference.conditional_transaction_id: ``sd_hash`` (hash of the open
        checkout token as issued, with all disclosures, as upstream does), ``issuer_jwt`` (hash
        of its issuer-signed JWT only) or ``presented`` (hash of the token as presented, after
        :attr:`withhold` removed disclosures; not what upstream does)."""
        self.note = (
            "Demo bundle generated by ap2-evidence with throwaway keys. Not a real transaction."
        )

    # ------------------------------------------------------------------ building blocks

    def _root(
        self,
        mandate: dict[str, Any],
        header: dict[str, Any],
        signer: ec.EllipticCurvePrivateKey | None = None,
    ) -> str:
        iss = _SdIssuer(self.rng)
        payload = {"delegate_payload": iss.encode([SdElem(mandate)]), "_sd_alg": "sha-256"}
        jwt = sign_es256(header, payload, signer or self.keys.issuer)
        return jwt + "~" + "".join(d + "~" for d in iss.disclosures)

    def _present(self, kind: str, token: str) -> str:
        pred = self.withhold.get(kind)
        if pred is None:
            return token
        from .jose import b64url_decode

        jwt, *discs = token.split("~")
        keep = [d for d in discs if d and not pred(json.loads(b64url_decode(d)))]
        return jwt + "~" + "".join(d + "~" for d in keep)

    def _kb(
        self,
        mandate: dict[str, Any],
        prev: str,
        claims: dict[str, Any],
        signer: ec.EllipticCurvePrivateKey,
        binding: str = "sd_hash",
    ) -> str:
        iss = _SdIssuer(self.rng)
        base: dict[str, Any] = {"delegate_payload": iss.encode([SdElem(mandate)])}
        base.update(
            {
                "iat": claims.get("iat"),
                "aud": claims.get("aud"),
                "nonce": claims.get("nonce"),
                binding: hash_b64(prev if binding == "sd_hash" else prev.split("~", 1)[0]),
                "_sd_alg": "sha-256",
            }
        )
        payload = _apply(
            base, {k: v for k, v in claims.items() if k not in ("iat", "aud", "nonce")}
        )
        for k in ("iat", "aud", "nonce"):
            if k in claims and claims[k] is None:
                payload.pop(k, None)
        jwt = sign_es256(self.closed_header, payload, signer)
        return jwt + "~" + "".join(d + "~" for d in iss.disclosures)

    def build(self) -> DemoArtifacts:
        """Sign everything and return the tokens and the bundle."""
        k = self.keys
        checkout_jwt = sign_es256(self.checkout_header, self.checkout_payload, k.merchant)
        cjwt_hash = hash_b64(checkout_jwt, "sha-256")

        open_checkout_issued = self._root(copy.deepcopy(self.open_checkout), self.open_header)
        open_checkout = self._present("checkout", open_checkout_issued)

        closed_c = copy.deepcopy(self.closed_checkout)
        if closed_c.get("checkout_hash") is AUTO:
            closed_c["checkout_hash"] = cjwt_hash
        cj = closed_c.get("checkout_jwt")
        if isinstance(cj, SdProp) and cj.value is AUTO:
            closed_c["checkout_jwt"] = SdProp(checkout_jwt)
        elif cj is AUTO:
            closed_c["checkout_jwt"] = checkout_jwt
        closed_checkout = self._kb(
            closed_c,
            open_checkout,
            self.closed_checkout_kb,
            self.closed_checkout_signer or k.agent,
            self.binding["checkout"],
        )

        open_p = copy.deepcopy(self.open_payment)
        cons: Any = open_p.get("constraints", [])
        if isinstance(cons, SdProp):
            cons = cons.value
        # Upstream computes the reference over the open checkout token as issued (with every
        # disclosure), before the agent withholds any of them when presenting it.
        if self.reference_cti == "sd_hash":
            cti = hash_b64(open_checkout_issued, "sha-256")
        elif self.reference_cti == "presented":
            cti = hash_b64(open_checkout, "sha-256")
        else:
            cti = hash_b64(open_checkout_issued.split("~", 1)[0], "sha-256")
        for c in cons if isinstance(cons, list) else []:
            inner = c.value if isinstance(c, SdElem) else c
            if isinstance(inner, dict) and inner.get("conditional_transaction_id") is AUTO:
                inner["conditional_transaction_id"] = cti
        if self.payment_agent is not None:
            open_p["cnf"] = {"jwk": public_jwk(self.payment_agent)}
        p_header, p_signer = self.open_header, None
        if self.payment_issuer is not None:
            p_signer = self.payment_issuer[0]
            p_header = dict(self.open_header, kid=self.payment_issuer[1])
        open_payment = self._present("payment", self._root(open_p, p_header, p_signer))

        closed_p = copy.deepcopy(self.closed_payment)
        if closed_p.get("transaction_id") is AUTO:
            closed_p["transaction_id"] = cjwt_hash
        if self.direct_payment:
            closed_payment = self._root(closed_p, self.open_header)
        else:
            closed_payment = self._kb(
                closed_p,
                open_payment,
                self.closed_payment_kb,
                self.closed_payment_signer or self.payment_agent or k.agent,
                self.binding["payment"],
            )

        def receipt(kind: str, claims: dict[str, Any], leaf: str, signer: Any) -> str:
            c = dict(claims)
            if c.get("reference") is AUTO:
                prose = self.reference_form[kind] == "prose"
                c["reference"] = hash_b64(leaf if prose else leaf.split("~", 1)[0], "sha-256")
            return sign_es256(self.receipt_header[kind], c, signer)

        checkout_receipt = receipt(
            "checkout",
            self.checkout_receipt,
            closed_checkout,
            self.checkout_receipt_signer or k.merchant,
        )
        payment_receipt = receipt(
            "payment",
            self.payment_receipt,
            closed_payment,
            self.payment_receipt_signer or k.processor,
        )
        bundle: dict[str, Any] = {
            "bundle_version": BUNDLE_VERSION,
            "checkout_mandate": _strip(open_checkout) + "~~" + closed_checkout,
            "payment_mandate": (
                closed_payment
                if self.direct_payment
                else _strip(open_payment) + "~~" + closed_payment
            ),
            "checkout_receipt": checkout_receipt,
            "payment_receipt": payment_receipt,
            "keys": {
                "mandate_issuer": [public_jwk(k.issuer, k.issuer_kid)]
                + (
                    [public_jwk(self.payment_issuer[0], self.payment_issuer[1])]
                    if self.payment_issuer is not None
                    else []
                ),
                "merchant": [public_jwk(k.merchant, k.merchant_kid)],
                "payment_processor": [public_jwk(k.processor, k.processor_kid)],
            },
            "expected": copy.deepcopy(self.expected),
            "note": self.note,
        }
        return DemoArtifacts(
            bundle=bundle,
            checkout_jwt=checkout_jwt,
            open_checkout=open_checkout,
            closed_checkout=closed_checkout,
            open_payment=open_payment,
            closed_payment=closed_payment,
            checkout_receipt=checkout_receipt,
            payment_receipt=payment_receipt,
            open_checkout_as_issued=open_checkout_issued,
        )


def _swap_merchant_disclosure(chain: str, rng: random.Random | None) -> str:
    """Replace the allowed-merchant disclosure of the open segment with another merchant."""
    from .jose import b64url_decode

    first, rest = chain.split("~~", 1)
    parts = first.split("~")
    for i, disc in enumerate(parts[1:], start=1):
        arr = json.loads(b64url_decode(disc))
        if len(arr) == 2 and isinstance(arr[1], dict) and arr[1].get("id") == MERCHANT["id"]:
            salt = b64url_encode(rng.randbytes(16) if rng is not None else secrets.token_bytes(16))
            other = {
                "id": "merchant_666",
                "name": "Other Merchant",
                "website": "https://other.example",
            }
            parts[i] = b64url_encode(json.dumps([salt, other]).encode("utf-8"))
            break
    return "~".join(parts) + "~~" + rest


def build_demo_bundle(
    tamper: str | None = None, *, seed: int | None = None, now: int | None = None
) -> dict[str, Any]:
    """Build a complete demo bundle, optionally with one dispute scenario applied.

    Args:
        tamper: ``None`` for a valid transaction, or one of :data:`TAMPER_MODES`.
        seed: Seed for disclosure salts (keys are always fresh).
        now: Unix time the transaction is placed around (default: current time).

    Returns:
        A bundle dict in the ``ap2-evidence/1`` format.

    Raises:
        ValueError: For an unknown ``tamper`` value.
    """
    if tamper is not None and tamper not in TAMPER_MODES:
        raise ValueError(f"unknown tamper mode {tamper!r}; choose from {', '.join(TAMPER_MODES)}")
    b = DemoBuilder(seed=seed, now=now)
    if tamper == "amount":
        b.closed_payment["payment_amount"] = {"amount": 25000, "currency": "USD"}
    elif tamper == "key":
        b.closed_payment_signer = _new_key()
    elif tamper == "receipt":
        other = DemoBuilder(keys=b.keys, seed=None if seed is None else seed + 1, now=b.now - 86400)
        other.closed_payment["payment_amount"] = {"amount": 4900, "currency": "USD"}
        leaf = other.build().closed_payment.split("~", 1)[0]
        b.payment_receipt["reference"] = hash_b64(leaf, "sha-256")
    bundle = b.build().bundle
    if tamper == "disclosure":
        bundle["checkout_mandate"] = _swap_merchant_disclosure(bundle["checkout_mandate"], b.rng)
    if tamper is not None:
        bundle["note"] = f"Demo bundle, scenario '{tamper}': {TAMPER_MODES[tamper]}"
    return bundle
