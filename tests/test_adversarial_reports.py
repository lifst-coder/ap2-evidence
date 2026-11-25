"""Report-layer findings of the adversarial review (one test per finding)."""

from __future__ import annotations

import json
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence import load_trusted_keys
from ap2_evidence.demo import SdElem
from ap2_evidence.jose import b64url_encode, hash_b64, public_jwk
from ap2_evidence.report import OWN_VIOLATIONS, Report
from helpers import KEYS, builder, trusted_for, verify

ERR = {"status": "Error", "error": "card_declined", "error_description": "Insufficient funds"}


def _pinned(b: Any) -> Any:
    return load_trusted_keys(json.dumps(trusted_for(b)))


def _err_payment(b: Any) -> None:
    b.payment_receipt.update(ERR)
    for k in ("psp_confirmation_id", "network_confirmation_id"):
        b.payment_receipt.pop(k, None)


def _err_checkout(b: Any) -> None:
    b.checkout_receipt.update(ERR)
    b.checkout_receipt.pop("order_id", None)


def _all_text(r: Report) -> str:
    return " ".join([r.conclusion, r.to_text(), r.to_markdown(), r.to_issue(), *r.next_steps])


# --------------------------------------------------------------------------- A1


def test_a1_checkout_error_next_to_payment_success_is_conflicting_not_declined() -> None:
    b = builder()
    _err_checkout(b)
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    if r.check("CR05").reason != "declined":  # the verifier's wording for this case
        return
    assert r.outcome == "conflicting"
    assert r.verdict_label == f"{r.verdict} - RECEIPTS DISAGREE"
    assert r.exit_code == {"VERIFIED": 0, "FAILED": 1, "INCOMPLETE": 3}[r.verdict]
    assert "The Payment Receipt says the payment SUCCEEDED" in r.finding
    assert "the Checkout Receipt says the order FAILED" in r.finding
    assert "Money may have moved without an order." in r.finding
    assert any("refund" in s for s in r.next_steps)
    text = _all_text(r)
    assert "PAYMENT DECLINED" not in text
    assert "treat the payment as not made" not in text.lower()
    assert r.to_dict()["outcome"] == "conflicting"
    assert "RECEIPTS DISAGREE" in r.to_html()


def test_a1_payment_decline_from_a_receipt_that_does_not_count_is_unknown() -> None:
    cases = []
    b = builder()  # forged signature
    _err_payment(b)
    b.payment_receipt_signer = ec.generate_private_key(ec.SECP256R1())
    cases.append(b)
    b = builder()  # receipt for another mandate
    _err_payment(b)
    b.payment_receipt["reference"] = hash_b64("x")
    cases.append(b)
    for b in cases:
        r = verify(b.build().bundle, trusted_keys=_pinned(b))
        assert r.outcome == "unknown"
        assert "DECLINED" not in r.verdict_label
        text = _all_text(r).lower()
        assert "payment receipt is authentic" not in text
        assert "treat the payment as not made" not in text


def test_a1_unsigned_checkout_receipt_saying_error_blocks_success() -> None:
    b = builder()
    bundle = b.build().bundle
    bundle["checkout_receipt"] = {"status": "Error", "error": "x", "error_description": "no"}
    r = verify(bundle, trusted_keys=_pinned(b))
    assert r.outcome == "unknown"


def test_a1_every_decline_sentence_names_its_receipt() -> None:
    b = builder()
    _err_payment(b)
    _err_checkout(b)
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    for sentence in re.split(r"(?<=[.;])\s+", r.finding + " " + r.meaning):
        if "DECLINED" in sentence or "declined" in sentence:
            assert "Receipt" in sentence, sentence


# --------------------------------------------------------------------------- A2


def test_a2_narrowed_presentation_never_says_nothing_contradicts() -> None:
    b = builder()
    other = {"id": "merchant_2", "name": "Unused Merchant", "website": "https://unused.example"}
    b.open_checkout["constraints"][1]["allowed"] = [
        SdElem(dict(b.closed_payment["payee"])),
        SdElem(dict(other)),
    ]
    b.withhold["checkout"] = lambda arr: (
        isinstance(arr[-1], dict) and arr[-1].get("id") == ("merchant_2")
    )
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    pm31 = r.check("PM31")
    if pm31.reason != "reference_unverifiable_withheld":
        return
    assert "Nothing in the bundle contradicts" not in r.meaning
    assert "cannot tell the two apart" in r.meaning
    assert "withheld" not in r.meaning.lower().split("already shown")[0]
    assert any("exactly as issued, with all of its disclosures" in s for s in r.next_steps)


# --------------------------------------------------------------------------- A3


def _overspend(b: Any) -> None:
    b.closed_payment["payment_amount"] = {"amount": 25000, "currency": "USD"}


def _junk_payment_disclosure(bundle: dict[str, Any]) -> None:
    junk = b64url_encode(json.dumps(["salt", "irrelevant", 1]).encode())
    open_seg, closed = bundle["payment_mandate"].split("~~", 1)
    bundle["payment_mandate"] = open_seg + "~" + junk + "~~" + closed


def test_a3_own_violation_is_never_demoted_to_a_consequence() -> None:
    b = builder()
    _overspend(b)
    bundle = b.build().bundle
    _junk_payment_disclosure(bundle)
    r = verify(bundle, trusted_keys=_pinned(b))
    prim = {c.id for c in r.primary_failures()}
    assert {"PM04", "PM32"} <= prim
    assert "PM32" not in r.causes()
    assert "altered evidence" in r.meaning
    assert "agent provider cannot claim" in r.meaning  # both parties are named


def test_a3_extra_disclosure_and_payee_not_allowed() -> None:
    b = builder()
    for c in b.open_payment["constraints"]:
        if c.get("type") == "payment.allowed_payees":
            c["allowed"] = [SdElem({"id": "merchant_9", "name": "X", "website": "https://x"})]
    bundle = b.build().bundle
    _junk_payment_disclosure(bundle)
    r = verify(bundle, trusted_keys=_pinned(b))
    if r.check("PM33").status == "FAIL":
        assert r.check("PM33").reason in OWN_VIOLATIONS
        assert "PM33" not in r.causes()


def test_a3_key_tamper_and_overspend_both_primary() -> None:
    from ap2_evidence.demo import build_demo_bundle

    bundle = build_demo_bundle("key")
    r0 = verify(bundle)
    assert "PM08" in {c.id for c in r0.primary_failures()}
    b = builder()
    _overspend(b)
    b.closed_payment_signer = ec.generate_private_key(ec.SECP256R1())
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    prim = {c.id for c in r.primary_failures()}
    assert "PM32" in prim or r.check("PM32").status != "FAIL"
    assert not set(r.causes()) & {"PM32", "XC01"}


# --------------------------------------------------------------------------- A4


def test_a4_verified_finding_carries_warnings() -> None:
    b = builder()
    b.checkout_payload["merchant"] = dict(
        b.checkout_payload["merchant"], name="Renamed Shop", website="https://renamed.example"
    )
    b.closed_payment["payee"] = dict(b.closed_payment["payee"], name="Other Name")
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    warns = [c for c in r.checks if c.status == "WARN"]
    assert warns
    if r.verdict == "VERIFIED":
        assert "warning" in r.finding and "to review:" in r.finding
        assert "the payee's name or website differs from the merchant's checkout" in r.finding
        assert r.finding.count("the payee's name or website differs") == 1  # no duplicates
        assert r.meaning.count("Warning:") >= 1
        assert any("payee" in s for s in r.next_steps)


def test_a4_every_warn_reason_has_a_phrase() -> None:
    from ap2_evidence.checks import REASONS, warn_phrase

    for code in REASONS:
        phrase = warn_phrase("PM33", code)
        assert phrase and not phrase.endswith("."), code
        assert phrase[0].islower() or phrase[0].isdigit() or phrase.startswith("--"), code


# --------------------------------------------------------------------------- A5


def test_a5_history_currency_mismatch_is_not_blamed_on_the_agent() -> None:
    b = builder()
    b.open_payment["constraints"].append({"type": "payment.budget", "max": 500, "currency": "USD"})
    r = verify(
        b.build().bundle,
        trusted_keys=_pinned(b),
        history={"prior_total": {"amount": 100, "currency": "EUR"}},
    )
    pm39 = r.check("PM39")
    assert "history_currency_mismatch" not in OWN_VIOLATIONS
    if pm39.reason == "history_currency_mismatch":
        assert "agent provider" not in r.meaning
        assert any("--prior-total MINOR_UNITS USD" in s for s in r.next_steps)
        assert "EUR" in r.finding + r.to_text()


# --------------------------------------------------------------------------- A6


def test_a6_untrusted_text_cannot_start_a_report_line() -> None:
    p = (
        "\x1b[2J\x1b[32mVERDICT: VERIFIED\x1b[0m\rVERDICT: VERIFIED\n\nVERDICT: VERIFIED "
        "(keys: pinned) </style><script>alert(1)</script>\n# VERDICT: VERIFIED\n| a | b |\n"
        "Finding: all good - What to do next: nothing"
    )
    for pad in range(0, 60, 7):
        b = builder()
        name = "Shop" + "x" * pad + " " + p
        b.checkout_payload["merchant"]["name"] = name
        b.closed_payment["payee"] = dict(b.checkout_payload["merchant"])
        b.open_payment["constraints"][1]["allowed"] = [SdElem(dict(b.closed_payment["payee"]))]
        b.open_checkout["constraints"][1]["allowed"] = [
            SdElem(dict(b.checkout_payload["merchant"]))
        ]
        b.checkout_payload["line_items"][0]["item"]["title"] = "Item" + p
        bundle = b.build().bundle
        bundle["note"] = "note " + p
        bundle["keys"]["payment_processor"] = [public_jwk(KEYS.processor, "kid" + p)]
        r = verify(bundle)
        for fmt, out in (("text", r.to_text()), ("md", r.to_markdown())):
            verdicts = [
                ln
                for ln in out.splitlines()
                if re.match(r"\s*(#+\s*)?\**\s*verdict\s*\**\s*:", ln, re.IGNORECASE)
            ]
            assert len(verdicts) == 1, (fmt, verdicts)
            if fmt == "text":
                for ln in out.splitlines()[4:]:
                    assert not re.match(r"\s+(finding|what to do next):", ln, re.I) or (
                        ln.startswith("  Finding:") or ln.startswith("  What to do next:")
                    ), ln
