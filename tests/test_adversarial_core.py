"""Regression tests for the adversarial review of the verification core (findings K1-K5).

Threat model: all three roles are pinned with --trusted-keys unless a test says otherwise.
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence import constraints as C
from ap2_evidence import load_trusted_keys
from ap2_evidence.checks import reason_text
from ap2_evidence.demo import ITEM_ID, MERCHANT, DemoBuilder, SdElem
from ap2_evidence.jose import hash_b64
from helpers import builder, trusted_for, verify


def _run(b: DemoBuilder, **kw: Any) -> Any:
    return verify(
        b.build().bundle, trusted_keys=load_trusted_keys(json.dumps(trusted_for(b))), **kw
    )


def _line(i: int | str, sku: str, qty: int = 1) -> dict[str, Any]:
    return {"id": f"li_{i}", "item": {"id": sku, "title": "t", "price": 100}, "quantity": qty}


EVIL = _line("x", "expensive_tv")


# =========================================================================== K1 line items


def test_k1_forbidden_item_with_padding_still_fails() -> None:
    # The merchant pads the cart beyond the size limit: the forbidden item must still FAIL.
    for pad in (0, C.MAX_LINES):
        b = builder()
        lines = b.checkout_payload["line_items"]
        lines.append(EVIL)
        lines += [_line(i, ITEM_ID) for i in range(pad)]
        r = _run(b)
        cm35 = r.check("CM35")
        assert cm35.status == "FAIL" and cm35.reason == "item_not_acceptable", pad
        assert "expensive_tv" in cm35.detail
        assert r.verdict == "FAILED"


def test_k1_total_over_capacity_with_padding_fails() -> None:
    b = builder()  # one requirement of quantity 1
    b.checkout_payload["line_items"] += [_line(i, ITEM_ID) for i in range(C.MAX_LINES)]
    cm35 = _run(b).check("CM35")
    assert cm35.status == "FAIL" and cm35.reason == "quantity_exceeded"
    assert "1001 unit(s)" in cm35.detail and "at most 1" in cm35.detail


def test_k1_per_item_capacity_over_limit_fails() -> None:
    cons = {
        "items": [
            {"id": "a", "acceptable_items": [{"id": "A"}], "quantity": 1},
            {"id": "b", "acceptable_items": [{"id": "B"}], "quantity": 5000},
        ]
    }
    cart = [{"item": {"id": "B"}, "quantity": 1} for _ in range(C.MAX_LINES)]
    cart.append({"item": {"id": "A"}, "quantity": 2})
    out = C.eval_line_items(cons, cart)
    assert out.status == "FAIL" and out.reason == "quantity_exceeded"
    assert "2 unit(s) of A" in out.detail
    # the same with A within its capacity is beyond the limits: SKIP, never PASS
    cart[-1]["quantity"] = 1
    assert C.eval_line_items(cons, cart).reason == "too_large"


def test_k1_exhausted_work_budget_keeps_linear_fail() -> None:
    cons = {"items": [{"acceptable_items": [{"id": "s0"}, {"id": "s1"}], "quantity": 1}]}
    cart = [{"item": {"id": "s0"}, "quantity": 1}, {"item": {"id": "s1"}, "quantity": 1}]
    out = C.eval_line_items(cons, cart, C.WorkBudget(0))
    assert out.status == "FAIL" and out.reason == "quantity_exceeded"
    cons["items"][0]["quantity"] = 2
    assert C.eval_line_items(cons, cart, C.WorkBudget(0)).reason == "too_large"


def test_k1_fitting_large_cart_is_skip_not_pass() -> None:
    b = builder()
    b.open_checkout["constraints"][0]["items"][0]["quantity"] = 5000
    b.checkout_payload["line_items"] += [_line(i, ITEM_ID) for i in range(C.MAX_LINES)]
    r = _run(b)
    cm35 = r.check("CM35")
    assert cm35.status == "SKIP" and cm35.required and cm35.reason == "too_large"
    assert r.verdict == "INCOMPLETE"


def test_k1_line_items_not_a_list_fails() -> None:
    for value in ({"0": EVIL}, "expensive_tv", None, 3):
        b = builder()
        b.checkout_payload["line_items"] = value
        r = _run(b)
        cm35 = r.check("CM35")
        assert cm35.status == "FAIL" and cm35.reason == "malformed_checkout", value
        assert "not an array" in cm35.detail
        assert r.verdict == "FAILED"


def test_k1_line_items_absent_is_required_skip_that_says_not_checked() -> None:
    b = builder()
    del b.checkout_payload["line_items"]
    b.checkout_payload["items"] = [EVIL]
    r = _run(b)
    assert r.check("CM33").status == "WARN" and r.check("CM33").reason == "not_ucp"
    cm35 = r.check("CM35")
    assert cm35.status == "SKIP" and cm35.required and cm35.reason == "line_items_unreadable"
    assert "NOT checked" in cm35.detail and "not a pass" in cm35.detail
    assert r.verdict == "INCOMPLETE"


def test_k1_one_megabyte_adversarial_inputs_are_fast() -> None:
    # Over the limits: ~1 MB of lines that pass every linear test, under 32 constraints.
    # (The checkout JWT itself is capped at 1 MiB, which bounds the number of lines.)
    for forbidden in (False, True):
        b = builder()
        base = b.open_checkout["constraints"][0]
        cons = []
        for k in range(C.MAX_LINE_ITEM_CONSTRAINTS):
            c = copy.deepcopy(base)
            c["items"][0]["quantity"] = 10**9 + k
            cons.append(c)
        b.open_checkout["constraints"] = [*cons, b.open_checkout["constraints"][1]]
        b.checkout_payload["line_items"] += [_line(i, ITEM_ID) for i in range(5_500)]
        if forbidden:
            b.checkout_payload["line_items"].append(EVIL)
        bundle = b.build().bundle
        assert len(json.dumps(bundle)) > 1_000_000
        t0 = time.perf_counter()
        r = verify(bundle, trusted_keys=load_trusted_keys(json.dumps(trusted_for(b))))
        assert time.perf_counter() - t0 < 5
        want = "item_not_acceptable" if forbidden else "too_large"
        assert r.check("CM35").reason == want
    # ~1 MB of distinct acceptable items and lines, all matching: linear tests pass, SKIP
    n = 20_000
    acc = [{"id": f"s{i}"} for i in range(n)]
    cons = {"items": [{"id": "r", "acceptable_items": acc, "quantity": n}]}
    cart = [{"item": {"id": f"s{i}"}, "quantity": 1} for i in range(n)]
    t0 = time.perf_counter()
    out = C.eval_line_items(cons, cart)
    assert time.perf_counter() - t0 < 2
    assert out.reason == "too_large" and len(out.detail) < 2000


def test_k1_long_fail_text_is_bounded() -> None:
    cart = [{"item": {"id": f"bad{i}"}, "quantity": 1} for i in range(5000)]
    out = C.eval_line_items({"items": [{"acceptable_items": [{"id": "A"}], "quantity": 1}]}, cart)
    assert out.reason == "item_not_acceptable"
    assert "(+4950 more)" in out.detail and len(out.detail) < 2000


# =========================================================================== K2 PM31 / CM22


def _wrong_ref(b: DemoBuilder) -> None:
    for c in b.open_payment["constraints"]:
        if c["type"] == "payment.reference":
            c["conditional_transaction_id"] = hash_b64("some-other-open-checkout-token~")


def _narrowed(b: DemoBuilder) -> None:
    other = {"id": "merchant_2", "name": "Second", "website": "https://second.example"}
    b.open_checkout["constraints"][1]["allowed"] = [SdElem(dict(MERCHANT)), SdElem(other)]
    b.withhold["checkout"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("id") == "merchant_2"
    )


def _pm31_says_unverified(detail: str, n: int) -> None:
    assert "does NOT match the open checkout mandate as presented" in detail
    assert f"{n} undisclosed digest" in detail
    assert "or decoys" in detail
    assert "fewer disclosures than were issued" in detail
    assert "reference to a different checkout authorisation" in detail
    assert "not verified either way" in detail


def test_k2_narrowed_presentation_sentence_is_plain() -> None:
    for wrong in (False, True):
        b = builder()
        _narrowed(b)
        if wrong:
            _wrong_ref(b)
        r = _run(b)
        pm31 = r.check("PM31")
        assert pm31.status == "SKIP" and pm31.required
        assert pm31.reason == "reference_unverifiable_withheld"
        _pm31_says_unverified(pm31.detail, 1)
        assert r.verdict == "INCOMPLETE"
        cm22 = r.check("CM22")
        assert cm22.status == "PASS"
        assert "no constraint entry and no claim" in cm22.detail
        assert "1 other undisclosed digest" in cm22.detail and "or decoys" in cm22.detail


def test_k2_decoy_digest_is_not_called_withheld() -> None:
    b = builder()
    b.open_checkout["constraints"][1]["allowed"].append({"...": hash_b64("decoy")})
    _wrong_ref(b)
    r = _run(b)
    cm22, pm31 = r.check("CM22"), r.check("PM31")
    assert cm22.status == "PASS" and "1 other undisclosed digest" in cm22.detail
    assert "withheld" not in cm22.detail.split(";")[0]
    _pm31_says_unverified(pm31.detail, 1)
    assert "undisclosed entr" not in pm31.detail  # no "N undisclosed entries" (stated as fact)


def test_k2_nothing_undisclosed_stays_fail() -> None:
    b = builder()
    _wrong_ref(b)
    r = _run(b)
    assert r.check("PM31").status == "FAIL" and r.check("PM31").reason == "reference_mismatch"
    assert r.check("CM22").detail.startswith("no constraint entry and no claim")


# =========================================================================== K3 declined text


def test_k3_declined_sentence_does_not_assert_authenticity() -> None:
    for kind, prefix in (("payment", "PR"), ("checkout", "CR")):
        b = builder()
        getattr(b, f"{kind}_receipt").update(
            status="Error", error="card_declined", error_description="declined by issuer"
        )
        setattr(b, f"{kind}_receipt_signer", ec.generate_private_key(ec.SECP256R1()))
        r = _run(b)
        assert r.check(f"{prefix}02").status == "FAIL"
        c05 = r.check(f"{prefix}05")
        assert c05.status == "WARN" and c05.reason == "declined"
        assert c05.detail.startswith(f"the {kind} receipt reports an error: 'card_declined'")
        assert "not that it is genuine" in c05.detail
        for word in ("authentic", "is evidence", "documents"):
            assert word not in c05.detail and word not in (c05.hint or ""), word


# =========================================================================== K4 renamed merchant


def test_k4_renamed_checkout_merchant_under_allowed_id_warns() -> None:
    b = builder()
    b.checkout_payload["merchant"] = {
        "id": MERCHANT["id"],
        "name": "Evil Corp",
        "website": "https://evil.example",
    }
    r = _run(b)
    cm34 = r.check("CM34")
    assert cm34.status == "WARN" and cm34.reason == "merchant_details_differ"
    assert "Evil Corp" in cm34.actual and "Demo Merchant" in cm34.expected
    assert reason_text("CM34", "merchant_details_differ") is not None
    assert r.verdict == "VERIFIED"  # id matching is upstream semantics; the WARN is the signal


def test_k4_matching_merchant_still_passes() -> None:
    assert _run(builder()).check("CM34").status == "PASS"


# =========================================================================== K5 history currency


BUDGET = {"type": "payment.budget", "max": 1000.00, "currency": "USD"}


def test_k5_history_in_other_currency_is_required_skip() -> None:
    b = builder()
    b.open_payment["constraints"].append(dict(BUDGET))
    r = _run(b, history={"prior_total": {"amount": 0, "currency": "EUR"}})
    pm39 = r.check("PM39")
    assert pm39.status == "SKIP" and pm39.required
    assert pm39.reason == "history_currency_mismatch"
    assert "EUR" in pm39.detail and "USD" in pm39.detail and "not checked" in pm39.detail
    assert r.verdict == "INCOMPLETE"
    assert reason_text("PM39", "history_currency_mismatch") is not None


def test_k5_payment_in_other_currency_still_fails() -> None:
    usd = {"amount": 0, "currency": "USD"}
    out = C.eval_cumulative_budget(BUDGET, {"amount": 100, "currency": "EUR"}, usd)
    assert out.status == "FAIL" and out.reason == "currency_mismatch"
    # payment wrong and history wrong: the payment's violation wins
    eur = {"amount": 0, "currency": "EUR"}
    out = C.eval_cumulative_budget(BUDGET, {"amount": 100, "currency": "EUR"}, eur)
    assert out.status == "FAIL" and out.reason == "currency_mismatch"
