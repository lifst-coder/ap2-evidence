"""Regression tests for the technical audit of the verification core and the third-party
vector run (batch 2). Each test names the finding or the surviving mutant it pins.

Threat model: all three roles are pinned with --trusted-keys unless a test says otherwise.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import time
from collections import deque
from typing import Any

import pytest

from ap2_evidence import constraints as C
from ap2_evidence import load_trusted_keys
from ap2_evidence.bundle import InputError
from ap2_evidence.demo import ITEM_ID, MERCHANT, DemoBuilder, SdElem, build_demo_bundle
from ap2_evidence.jose import b64url_encode, hash_b64, public_jwk, sign_es256
from ap2_evidence.sdjwt import ResolvedList, SdJwtError, parse_segment, resolve
from ap2_evidence.strictjson import loads as strict_loads
from ap2_evidence.verify import _host
from helpers import KEYS, NOW, ROOT, builder, other_key_jwk, trusted_for, verify

T0 = NOW - 3600
FX = ROOT / "tests" / "fixtures" / "upstream-sdk"


def _pinned(b: DemoBuilder) -> Any:
    return load_trusted_keys(json.dumps(trusted_for(b)))


def _run(b: DemoBuilder, **kw: Any) -> Any:
    return verify(b.build().bundle, trusted_keys=_pinned(b), **kw)


def _open_points(r: Any) -> list[str]:
    return [
        c.id
        for c in r.checks
        if c.status in ("FAIL", "WARN") or (c.status == "SKIP" and c.required)
    ]


# =========================================================================== 1. line-items DoS


def _li_bundle(lines: int, reqs: int, n_cons: int = 1) -> dict[str, Any]:
    """The audit's r2/r3 shape: n distinct one-unit lines, wildcard requirements."""
    b = builder()
    b.checkout_payload["line_items"] = [
        {"id": f"li{i}", "item": {"id": f"sku{i}", "title": "t", "price": 1}, "quantity": 1}
        for i in range(lines)
    ]
    rq = [{"id": f"r{j}", "acceptable_items": [], "quantity": 1} for j in range(reqs)]
    b.open_checkout["constraints"] = [
        {"type": "checkout.line_items", "items": rq} for _ in range(n_cons)
    ] + [b.open_checkout["constraints"][1]]
    return b.build().bundle


def test_dos_audit_input_is_too_large_and_fast() -> None:
    # attacks/r3: 1000 x 1000, four constraints, no keys needed; took 113 s before the fix
    bundle = _li_bundle(1000, 1000, 4)
    bundle.pop("keys")
    t0 = time.perf_counter()
    r = verify(bundle)
    assert time.perf_counter() - t0 < 10
    cm35 = r.check("CM35")
    assert cm35.status == "SKIP" and cm35.required and cm35.reason == "too_large"
    assert r.verdict == "INCOMPLETE"


def test_dos_accepted_sizes_still_evaluated() -> None:
    r = verify(_li_bundle(400, 400))
    assert r.check("CM35").status == "PASS"


def test_dos_too_many_line_item_constraints() -> None:
    r = verify(_li_bundle(2, 2, C.MAX_LINE_ITEM_CONSTRAINTS + 1))
    cm35 = r.check("CM35")
    assert cm35.status == "SKIP" and cm35.required and cm35.reason == "too_large"
    assert verify(_li_bundle(2, 2, C.MAX_LINE_ITEM_CONSTRAINTS)).check("CM35").status == "PASS"


def _cart(n: int, qty: int = 1) -> list[dict[str, Any]]:
    return [{"item": {"id": f"s{i}"}, "quantity": qty} for i in range(n)]


def test_dos_limits_give_skip_never_pass() -> None:
    wild = {"items": [{"acceptable_items": [], "quantity": 1}] * (C.MAX_LINES + 1)}
    assert C.eval_line_items(wild, _cart(1)).reason == "too_large"
    roomy = {"items": [{"acceptable_items": [], "quantity": C.MAX_LINES + 1}]}
    assert C.eval_line_items(roomy, _cart(C.MAX_LINES + 1)).reason == "too_large"
    # a cart over the total capacity is a FAIL whatever its size (adversarial review K1)
    over = C.eval_line_items({"items": wild["items"][:1]}, _cart(C.MAX_LINES + 1))
    assert over.status == "FAIL" and over.reason == "quantity_exceeded"
    side = int(C.MAX_PAIRS**0.5) + 1
    pairs = {"items": [{"acceptable_items": [], "quantity": side}] * side}
    out = C.eval_line_items(pairs, _cart(side))
    assert out.status == "SKIP" and out.reason == "too_large"
    # an exhausted work budget also stops evaluation, with SKIP
    small = {"items": [{"acceptable_items": [{"id": "s0"}, {"id": "s1"}], "quantity": 2}]}
    assert C.eval_line_items(small, _cart(2), C.WorkBudget(3)).reason == "too_large"
    assert C.eval_line_items(small, _cart(2), C.WorkBudget()).status == "PASS"
    # reading many (identical) requirements is charged too, not only the merged flow graph
    acc = [{"id": f"s{i}"} for i in range(100)]
    many = {"items": [{"acceptable_items": acc, "quantity": 1}] * 50}
    assert C.eval_line_items(many, _cart(1), C.WorkBudget(1000)).reason == "too_large"
    assert C.eval_line_items(many, _cart(1), C.WorkBudget(10_000)).status == "WARN"


def test_dos_worst_case_accepted_input_is_bounded() -> None:
    # Triangular acceptable sets defeat greedy matching and need many Dinic phases; 32 such
    # constraints share one bundle budget. Must finish fast and never hang.
    n = 500
    tri = {
        "items": [
            {"acceptable_items": [{"id": f"s{i}"} for i in range(j + 1)], "quantity": 1}
            for j in range(n)
        ]
    }
    budget = C.WorkBudget()
    t0 = time.perf_counter()
    outs = [C.eval_line_items(tri, _cart(n), budget) for _ in range(C.MAX_LINE_ITEM_CONSTRAINTS)]
    assert time.perf_counter() - t0 < 10
    assert {o.status for o in outs} <= {"PASS", "SKIP"}
    assert all(o.reason == "too_large" for o in outs if o.status == "SKIP")


# -- randomized equivalence with the pre-audit algorithm (kept here only)


def _old_max_flow(cap: list[dict[int, int]], source: int, sink: int) -> int:
    flow = 0
    n = len(cap)
    while True:
        parent = [-1] * n
        parent[source] = source
        queue: deque[int] = deque([source])
        while queue and parent[sink] == -1:
            node = queue.popleft()
            for v, c in cap[node].items():
                if c > 0 and parent[v] == -1:
                    parent[v] = node
                    queue.append(v)
        if parent[sink] == -1:
            return flow
        push: int | None = None
        v = sink
        while v != source:
            w = parent[v]
            push = cap[w][v] if push is None else min(push, cap[w][v])
            v = w
        assert push is not None
        v = sink
        while v != source:
            w = parent[v]
            cap[w][v] -= push
            cap[v][w] = cap[v].get(w, 0) + push
            v = w
        flow += push


def _old_flow(cart: dict[str, int], req_sets: list[set[str] | None], qty: list[int]) -> int:
    skus = list(cart)
    n_nodes = 2 + len(skus) + len(req_sets)
    source, sink = 0, n_nodes - 1
    cap: list[dict[int, int]] = [{} for _ in range(n_nodes)]
    total = sum(cart.values())
    for i, sku in enumerate(skus):
        cap[source][1 + i] = cart[sku]
        for j, s in enumerate(req_sets):
            if s is None or sku in s:
                cap[1 + i][1 + len(skus) + j] = total
    for j, q in enumerate(qty):
        cap[1 + len(skus) + j][sink] = q
    return _old_max_flow(cap, source, sink)


def test_new_flow_equals_old_flow_randomized() -> None:
    rng = random.Random(20261125)
    for _ in range(3000):
        n_sku = rng.randint(1, 8)
        cart = {f"s{i}": rng.randint(1, 5) for i in range(n_sku)}
        req_sets: list[set[str] | None] = []
        for _ in range(rng.randint(1, 8)):
            if rng.random() < 0.15:
                req_sets.append(None)
            else:
                req_sets.append({f"s{i}" for i in range(n_sku + 2) if rng.random() < 0.4})
        qty = [rng.randint(1, 6) for _ in req_sets]
        new = C._assignable(cart, req_sets, qty, C.WorkBudget())
        assert new == _old_flow(cart, req_sets, qty), (cart, req_sets, qty)


def _rand_constraint(rng: random.Random) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    skus = [f"s{i}" for i in range(rng.randint(1, 6))]
    reqs = []
    for j in range(rng.randint(1, 5)):
        if rng.random() < 0.15:
            acc: list[Any] = []
        else:
            acc = ResolvedList({"id": s, "title": s} for s in skus if rng.random() < 0.5)
            acc.hidden = rng.choice([0, 0, 1])
        reqs.append({"id": f"r{j}", "acceptable_items": acc, "quantity": rng.randint(1, 4)})
    cart = [
        {"item": {"id": rng.choice(skus + ["x"])}, "quantity": rng.randint(1, 3)}
        for _ in range(rng.randint(1, 6))
    ]
    return {"type": "checkout.line_items", "items": reqs}, cart


def test_eval_line_items_outcomes_unchanged_randomized(monkeypatch: pytest.MonkeyPatch) -> None:
    rng = random.Random(7)
    cases = [_rand_constraint(rng) for _ in range(1500)]
    new = [C.eval_line_items(c, cart) for c, cart in cases]

    def old_assignable(cart: Any, req_sets: Any, qty: Any, budget: Any) -> int:
        return _old_flow(cart, req_sets, qty)

    monkeypatch.setattr(C, "_assignable", old_assignable)
    old = [C.eval_line_items(c, cart) for c, cart in cases]
    assert new == old
    assert {o.status for o in new} == {"PASS", "WARN", "FAIL"}


# =========================================================================== 3. payee details


def _evil_payee(b: DemoBuilder) -> None:
    b.closed_payment["payee"] = {
        "id": "merchant_1",
        "name": "Evil Corp",
        "website": "https://evil.example",
    }


def test_payee_renamed_under_merchant_id_warns() -> None:
    b = builder()
    _evil_payee(b)
    r = _run(b)
    xc02 = r.check("XC02")
    assert xc02.status == "WARN" and xc02.reason == "payee_details_differ"
    assert xc02.expected == "Demo Merchant (merchant_1, https://demo-merchant.example)"
    assert xc02.actual == "Evil Corp (merchant_1, https://evil.example)"
    pm33 = r.check("PM33")
    assert pm33.status == "WARN" and pm33.reason == "payee_details_differ"
    assert r.verdict == "VERIFIED"  # id matching is upstream semantics


def test_payee_matching_details_pass_with_both_descriptions() -> None:
    r = _run(builder())
    xc02 = r.check("XC02")
    assert xc02.status == "PASS" and xc02.expected == xc02.actual
    assert r.check("PM33").status == "PASS"


# =========================================================================== 4. success + error


@pytest.mark.parametrize("field", ["error", "error_description"])
def test_success_receipt_with_error_fails(field: str) -> None:
    b = builder()
    b.payment_receipt[field] = "card_declined"
    r = _run(b)
    pr05 = r.check("PR05")
    assert pr05.status == "FAIL" and pr05.reason == "success_with_error"
    assert r.verdict == "FAILED"


@pytest.mark.parametrize("value", [None, ""])
def test_success_receipt_with_empty_error_passes(value: Any) -> None:
    b = builder()
    b.payment_receipt["error"] = value
    b.payment_receipt["error_description"] = value
    assert _run(b).check("PR05").status == "PASS"


# =========================================================================== 5. checkout status


def test_canceled_checkout_fails() -> None:
    b = builder()
    b.checkout_payload["status"] = "canceled"
    r = _run(b)
    cm33 = r.check("CM33")
    assert cm33.status == "FAIL" and cm33.reason == "checkout_canceled"
    # the payload itself is fine, so the constraint checks still run
    assert r.check("CM34").status == "PASS" and r.check("CM35").status == "PASS"


@pytest.mark.parametrize("status", ["incomplete", "ready_for_complete", "completed"])
def test_signable_checkout_status_passes(status: str) -> None:
    b = builder()
    b.checkout_payload["status"] = status
    assert _run(b).check("CM33").status == "PASS"


def test_not_final_checkout_status_warns() -> None:
    b = builder()
    b.checkout_payload["status"] = "requires_escalation"
    cm33 = _run(b).check("CM33")
    assert cm33.status == "WARN" and cm33.reason == "checkout_not_final"


# =========================================================================== 6. PM31 narrowed


def _narrowed(b: DemoBuilder) -> None:
    other = {"id": "merchant_2", "name": "Second", "website": "https://second.example"}
    b.open_checkout["constraints"][1]["allowed"] = [SdElem(dict(MERCHANT)), SdElem(other)]
    b.withhold["checkout"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("id") == "merchant_2"
    )


def test_narrowed_presentation_reference_is_unverifiable_not_fail() -> None:
    b = builder()
    _narrowed(b)
    r = _run(b)
    pm31 = r.check("PM31")
    assert pm31.status == "SKIP" and pm31.required
    assert pm31.reason == "reference_unverifiable_withheld"
    assert "as issued" in pm31.detail
    assert r.verdict == "INCOMPLETE" and _open_points(r) == ["PM31"]


def test_reference_mismatch_with_nothing_withheld_stays_fail() -> None:
    b = builder()
    b.open_payment["constraints"][3]["conditional_transaction_id"] = "A" * 43
    pm31 = _run(b).check("PM31")
    assert pm31.status == "FAIL" and pm31.reason == "reference_mismatch"


def test_swapped_disclosure_still_fails_pm31() -> None:
    r = verify(build_demo_bundle("disclosure", seed=1))
    assert r.check("PM31").status == "FAIL"


def test_demo_reference_hashes_the_token_as_issued() -> None:
    b = builder()
    _narrowed(b)
    a = b.build()
    assert a.open_checkout != a.open_checkout_as_issued
    from helpers import segments

    res = resolve(parse_segment(segments(a.bundle["payment_mandate"])[0], 1))
    assert res.payload is not None
    cti = res.payload["delegate_payload"][0]["constraints"][3]["conditional_transaction_id"]
    assert cti == hash_b64(a.open_checkout_as_issued) != hash_b64(a.open_checkout)


def test_v_redact_upstream_fixture_still_fails() -> None:
    d = FX / "v_redact"
    r = verify(
        json.loads((d / "bundle.json").read_text(encoding="utf-8")),
        trusted_keys=load_trusted_keys((d / "trusted_keys.json").read_text(encoding="utf-8")),
    )
    assert r.verdict == "FAILED"
    assert {c.id for c in r.checks if c.status == "FAIL"} == {"CM34", "CM35"}
    assert r.check("PM31").reason == "reference_unverifiable_withheld"


# =========================================================================== 7. date profile


@pytest.mark.parametrize(
    ("text", "iso"),
    [
        ("2026-12-15", "2026-12-15T00:00:00+00:00"),
        ("2026-12-15T10:00:00Z", "2026-12-15T10:00:00+00:00"),
        ("2026-12-15t10:00:00z", "2026-12-15T10:00:00+00:00"),
        ("2026-12-15T10:00:00.5Z", "2026-12-15T10:00:00.500000+00:00"),
        ("2026-12-15T10:00:00.1234567Z", "2026-12-15T10:00:00.123456+00:00"),
        ("2026-12-15T19:00:00+09:00", "2026-12-15T10:00:00+00:00"),
        ("2026-12-15T05:30:00-04:30", "2026-12-15T10:00:00+00:00"),
    ],
)
def test_parse_when_accepts_rfc3339_profile(text: str, iso: str) -> None:
    when = C.parse_when(text)
    assert when is not None and when.isoformat() == iso


@pytest.mark.parametrize(
    "text",
    [
        "20261215",  # basic format: accepted by fromisoformat on 3.11+
        "2026-W50-2",  # ISO week date: accepted by fromisoformat on 3.11+
        "2026-12-15T10:00:00",  # no offset
        "2026-12-15T10:00Z",  # no seconds
        "2026-12-15 10:00:00Z",  # space separator
        " 2026-12-15",
        "2026-12-15T10:00:60Z",  # leap second
        "2026-13-01",
        "2026-02-30",
        "2026-12-15T10:00:00+24:00",
        "0000-01-01",
        "２０２６-12-15",  # non-ASCII digits
        "next tuesday",
    ],
)
def test_parse_when_rejects_everything_else(text: str) -> None:
    assert C.parse_when(text) is None


def test_execution_date_outside_profile_is_compared_as_string() -> None:
    c = {"not_before": "2026-01-01", "not_after": "2026-12-31"}
    out = C.eval_execution_date(c, "2026-W50-2")
    assert "plain strings" in out.detail


def test_parse_instant() -> None:
    assert C.parse_instant("1780000000") == 1_780_000_000
    assert C.parse_instant(" 2026-01-01T00:00:00Z ") == 1_767_225_600
    assert C.parse_instant("2026-01-01T00:00:00.9Z") == 1_767_225_600
    assert C.parse_instant("2026-01-01") == 1_767_225_600
    for bad in ("", "1.5", "-5", "2026-01-01T00:00:00", "tomorrow", "1234567890123"):
        assert C.parse_instant(bad) is None, bad


# =========================================================================== 8. require_pinned


def test_require_pinned_turns_bundle_keys_into_skip() -> None:
    bundle = builder().build().bundle
    assert verify(bundle).verdict == "VERIFIED"  # default unchanged
    r = verify(bundle, require_pinned=True)
    assert r.verdict == "INCOMPLETE"
    for cid in ("CM03", "PM03", "CM32", "CR02", "PR02"):
        c = r.check(cid)
        assert c.status == "SKIP" and c.required and c.reason == "key_not_pinned", cid
        assert c.key_provenance == "bundle"
    assert r.check("CM08").status == "PASS"  # agent key from cnf.jwk is not a bundle key


def test_require_pinned_with_pinned_keys_verifies() -> None:
    b = builder()
    assert _run(b, require_pinned=True).verdict == "VERIFIED"


# =========================================================================== 9. unsigned receipts


def test_unsigned_receipt_object_is_incomplete_not_tampering() -> None:
    def post(bundle: dict[str, Any]) -> None:
        bundle["payment_receipt"] = {"status": "Success", "payment_id": "p1"}

    b = builder()
    bundle = b.build().bundle
    post(bundle)
    r = verify(bundle, trusted_keys=_pinned(b))
    assert r.check("B01").status == "PASS"
    pr01 = r.check("PR01")
    assert pr01.status == "SKIP" and pr01.required and pr01.reason == "unsigned_receipt"
    assert "proves nothing" in pr01.detail
    assert r.verdict == "INCOMPLETE"
    bundle["payment_receipt"] = json.dumps({"status": "Success"})
    assert verify(bundle, trusted_keys=_pinned(b)).check("PR01").reason == "unsigned_receipt"


def test_other_receipt_types_stay_fail() -> None:
    bundle = builder().build().bundle
    bundle["checkout_receipt"] = 5
    r = verify(bundle)
    assert r.check("B01").status == "FAIL" and r.check("B01").reason == "bad_member_type"
    bundle["checkout_receipt"] = "[1, 2]"
    assert verify(bundle).check("CR01").reason == "not_jws"


# =========================================================================== 10. aud / nonce


@pytest.mark.parametrize("claim", ["aud", "nonce"])
def test_missing_kb_claim_fails_without_expected_value(claim: str) -> None:
    b = builder()
    b.expected = {}
    b.closed_checkout_kb[claim] = None  # the demo builder drops the claim
    r = _run(b)
    c = r.check("CM14" if claim == "aud" else "CM15")
    assert c.status == "FAIL" and c.reason == f"{claim}_missing"


def test_aud_array_containing_expected_value_passes() -> None:
    b = builder()
    b.closed_checkout_kb["aud"] = ["merchant", "other"]
    assert _run(b).check("CM14").status == "PASS"
    b.closed_checkout_kb["aud"] = ["someone-else"]
    assert _run(b).check("CM14").reason == "aud_mismatch"
    b.closed_checkout_kb["aud"] = [5]
    assert _run(b).check("CM14").reason == "aud_missing"


# =========================================================================== 11-17. low


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("https://demo-merchant.example:x@evil.example/", None),
        ("https://user@demo-merchant.example/", None),
        ("https://Demo-Merchant.example:8443/path", "demo-merchant.example"),
        ("pay.demo-processor.example", "pay.demo-processor.example"),
        ("https://[::1", None),
    ],
)
def test_host_parsing(value: str, host: str | None) -> None:
    assert _host(value) == host


def test_receipt_iss_with_userinfo_does_not_match() -> None:
    b = builder()
    b.checkout_receipt["iss"] = "https://demo-merchant.example:x@evil.example/"
    cr07 = _run(b).check("CR07")
    assert cr07.status == "WARN" and cr07.reason == "issuer_mismatch"


def test_negative_payment_amount_is_rejected() -> None:
    b = builder()
    del b.checkout_payload["totals"]
    b.open_payment["constraints"][0].pop("min")
    b.closed_payment["payment_amount"] = {"amount": -19900, "currency": "USD"}
    r = _run(b)
    assert r.check("PM13").status == "FAIL" and "negative" in r.check("PM13").detail


def test_preset_equality_is_type_strict() -> None:
    b = builder()
    b.open_payment["risk_data"] = {"device_trusted": True, "score": 1}
    b.closed_payment["risk_data"] = {"device_trusted": 1, "score": 1.0}
    pm18 = _run(b).check("PM18")
    assert pm18.status == "FAIL" and pm18.reason == "preset_claim_changed"
    b.closed_payment["risk_data"] = {"score": 1, "device_trusted": True}
    assert _run(b).check("PM18").status == "PASS"


def test_hidden_allowed_on_non_allow_list_constraint_is_not_narrowing() -> None:
    # attacks/a1 case 1d: an 'allowed' member on payment.amount_range means nothing
    b = builder()
    b.open_payment["constraints"][0]["allowed"] = [SdElem({"note": "decoy"})]
    b.withhold["payment"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("note") == "decoy"
    )
    pm22 = _run(b).check("PM22")
    assert pm22.status == "SKIP" and pm22.reason == "withheld_claim"


def test_hidden_nested_allowed_inside_entry_is_not_narrowing() -> None:
    # attacks/a1 case 1c: an array named 'allowed' inside an allowed entry
    b = builder()
    b.open_checkout["constraints"][1]["allowed"] = [SdElem(dict(MERCHANT, allowed=[SdElem("x")]))]
    b.withhold["checkout"] = lambda d: len(d) == 2 and d[1] == "x"
    cm22 = _run(b).check("CM22")
    assert cm22.status == "SKIP" and cm22.reason == "withheld_claim"


def test_hidden_acceptable_item_is_narrowing() -> None:
    b = builder()
    b.open_checkout["constraints"][0]["items"][0]["acceptable_items"].append(
        SdElem({"id": "other_item", "title": "Other"})
    )
    b.withhold["checkout"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("id") == "other_item"
    )
    cm22 = _run(b).check("CM22")
    assert cm22.status == "PASS" and "only narrow" in cm22.detail


def test_pm10_text_for_top_level_mandate() -> None:
    from ap2_evidence.demo import SdProp, _SdIssuer
    from helpers import segments

    b = builder()
    a = b.build()
    open_seg = segments(a.bundle["payment_mandate"])[0]
    mand = dict(b.closed_payment, transaction_id=hash_b64(a.checkout_jwt))
    iss = _SdIssuer(None)
    enc = iss.encode({"delegate_payload": SdProp([mand]), **mand})
    enc.update({"_sd_alg": "sha-256", **b.closed_payment_kb, "sd_hash": hash_b64(open_seg)})
    jwt = sign_es256({"alg": "ES256", "typ": "kb+sd-jwt"}, enc, KEYS.agent)
    bundle = dict(a.bundle, payment_mandate=open_seg[:-1] + "~~" + jwt + "~")
    r = verify(bundle, trusted_keys=_pinned(b))
    pm10 = r.check("PM10")
    assert pm10.status == "PASS"
    assert "delegate_payload resolves to exactly one" not in pm10.detail
    assert "top level" in pm10.detail
    assert r.check("PM22").status == "SKIP"


def test_cm33_warning_lists_only_present_members() -> None:
    b = builder()
    del b.checkout_payload["totals"]
    del b.checkout_payload["links"]
    cm33 = _run(b).check("CM33")
    assert cm33.reason == "not_ucp"
    assert "(merchant, line_items, currency)" in cm33.detail
    assert "totals) are still used" not in cm33.detail


def test_bom_is_still_stripped() -> None:
    assert strict_loads("﻿{}") == {}
    assert strict_loads(b"\xef\xbb\xbf[1]") == [1]


# =========================================================================== surviving mutants


def test_mutant_v06_xc01_compares_currency() -> None:
    b = builder()
    b.open_payment["constraints"] = [
        c for c in b.open_payment["constraints"] if c.get("type") != "payment.amount_range"
    ]
    b.closed_payment["payment_amount"] = {"amount": 19900, "currency": "EUR"}
    xc01 = _run(b).check("XC01")
    assert xc01.status == "FAIL" and xc01.reason == "currency_mismatch"


def test_mutant_v10_withheld_digest_outside_mandate_object() -> None:
    b = builder()
    b.closed_payment_kb["_sd"] = ["A" * 43]
    r = _run(b)
    pm22 = r.check("PM22")
    assert pm22.status == "SKIP" and pm22.required and pm22.reason == "withheld_claim"
    assert "outside the mandate object" in pm22.detail
    assert r.verdict == "INCOMPLETE"


@pytest.mark.parametrize(("delta", "status"), [(0, "PASS"), (1, "FAIL")])
def test_mutant_v12_receipt_before_mandate_skew_boundary(delta: int, status: str) -> None:
    b = builder()
    b.payment_receipt["iat"] = (T0 + 13) - 300 - delta  # closed payment KB iat is T0 + 13
    pr06 = _run(b).check("PR06")
    assert pr06.status == status
    if status == "FAIL":
        assert pr06.reason == "receipt_before_mandate"


def test_mutant_v13_preset_payee_is_compared() -> None:
    b = builder()
    b.open_payment["payee"] = dict(MERCHANT)
    b.closed_payment["payee"] = dict(MERCHANT, website="https://demo-merchant.example/other")
    pm18 = _run(b).check("PM18")
    assert pm18.status == "FAIL" and pm18.reason == "preset_claim_changed"


def test_mutant_v14_pm30_needs_checkout_hash_to_match_the_jwt() -> None:
    b = builder()
    b.closed_checkout["checkout_hash"] = "B" * 43
    b.closed_payment["transaction_id"] = "B" * 43
    r = _run(b)
    assert r.check("CM31").reason == "hash_mismatch"
    pm30 = r.check("PM30")
    assert pm30.status == "FAIL" and pm30.reason == "checkout_hash_mismatch"


@pytest.mark.parametrize(("delta", "status"), [(0, "PASS"), (1, "FAIL")])
def test_mutant_v16_at_expiry_skew_boundary(delta: int, status: str) -> None:
    b = builder()
    at = (T0 + 3600) + 300 + delta  # both open mandates expire at T0 + 3600
    pm19 = _run(b, at=at).check("PM19")
    assert pm19.status == status
    if status == "FAIL":
        assert pm19.reason == "not_valid_at"


def _fixed_checkout_jwt(b: DemoBuilder) -> str:
    return sign_es256(b.checkout_header, b.checkout_payload, KEYS.merchant)


def test_mutant_v17_sha384_checkout_hash_needs_sd_alg_sha384() -> None:
    from ap2_evidence.demo import SdProp

    b = builder()
    cj = _fixed_checkout_jwt(b)
    b.closed_checkout["checkout_jwt"] = SdProp(cj)
    b.closed_checkout["checkout_hash"] = hash_b64(cj, "sha-384")
    b.closed_payment["transaction_id"] = hash_b64(cj, "sha-384")
    cm31 = _run(b).check("CM31")
    assert cm31.status == "FAIL" and cm31.reason == "hash_mismatch"


def test_mutant_v21_prose_error_receipt_is_declined() -> None:
    b = builder()
    b.payment_receipt.pop("status")
    b.payment_receipt.update(result="error", error="card_declined")
    pr05 = _run(b).check("PR05")
    assert pr05.status == "WARN" and pr05.reason == "declined"


def _disc(arr: list[Any]) -> str:
    return b64url_encode(json.dumps(arr).encode("utf-8"))


def _segment(payload: dict[str, Any], discs: list[str]) -> Any:
    jwt = sign_es256({"alg": "ES256"}, payload, KEYS.issuer)
    return parse_segment(jwt + "~" + "".join(d + "~" for d in discs), 1)


def test_mutant_s01_digest_referenced_twice() -> None:
    d = _disc(["salt", "a", 1])
    res = resolve(_segment({"_sd": [hash_b64(d), hash_b64(d)]}, [d]))
    assert "digest_reused" in res.codes


def test_mutant_s03_disclosed_claim_cannot_override_plain_claim() -> None:
    d = _disc(["salt", "a", 2])
    res = resolve(_segment({"_sd": [hash_b64(d)], "a": 1}, [d]))
    assert "claim_collision" in res.codes


@pytest.mark.parametrize("name", ["_sd", "..."])
def test_mutant_s04_reserved_claim_names(name: str) -> None:
    d = _disc(["salt", name, 1])
    res = resolve(_segment({"_sd": [hash_b64(d)]}, [d]))
    assert "reserved_claim_name" in res.codes


def test_mutant_s05_disclosure_cap() -> None:
    discs = [_disc([f"s{i}", i]) for i in range(513)]
    payload = {"list": [{"...": hash_b64(d)} for d in discs]}
    with pytest.raises(SdJwtError, match="more than 512 disclosures"):
        _segment(payload, discs)
    seg = _segment({"list": [{"...": hash_b64(d)} for d in discs[:512]]}, discs[:512])
    assert not resolve(seg).errors


def test_mutant_s07_placeholder_with_extra_members() -> None:
    d = _disc(["salt", 1])
    res = resolve(_segment({"list": [{"...": hash_b64(d), "x": 1}]}, [d]))
    assert "bad_placeholder" in res.codes


def test_mutant_j05_non_ascii_checkout_jwt_is_not_hashed() -> None:
    from ap2_evidence.demo import SdProp

    b = builder()
    text = "é.é.é"
    utf8 = b64url_encode(hashlib.sha256(text.encode("utf-8")).digest())
    b.closed_checkout["checkout_jwt"] = SdProp(text)
    b.closed_checkout["checkout_hash"] = utf8
    b.closed_payment["transaction_id"] = utf8
    r = _run(b)
    cm31 = r.check("CM31")
    assert cm31.status == "FAIL" and cm31.reason == "not_ascii"


@pytest.mark.parametrize(
    ("amount", "status"),
    [(20000, "PASS"), (20001, "FAIL"), (100, "PASS"), (99, "FAIL")],
)
def test_mutant_c03_amount_range_boundaries(amount: int, status: str) -> None:
    c = {"type": "payment.amount_range", "currency": "USD", "max": 20000, "min": 100}
    out = C.eval_amount_range(c, {"amount": amount, "currency": "USD"})
    assert out.status == status
    if status == "FAIL":
        assert out.reason == ("amount_above_max" if amount > 20000 else "amount_below_min")


def test_mutant_c13_empty_target_id_uses_name_and_website() -> None:
    cand = {"id": "m1", "name": "A", "website": "https://a"}
    assert C.merchant_matches(cand, {"id": "", "name": "A", "website": "https://a"})
    assert not C.merchant_matches(cand, {"id": "", "name": "B", "website": "https://a"})


# =========================================================================== batch 2


def test_a_direct_closed_mandate_may_carry_cnf() -> None:
    b = builder()
    b.direct_payment = True
    b.closed_payment["cnf"] = {"jwk": public_jwk(KEYS.agent)}
    pm12 = _run(b).check("PM12")
    assert pm12.status == "PASS" and "carries cnf" in pm12.detail
    b2 = builder()
    b2.closed_payment["cnf"] = {"jwk": public_jwk(KEYS.agent)}
    assert _run(b2).check("PM12").reason == "cnf_in_closed"


def test_b_empty_checkout_fails_line_items() -> None:
    b = builder()
    b.checkout_payload["line_items"] = []
    cm35 = _run(b).check("CM35")
    assert cm35.status == "FAIL" and cm35.reason == "empty_checkout"
    assert "satisfies the upstream SDK" not in cm35.detail


def test_c_declined_receipt_is_intact_evidence() -> None:
    b = builder()
    b.payment_receipt.update(status="Error", error="card_declined", error_description="no")
    b.payment_receipt.pop("psp_confirmation_id")
    b.payment_receipt.pop("network_confirmation_id")
    r = _run(b)
    pr05 = r.check("PR05")
    assert pr05.status == "WARN" and pr05.reason == "declined" and pr05.actual == "declined"
    assert r.check("CR05").actual == "success"
    assert r.verdict == "VERIFIED"
    b.payment_receipt_signer = KEYS.agent  # integrity problems stay FAIL
    assert _run(b).verdict == "FAILED"


def test_d_at_before_closed_hop_iat_fails() -> None:
    b = builder()
    at = (T0 + 13) - 300 - 1  # the closed payment hop's own iat is T0 + 13
    pm19 = _run(b, at=at).check("PM19")
    assert pm19.status == "FAIL" and "segment 2 JWT was issued later" in pm19.detail
    assert _run(b, at=at + 1).check("PM19").status == "PASS"


def test_e_product_shaped_line_items_warn_not_fail() -> None:
    b = builder()
    b.checkout_payload["line_items"] = [{"product": {"sku": ITEM_ID}, "quantity": 1}]
    b.open_checkout["constraints"] = b.open_checkout["constraints"][1:]  # no line_items
    r = _run(b)
    assert r.check("CM33").status == "WARN" and r.check("CM33").reason == "not_ucp"
    assert r.check("CM34").status == "PASS"
    b2 = builder()
    b2.checkout_payload["line_items"] = [{"product": {"sku": ITEM_ID}, "quantity": 1}]
    cm35 = _run(b2).check("CM35")
    assert cm35.status == "FAIL" and cm35.reason == "malformed_checkout"


BUDGET = {"type": "payment.budget", "max": 1000.00, "currency": "USD"}
RECUR = {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 3}


def _cumulative(b: DemoBuilder) -> None:
    b.open_payment["constraints"] += [dict(BUDGET), dict(RECUR)]


@pytest.mark.parametrize(
    ("history", "status", "reason"),
    [
        (None, "SKIP", "history_needed"),
        ({"prior_uses": 0}, "SKIP", "history_needed"),
        ({"prior_total": {"amount": 0, "currency": "USD"}, "prior_uses": 2}, "PASS", None),
        (
            {"prior_total": {"amount": 80101, "currency": "USD"}, "prior_uses": 0},
            "FAIL",
            "budget_exceeded",
        ),
        (
            {"prior_total": {"amount": 0, "currency": "USD"}, "prior_uses": 3},
            "FAIL",
            "occurrences_exceeded",
        ),
        (  # the operator's figure is in another currency: unverified, not failed (review K5)
            {"prior_total": {"amount": 0, "currency": "EUR"}, "prior_uses": 0},
            "SKIP",
            "history_currency_mismatch",
        ),
    ],
)
def test_f_cumulative_limits_need_history(history: Any, status: str, reason: str | None) -> None:
    b = builder()
    _cumulative(b)
    r = _run(b, history=history)
    pm39 = r.check("PM39")
    assert pm39.status == status and pm39.reason == reason
    if status == "SKIP":
        assert pm39.required and r.verdict == "INCOMPLETE"
    if status == "PASS":
        assert "supplied by whoever ran the verifier" in pm39.detail
        assert r.verdict == "VERIFIED"


@pytest.mark.parametrize(
    "history",
    [
        [],
        {"prior_total": 5},
        {"prior_total": {"amount": -1, "currency": "USD"}},
        {"prior_total": {"amount": 1, "currency": "usd"}},
        {"prior_uses": -1},
        {"prior_uses": True},
        {"spent": 1},
    ],
)
def test_f_invalid_history_is_rejected(history: Any) -> None:
    with pytest.raises(InputError):
        verify(builder().build().bundle, history=history)


@pytest.mark.parametrize("case", ["v_extras_usd", "v_extras_jpy", "v_extras_kwd"])
def test_f_upstream_extras_verify_with_zero_history(case: str) -> None:
    d = FX / case
    bundle = json.loads((d / "bundle.json").read_text(encoding="utf-8"))
    keys = load_trusted_keys((d / "trusted_keys.json").read_text(encoding="utf-8"))
    assert verify(bundle, trusted_keys=keys).verdict == "INCOMPLETE"
    cur = case[-3:].upper()
    hist = {"prior_total": {"amount": 0, "currency": cur}, "prior_uses": 0}
    assert verify(bundle, trusted_keys=keys, history=hist).verdict == "VERIFIED"


def test_g_expectations_given_but_artifact_missing_is_required_skip() -> None:
    bundle = builder().build().bundle
    del bundle["checkout_mandate"]
    exp = {
        "checkout_id": "demo-checkout-0001",
        "require_constraints": ["checkout.line_items"],
    }
    r = verify(bundle, expected=exp)
    for cid in ("EX02", "EX05"):
        c = r.check(cid)
        assert c.status == "SKIP" and c.required and c.blocked_by == "B02", cid


def test_g_expected_agent_key_and_aud_together() -> None:
    b = builder()
    exp = {"agent_key": public_jwk(KEYS.agent), "payment": {"aud": "credential-provider"}}
    r = _run(b, expected=exp)
    assert r.check("EX01").status == "PASS" and r.check("PM14").status == "PASS"
    r = _run(b, expected={"agent_key": other_key_jwk("x")})
    assert r.check("EX01").reason == "agent_key_mismatch" and r.verdict == "FAILED"


@pytest.mark.parametrize(
    "exp",
    [
        {"agent_key": {"kty": "EC"}},
        {"checkout_id": 5},
        {"total": {"amount": "1", "currency": "USD"}},
        {"require_constraints": ["payment.nope"]},
        {"surprise": 1},
    ],
)
def test_g_invalid_expectations_are_rejected(exp: dict[str, Any]) -> None:
    with pytest.raises(InputError):
        verify(builder().build().bundle, expected=exp)


def test_h_cm33_names_the_missing_artifact() -> None:
    bundle = builder().build().bundle
    del bundle["checkout_mandate"]
    r = verify(bundle)
    assert r.check("CM33").blocked_by == "B02" == r.check("CM32").blocked_by


def test_registry_has_86_checks() -> None:
    from ap2_evidence.checks import REGISTRY

    assert len(REGISTRY) == 86
    assert [c for c in REGISTRY if c.startswith("EX")] == [f"EX0{i}" for i in range(1, 6)]


def test_report_is_deep_copy_safe() -> None:
    # verify_bundle must not mutate the caller's bundle (used by the vector runner)
    bundle = builder().build().bundle
    before = copy.deepcopy(bundle)
    verify(bundle, history={"prior_uses": 0})
    assert bundle == before
