"""Every check in the registry has a passing case and a forged case, with a stable reason.

CASES is the parametrized table of (check id, expected status, expected reason
code, bundle factory, verify kwargs). ``test_registry_fully_covered`` fails when
a registry ID lacks a PASS case (unless it can never pass) or a case producing
its worst status (FAIL for normal checks, WARN for advisory ones, SKIP for the
chain-shape check). Every non-PASS case also asserts the machine-readable
``reason`` so a test cannot pass because the check failed for another reason.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from functools import cache
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence.checks import REGISTRY
from ap2_evidence.demo import MERCHANT, PISP, SdElem, SdProp, build_demo_bundle
from ap2_evidence.jose import hash_b64
from helpers import (
    NOW,
    add_disclosure,
    build,
    disclosure,
    other_key_jwk,
    segments,
    two_object_closed_payment,
    verify,
)

Factory = Callable[[], dict[str, Any]]
Case = tuple[str, str, "str | None", Factory, dict[str, Any]]
OTHER_MERCHANT = {"id": "merchant_2", "name": "Other Shop", "website": "https://other.example"}
T0 = NOW - 3600
_DEL = object()


def _k() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def f_default() -> dict[str, Any]:
    return build()


def _set(path: str, value: Any) -> Callable[[Any], None]:
    """mutate(b): set an attribute path like 'open_checkout.constraints.0.items'."""

    def m(b: Any) -> None:
        first, *rest = path.split(".")
        obj = getattr(b, first)
        for k in rest[:-1]:
            obj = obj[int(k)] if isinstance(obj, list) else obj[k]
        last = rest[-1]
        if value is _DEL:
            if isinstance(obj, list):
                del obj[int(last)]
            else:
                del obj[last]
        elif isinstance(obj, list):
            obj[int(last)] = value
        else:
            obj[last] = value

    return m


def _attr(name: str, value: Any) -> Callable[[Any], None]:
    def m(b: Any) -> None:
        setattr(b, name, value() if callable(value) else value)

    return m


def _call(fn: Callable[[Any], None]) -> Callable[[Any], None]:
    return fn


def _post(fn: Callable[[dict[str, Any]], None]) -> Factory:
    return lambda: build(post=fn)


def _mut(*muts: Callable[[Any], None]) -> Factory:
    def m(b: Any) -> None:
        for x in muts:
            x(b)

    return lambda: build(mutate=m)


def _replace_key(role: str, kid: str | None = None) -> Callable[[dict[str, Any]], None]:
    def p(bundle: dict[str, Any]) -> None:
        bundle["keys"][role] = [other_key_jwk(kid or bundle["keys"][role][0]["kid"])]

    return p


def _three_segments(member: str) -> Callable[[dict[str, Any]], None]:
    def p(bundle: dict[str, Any]) -> None:
        s = segments(bundle[member])
        bundle[member] = s[0][:-1] + "~~" + s[1][:-1] + "~~" + s[1]

    return p


def _add_constraint(attr: str, c: dict[str, Any]) -> Callable[[Any], None]:
    def m(b: Any) -> None:
        getattr(b, attr)["constraints"].append(c)

    return m


def _dup_first_disclosure(member: str) -> Callable[[dict[str, Any]], None]:
    def p(b: dict[str, Any]) -> None:
        first = segments(b[member])[0].split("~")[1]
        b[member] = add_disclosure(b[member], 0, first)

    return p


def _withhold_constraint(kind: str, ctype: str) -> Callable[[Any], None]:
    """Issuer makes each constraint SD; the agent withholds the one of type ctype."""

    def m(b: Any) -> None:
        o = getattr(b, f"open_{kind}")
        o["constraints"] = [SdElem(c) for c in o["constraints"]]

        def pred(d: list[Any]) -> bool:
            v = d[-1]
            if len(d) != 2 or not isinstance(v, dict):
                return False
            if v.get("type") == ctype:
                return True
            # nested acceptable item of a withheld line_items constraint
            return ctype == "checkout.line_items" and "title" in v and "vct" not in v

        b.withhold[kind] = pred

    return m


def _withhold_property(kind: str, name: str, value: Any) -> Callable[[Any], None]:
    """Issuer makes a mandate-level claim SD; the agent withholds it."""

    def m(b: Any) -> None:
        o = getattr(b, f"open_{kind}")
        o[name] = SdProp(value if value is not None else o[name])

        def pred(d: list[Any]) -> bool:
            if len(d) == 3 and d[1] == name:
                return True
            # withholding the whole constraints claim also orphans its nested disclosures
            return (
                name == "constraints"
                and len(d) == 2
                and not (isinstance(d[1], dict) and "vct" in d[1])
            )

        b.withhold[kind] = pred

    return m


BUDGET_OK = {"type": "payment.budget", "max": 1000.00, "currency": "USD"}
RECUR = {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 12}
EXEC_WINDOW = {
    "type": "payment.execution_date",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2026-12-31T23:59:59Z",
}


def _receipt(kind: str, **claims: Any) -> Callable[[Any], None]:
    def m(b: Any) -> None:
        getattr(b, f"{kind}_receipt").update(claims)

    return m


def _receipt_prose(kind: str) -> Callable[[Any], None]:
    def m(b: Any) -> None:
        r = getattr(b, f"{kind}_receipt")
        r.pop("status")
        r["result"] = "success"

    return m


def _chain_cases(p: str, kind: str) -> list[Case]:
    member = f"{kind}_mandate"
    o, c, kb = f"open_{kind}", f"closed_{kind}", f"closed_{kind}_kb"
    signer = f"closed_{kind}_signer"
    unknown = {"type": f"{kind}.max_weight", "max": 5}
    cases: list[Case] = [
        (
            f"{p}01",
            "FAIL",
            "parse_error",
            _post(lambda b: b.__setitem__(member, b[member][:120])),
            {},
        ),
        (f"{p}02", "FAIL", "alg_not_allowed", _mut(_set("open_header.alg", "HS256")), {}),
        (f"{p}03", "FAIL", "signature_invalid", _post(_replace_key("mandate_issuer")), {}),
        # A4: a forged root whose kid matches no supplied key still FAILs (not SKIP)
        (
            f"{p}03",
            "FAIL",
            "signature_invalid",
            _post(_replace_key("mandate_issuer", "some-other-kid")),
            {},
        ),
        (
            f"{p}04",
            "FAIL",
            "unreferenced_disclosure",
            _post(
                lambda b: b.__setitem__(
                    member, add_disclosure(b[member], 0, disclosure(["salt-x", OTHER_MERCHANT]))
                )
            ),
            {},
        ),
        (f"{p}04", "FAIL", "duplicate_disclosure", _post(_dup_first_disclosure(member)), {}),
        (f"{p}05", "FAIL", "wrong_vct", _mut(_set(f"{o}.vct", f"mandate.{kind}.open")), {}),
        (f"{p}06", "FAIL", "no_cnf_jwk", _mut(_set(f"{o}.cnf", _DEL)), {}),
        (f"{p}07", "FAIL", "wrong_typ", _mut(_set("closed_header.typ", "JWT")), {}),
        (f"{p}07", "WARN", "typ_variant", _mut(_set("closed_header.typ", "kb-sd-jwt")), {}),
        (f"{p}08", "FAIL", "signature_invalid", _mut(_attr(signer, _k)), {}),
        (f"{p}09", "FAIL", "binding_mismatch", _mut(_set(f"{kb}.sd_hash", "A" * 43)), {}),
        (
            f"{p}09",
            "FAIL",
            "binding_claim_count",
            _mut(_set(f"{kb}.issuer_jwt_hash", "A" * 43)),
            {},
        ),
        (
            f"{p}10",
            "FAIL",
            "unreferenced_disclosure",
            _post(
                lambda b: b.__setitem__(
                    member, add_disclosure(b[member], 1, disclosure(["salt-y", "extra", 1]))
                )
            ),
            {},
        ),
        (f"{p}11", "FAIL", "wrong_vct", _mut(_set(f"{c}.vct", f"mandate.{kind}")), {}),
        (
            f"{p}12",
            "FAIL",
            "cnf_in_closed",
            _mut(_set(f"{c}.cnf", {"jwk": other_key_jwk(None)})),
            {},
        ),
        (
            f"{p}14",
            "FAIL",
            "aud_mismatch",
            _post(lambda b: b["expected"][kind].__setitem__("aud", "somebody-else")),
            {},
        ),
        (
            f"{p}15",
            "FAIL",
            "nonce_mismatch",
            _post(lambda b: b["expected"][kind].__setitem__("nonce", "other-nonce")),
            {},
        ),
        (f"{p}16", "FAIL", "signed_before_open", _mut(_set(f"{kb}.iat", T0 - 10_000)), {}),
        (f"{p}16", "FAIL", "signed_after_expiry", _mut(_set(f"{kb}.iat", T0 + 10_000)), {}),
        (f"{p}17", "FAIL", "unknown_constraint_type", _mut(_add_constraint(o, unknown)), {}),
        # A8 (iv): a non-string constraint type is a clean FAIL, not an internal error
        (
            f"{p}17",
            "FAIL",
            "unknown_constraint_type",
            _mut(_add_constraint(o, {"type": {"x": 1}})),
            {},
        ),
        (f"{p}19", "PASS", None, f_default, {"at": T0 + 60}),
        (f"{p}19", "FAIL", "not_valid_at", f_default, {"at": NOW + 10**6}),
        (f"{p}20", "SKIP", "delegation_unsupported", _post(_three_segments(member)), {}),
        (f"{p}21", "FAIL", "malformed_constraint", _mut(_set(f"{o}.constraints", "none")), {}),
        (f"{p}21", "WARN", "missing_required_constraint", _mut(_set(f"{o}.constraints", [])), {}),
        (f"{p}21", "WARN", "no_constraints", _mut(_set(f"{o}.constraints", _DEL)), {}),
    ]
    if kind == "checkout":
        cases += [
            (f"{p}13", "FAIL", "wrong_type", _mut(_set(f"{c}.iat", "yesterday")), {}),
            (f"{p}13", "FAIL", "missing_field", _mut(_set(f"{c}.checkout_jwt", _DEL)), {}),
            (f"{p}18", "FAIL", "preset_claim_changed", _mut(_set(f"{o}.checkout_hash", "x")), {}),
            # A3: items: true must FAIL the field/type check (and not crash the report)
            (
                f"{p}21",
                "FAIL",
                "malformed_constraint",
                _mut(_set(f"{o}.constraints.0.items", True)),
                {},
            ),
            (
                f"{p}22",
                "FAIL",
                "hidden_constraint",
                _mut(_withhold_constraint("checkout", "checkout.line_items")),
                {},
            ),
            (
                f"{p}22",
                "SKIP",
                "withheld_claim",
                _mut(_withhold_property("checkout", "constraints", None)),
                {},
            ),
        ]
    else:
        cases += [
            (f"{p}13", "FAIL", "missing_field", _mut(_set(f"{c}.payee", _DEL)), {}),
            (f"{p}13", "FAIL", "wrong_type", _mut(_set(f"{c}.payment_amount.amount", 199.0)), {}),
            (
                f"{p}18",
                "FAIL",
                "preset_claim_changed",
                _mut(_set(f"{o}.payment_amount", {"amount": 10000, "currency": "USD"})),
                {},
            ),
            (
                f"{p}10",
                "FAIL",
                "multiple_mandate_objects",
                lambda: two_object_closed_payment(with_vct=False),
                {},
            ),
            (
                f"{p}22",
                "FAIL",
                "hidden_constraint",
                _mut(_withhold_constraint("payment", "payment.amount_range")),
                {},
            ),
            (
                f"{p}22",
                "SKIP",
                "withheld_claim",
                _mut(
                    _withhold_property(
                        "payment", "payment_amount", {"amount": 19900, "currency": "USD"}
                    )
                ),
                {},
            ),
        ]
    return cases


def _payee_other(b: Any) -> None:
    b.closed_payment["payee"] = dict(OTHER_MERCHANT)
    b.open_payment["constraints"][1]["allowed"].append(SdElem(dict(OTHER_MERCHANT)))


def _non_ucp_without_totals(b: Any) -> None:
    for k in ("totals", "links", "currency"):
        b.checkout_payload.pop(k)


def _issuer_b(b: Any) -> None:
    b.payment_issuer = (_k(), "user-B-credential")


CASES: list[Case] = [
    (
        "B01",
        "FAIL",
        "bad_version",
        _post(lambda b: b.__setitem__("bundle_version", "ap2-evidence/2")),
        {},
    ),
    ("B01", "FAIL", "bad_version", _post(lambda b: b.pop("bundle_version")), {}),
    ("B01", "FAIL", "bad_member_type", _post(lambda b: b.__setitem__("checkout_mandate", 5)), {}),
    ("B01", "WARN", "unknown_member", _post(lambda b: b.__setitem__("extra_member", 1)), {}),
    ("B02", "FAIL", "no_artifacts", lambda: {"bundle_version": "ap2-evidence/1"}, {}),
    ("B02", "SKIP", "missing_artifact", _post(lambda b: b.pop("payment_receipt")), {}),
    (
        "B03",
        "FAIL",
        "invalid_key",
        _post(lambda b: b["keys"]["merchant"].append({"kty": "EC", "crv": "P-256", "x": "a"})),
        {},
    ),
    *_chain_cases("CM", "checkout"),
    *_chain_cases("PM", "payment"),
    ("CM30", "FAIL", "alg_not_allowed", _mut(_set("checkout_header.alg", "HS256")), {}),
    (
        "CM31",
        "FAIL",
        "hash_mismatch",
        _mut(_set("closed_checkout.checkout_hash", hash_b64("other", "sha-256"))),
        {},
    ),
    ("CM32", "FAIL", "signature_invalid", _post(_replace_key("merchant")), {}),
    ("CM33", "FAIL", "malformed_checkout", _mut(_set("checkout_payload.totals", "lots")), {}),
    ("CM33", "WARN", "not_ucp", _mut(_set("checkout_payload.links", _DEL)), {}),
    (
        "CM34",
        "FAIL",
        "merchant_not_allowed",
        _mut(_set("open_checkout.constraints.1.allowed", [SdElem(dict(OTHER_MERCHANT))])),
        {},
    ),
    ("CM34", "FAIL", "none_revealed", _mut(_set("open_checkout.constraints.1.allowed", [])), {}),
    (
        "CM35",
        "FAIL",
        "quantity_exceeded",
        _mut(_set("checkout_payload.line_items.0.quantity", 2)),
        {},
    ),
    (
        "CM35",
        "FAIL",
        "item_not_acceptable",
        _mut(_set("checkout_payload.line_items.0.item.id", "gold_bar_1kg")),
        {},
    ),
    (
        "CM35",
        "WARN",
        "requirement_unfilled",
        _mut(_set("open_checkout.constraints.0.items.0.quantity", 2)),
        {},
    ),
    (
        "PM30",
        "FAIL",
        "transaction_id_mismatch",
        _mut(_set("closed_payment.transaction_id", "B" * 43)),
        {},
    ),
    (
        "PM31",
        "FAIL",
        "reference_mismatch",
        _mut(_set("open_payment.constraints.3.conditional_transaction_id", "C" * 43)),
        {},
    ),
    ("PM32", "FAIL", "amount_above_max", lambda: build_demo_bundle("amount", seed=1, now=NOW), {}),
    (
        "PM32",
        "FAIL",
        "currency_mismatch",
        _mut(_set("closed_payment.payment_amount", {"amount": 19900, "currency": "EUR"})),
        {},
    ),
    ("PM32", "FAIL", "amount_below_min", _mut(_set("open_payment.constraints.0.min", 19950)), {}),
    (
        "PM33",
        "FAIL",
        "payee_not_allowed",
        _mut(_set("open_payment.constraints.1.allowed", [SdElem(dict(OTHER_MERCHANT))])),
        {},
    ),
    (
        "PM34",
        "FAIL",
        "instrument_not_allowed",
        _mut(_set("open_payment.constraints.2.allowed", [SdElem({"id": "x", "type": "card"})])),
        {},
    ),
    (
        "PM35",
        "PASS",
        None,
        _mut(_add_constraint("open_payment", {"type": "payment.allowed_pisps", "allowed": [PISP]})),
        {},
    ),
    (
        "PM35",
        "FAIL",
        "pisp_not_allowed",
        _mut(
            _add_constraint(
                "open_payment",
                {"type": "payment.allowed_pisps", "allowed": [dict(PISP, brand_name="Other")]},
            )
        ),
        {},
    ),
    (
        "PM35",
        "FAIL",
        "no_pisp",
        _mut(
            _add_constraint("open_payment", {"type": "payment.allowed_pisps", "allowed": [PISP]}),
            _set("closed_payment.pisp", _DEL),
        ),
        {},
    ),
    (
        "PM36",
        "PASS",
        None,
        _mut(
            _add_constraint("open_payment", EXEC_WINDOW),
            _set("closed_payment.execution_date", "2026-06-01"),
        ),
        {},
    ),
    (
        "PM36",
        "FAIL",
        "execution_date_after_window",
        _mut(
            _add_constraint("open_payment", EXEC_WINDOW),
            _set("closed_payment.execution_date", "2027-01-15"),
        ),
        {},
    ),
    ("PM37", "PASS", None, _mut(_add_constraint("open_payment", BUDGET_OK)), {}),
    (
        "PM37",
        "FAIL",
        "budget_exceeded",
        _mut(_add_constraint("open_payment", dict(BUDGET_OK, max=150))),
        {},
    ),
    (
        "PM38",
        "PASS",
        None,
        _mut(_add_constraint("open_payment", BUDGET_OK), _add_constraint("open_payment", RECUR)),
        {},
    ),
    (
        "PM38",
        "FAIL",
        "recurrence_missing_companion",
        _mut(_add_constraint("open_payment", RECUR)),
        {},
    ),
    # cumulative limits need the operator-supplied history
    (
        "PM39",
        "SKIP",
        "history_needed",
        _mut(_add_constraint("open_payment", BUDGET_OK)),
        {},
    ),
    (
        "PM39",
        "PASS",
        None,
        _mut(_add_constraint("open_payment", BUDGET_OK)),
        {"history": {"prior_total": {"amount": 80100, "currency": "USD"}}},
    ),
    (
        "PM39",
        "FAIL",
        "budget_exceeded",
        _mut(_add_constraint("open_payment", BUDGET_OK)),
        {"history": {"prior_total": {"amount": 80101, "currency": "USD"}}},
    ),
    (
        "XC01",
        "FAIL",
        "amount_mismatch",
        _mut(_set("closed_payment.payment_amount.amount", 19000)),
        {},
    ),
    # A2: when the checkout total cannot be read at all, XC01 is a REQUIRED skip
    ("XC01", "SKIP", "total_unreadable", _mut(_non_ucp_without_totals), {}),
    ("XC02", "FAIL", "payee_mismatch", _mut(_payee_other), {}),
    ("XC02", "SKIP", "merchant_unreadable", _mut(_set("checkout_payload.merchant", _DEL)), {}),
    ("XC03", "WARN", "agent_key_differs", _mut(_attr("payment_agent", _k)), {}),
    ("XC04", "WARN", "issuer_key_differs", _mut(_issuer_b), {}),
]

for _p, _kind in (("CR", "checkout"), ("PR", "payment")):
    _member = f"{_kind}_receipt"
    _id_field = "order_id" if _kind == "checkout" else "psp_confirmation_id"
    CASES += [
        (
            f"{_p}01",
            "FAIL",
            "sd_jwt_receipt",
            _post(lambda b, m=_member: b.__setitem__(m, b["payment_mandate"])),
            {},
        ),
        (f"{_p}02", "FAIL", "signature_invalid", _mut(_attr(f"{_kind}_receipt_signer", _k)), {}),
        (f"{_p}03", "FAIL", "missing_field", _mut(_receipt(_kind, **{_id_field: None})), {}),
        (f"{_p}03", "WARN", "prose_receipt_form", _mut(_receipt_prose(_kind)), {}),
        # A8 (iii): status Success together with result error is ambiguous
        (f"{_p}03", "FAIL", "conflicting_outcome", _mut(_receipt(_kind, result="error")), {}),
        (f"{_p}04", "FAIL", "reference_mismatch", _mut(_receipt(_kind, reference="D" * 43)), {}),
        # an authentic Error receipt documents a declined step: WARN, not a broken link
        (
            f"{_p}05",
            "WARN",
            "declined",
            _mut(
                _receipt(
                    _kind,
                    status="Error",
                    error="invalid_mandate",
                    error_description="declined by issuer",
                )
            ),
            {},
        ),
        (
            f"{_p}05",
            "FAIL",
            "success_with_error",
            _mut(_receipt(_kind, error="card_declined")),
            {},
        ),
        (f"{_p}06", "FAIL", "receipt_before_mandate", _mut(_receipt(_kind, iat=T0 - 5000)), {}),
        (
            f"{_p}07",
            "WARN",
            "issuer_mismatch",
            _mut(_receipt(_kind, iss="https://unexpected.example")),
            {},
        ),
    ]


def _rp(**exp: Any) -> dict[str, Any]:
    return {"expected": exp}


CASES += [
    ("EX01", "SKIP", "not_expected", f_default, {}),
    ("EX02", "PASS", None, f_default, _rp(checkout_id="demo-checkout-0001")),
    ("EX02", "FAIL", "checkout_id_mismatch", f_default, _rp(checkout_id="other")),
    ("EX03", "PASS", None, f_default, _rp(merchant_id="merchant_1")),
    ("EX03", "FAIL", "merchant_id_mismatch", f_default, _rp(merchant_id="merchant_9")),
    ("EX04", "PASS", None, f_default, _rp(total={"amount": 19900, "currency": "USD"})),
    ("EX04", "FAIL", "total_mismatch", f_default, _rp(total={"amount": 19901, "currency": "USD"})),
    ("EX05", "PASS", None, f_default, _rp(require_constraints=["payment.amount_range"])),
    (
        "EX05",
        "FAIL",
        "constraint_missing",
        f_default,
        _rp(require_constraints=["payment.budget"]),
    ),
]


def _agent_jwk() -> dict[str, Any]:
    from ap2_evidence.jose import public_jwk
    from helpers import KEYS

    return public_jwk(KEYS.agent)


CASES += [
    ("EX01", "PASS", None, f_default, _rp(agent_key=_agent_jwk())),
    ("EX01", "FAIL", "agent_key_mismatch", f_default, _rp(agent_key=other_key_jwk(None))),
]

# Everything that passes in the default demo bundle is a PASS case too.
DEFAULT_SKIPS = {"CM19", "PM19", "PM35", "PM36", "PM37", "PM38", "PM39"}
DEFAULT_SKIPS |= {"EX01", "EX02", "EX03", "EX04", "EX05"}  # need expectations
CASES += [(cid, "PASS", None, f_default, {}) for cid in REGISTRY if cid not in DEFAULT_SKIPS]


@cache
def _report_for(index: int) -> Any:
    _, _, _, factory, kw = CASES[index]
    return verify(copy.deepcopy(factory()), **kw)


@cache
def _default_report() -> Any:
    return verify(f_default())


def _get(index: int) -> Any:
    _, _, _, factory, kw = CASES[index]
    return _default_report() if factory is f_default and not kw else _report_for(index)


@pytest.mark.parametrize(
    "index",
    range(len(CASES)),
    ids=[f"{c[0]}-{c[1]}-{c[2] or 'ok'}-{i}" for i, c in enumerate(CASES)],
)
def test_case(index: int) -> None:
    cid, expected, reason, _, _ = CASES[index]
    got = _get(index).check(cid)
    assert got.status == expected, f"{cid}: expected {expected}, got {got.status}: {got.detail}"
    assert got.reason == reason, f"{cid}: expected reason {reason}, got {got.reason}: {got.detail}"


def test_registry_fully_covered() -> None:
    covered = {(c[0], c[1]) for c in CASES}
    missing = []
    for cid, d in REGISTRY.items():
        if d.can_pass and (cid, "PASS") not in covered:
            missing.append(f"{cid}: no PASS case")
        if (cid, d.worst) not in covered:
            missing.append(f"{cid}: no {d.worst} case")
    assert not missing, missing


def test_forged_cases_name_a_reason() -> None:
    assert all(c[2] for c in CASES if c[1] != "PASS")


def test_case_table_only_uses_registry_ids() -> None:
    assert {c[0] for c in CASES} <= set(REGISTRY)


def test_merchant_constant_unchanged() -> None:
    # The forged cases above rely on the demo merchant being merchant_1.
    assert MERCHANT["id"] == "merchant_1"


def test_every_non_pass_result_has_a_hint_and_reason() -> None:
    missing = set()
    for i in range(len(CASES)):
        for c in _get(i).checks:
            if c.status != "PASS" and (not c.hint or not c.reason):
                missing.add((c.id, c.status, c.reason, c.detail[:60]))
            if c.status == "PASS":
                assert c.reason is None
    assert not missing, sorted(missing)


def test_no_internal_errors_in_table() -> None:
    errors = set()
    for i in range(len(CASES)):
        for c in _get(i).checks:
            if c.reason == "internal_error":
                errors.add((c.id, c.detail[:120]))
    assert not errors, sorted(errors)
