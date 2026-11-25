from __future__ import annotations

import json

import pytest

from ap2_evidence import constraints as C
from ap2_evidence import currency, strictjson
from ap2_evidence.jose import (
    JoseError,
    b64url_decode,
    b64url_encode,
    jwk_thumbprint,
    load_public_jwk,
    parse_compact,
    public_jwk,
    sign_es256,
    verify_es256,
)
from ap2_evidence.report import clean, md
from ap2_evidence.sdjwt import (
    ResolvedList,
    SdJwtError,
    parse_chain,
    parse_segment,
    resolve,
    split_chain,
)
from helpers import KEYS, build, disclosure


@pytest.mark.parametrize("bad", ["a=", "ab==", "a", "a+b/", "ab c", "AB"])
def test_b64url_rejects_non_canonical(bad: str) -> None:
    # "AB" decodes to 1 byte with non-zero unused bits (canonical form is "AA")
    with pytest.raises(JoseError):
        b64url_decode(bad)


def test_b64url_roundtrip() -> None:
    for n in range(40):
        raw = bytes(range(n))
        assert b64url_decode(b64url_encode(raw)) == raw


@pytest.mark.parametrize(
    "text", ['{"a":1,"a":2}', "[NaN]", "[Infinity]", "[-Infinity]", "{", "[" * 100 + "]" * 100]
)
def test_strict_json_rejects(text: str) -> None:
    with pytest.raises(strictjson.StrictJsonError):
        strictjson.loads(text)


def test_strict_json_size_cap() -> None:
    with pytest.raises(strictjson.StrictJsonError):
        strictjson.loads("[" + "1," * 100 + "1]", max_bytes=50)


def test_es256_raw_signature_and_tamper() -> None:
    tok = sign_es256({"alg": "ES256"}, {"x": 1}, KEYS.merchant)
    key = load_public_jwk(public_jwk(KEYS.merchant))
    jws = parse_compact(tok)
    assert len(jws.signature) == 64
    assert verify_es256(jws, key)
    h, p, s = tok.split(".")
    other = parse_compact(f"{h}.{b64url_encode(json.dumps({'x': 2}).encode())}.{s}")
    assert not verify_es256(other, key)
    none_header = b64url_encode(b'{"alg": "none"}')
    none = parse_compact(f"{none_header}.{p}.")
    assert not verify_es256(none, key)


def test_jwk_validation() -> None:
    good = public_jwk(KEYS.agent, "k1")
    load_public_jwk(good)
    for bad in (
        dict(good, kty="RSA"),
        dict(good, crv="P-384"),
        dict(good, x=good["x"][:-1]),
        dict(good, y=good["x"]),  # not on the curve (almost surely)
        dict(good, d="AAAA"),
        dict(good, foo="bar"),
        dict(good, alg="ES384"),
        "not a dict",
    ):
        with pytest.raises(JoseError):
            load_public_jwk(bad)


def test_rfc7638_thumbprint_example() -> None:
    # RFC 7638 section 3.1 uses RSA; check an EC vector computed by hand instead.
    jwk = {"kty": "EC", "crv": "P-256", "x": "A" * 43, "y": "B" * 43}
    expected = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": "A" * 43, "y": "B" * 43}, separators=(",", ":")
    )
    import hashlib

    assert jwk_thumbprint(jwk) == b64url_encode(hashlib.sha256(expected.encode()).digest())


def test_split_chain_restores_tilde() -> None:
    assert split_chain("a.b.c~d1~~e.f.g~d2~") == ["a.b.c~d1~", "e.f.g~d2~"]
    assert split_chain("a.b.c~~e.f.g~") == ["a.b.c~", "e.f.g~"]
    for bad in ("", "~~x", "a~~~~b", "a~~~b"):
        with pytest.raises(SdJwtError):
            split_chain(bad)


def test_trailing_kb_jwt_rejected() -> None:
    chain = build()["checkout_mandate"]
    with pytest.raises(SdJwtError, match="trailing KB-JWT"):
        parse_chain(chain + "a.b.c")


def test_resolve_recursive_and_hidden() -> None:
    chain = build()["checkout_mandate"]
    seg = parse_chain(chain)[0]
    res = resolve(seg)
    assert not res.errors
    allowed = res.payload["delegate_payload"][0]["constraints"][1]["allowed"]
    assert isinstance(allowed, ResolvedList) and allowed.hidden == 0 and len(allowed) == 1
    # Remove the merchant disclosure: it becomes hidden, not an error.
    parts = seg.presented.split("~")
    trimmed = "~".join([parts[0], parts[1], parts[3], ""])
    res2 = resolve(parse_segment(trimmed, 1))
    assert not res2.errors
    allowed2 = res2.payload["delegate_payload"][0]["constraints"][1]["allowed"]
    assert len(allowed2) == 0 and allowed2.hidden == 1


def test_resolve_unreferenced_and_wrong_kind() -> None:
    seg_text = parse_chain(build()["checkout_mandate"])[0].presented
    extra = disclosure(["salt", "name", "value"])
    res = resolve(parse_segment(seg_text + extra + "~", 1))
    assert any("not referenced" in e for e in res.errors)
    assert res.unreferenced == [4]


def test_unsupported_sd_alg() -> None:
    tok = sign_es256({"alg": "ES256"}, {"_sd_alg": "md5", "delegate_payload": []}, KEYS.issuer)
    res = resolve(parse_segment(tok + "~", 1))
    assert res.payload is None and "unsupported _sd_alg" in res.errors[0]


def test_currency() -> None:
    assert currency.format_minor(19900, "USD") == "USD 199.00"
    assert currency.format_minor(1000, "KRW") == "KRW 1000"
    assert currency.format_minor(1500, "KWD") == "KWD 1.500"
    assert currency.major_to_minor(1000.00, "USD") == 100000
    assert currency.major_to_minor(10, "JPY") == 10
    assert currency.major_to_minor(1.5, "BHD") == 1500
    assert currency.exponent("XYZ") == (2, False)


def test_budget_uses_currency_exponent() -> None:
    amt = {"amount": 1500, "currency": "KRW"}
    assert C.eval_budget({"max": 1000, "currency": "KRW"}, amt).status == "FAIL"
    assert C.eval_budget({"max": 2000, "currency": "KRW"}, amt).status == "PASS"
    assert (
        C.eval_budget({"max": 1.5, "currency": "KWD"}, {"amount": 1500, "currency": "KWD"}).status
        == "PASS"
    )
    assert (
        C.eval_budget({"max": 1.4, "currency": "KWD"}, {"amount": 1500, "currency": "KWD"}).status
        == "FAIL"
    )


def _req(rid: str, ids: list[str], qty: int) -> dict[str, object]:
    return {
        "id": rid,
        "acceptable_items": ResolvedList({"id": i, "title": i} for i in ids),
        "quantity": qty,
    }


def _cart(*items: tuple[str, int]) -> list[dict[str, object]]:
    return [{"item": {"id": i}, "quantity": q} for i, q in items]


def test_line_items_upstream_doc_example() -> None:
    # docs/ap2/checkout_mandate.md "Line Items" example
    c = {
        "type": "checkout.line_items",
        "items": [_req("shoes", ["BAB1234", "FAF1234"], 1), _req("socks", ["QRT1234"], 1)],
    }
    assert C.eval_line_items(c, _cart(("BAB1234", 1), ("QRT1234", 1))).status == "PASS"
    assert C.eval_line_items(c, _cart(("FAF1234", 1), ("QRT1234", 1))).status == "PASS"
    assert C.eval_line_items(c, _cart(("BAB1234", 1), ("FAF1234", 1))).status == "FAIL"
    # prose says invalid, upstream SDK accepts: reported as WARN
    assert C.eval_line_items(c, _cart(("BAB1234", 1))).status == "WARN"
    assert C.eval_line_items(c, _cart(("QRT1234", 1))).status == "WARN"


def test_line_items_needs_max_flow() -> None:
    # Greedy assignment of A to r1 would block B; max-flow finds A->r2, B->r1.
    c = {"items": [_req("r1", ["A", "B"], 1), _req("r2", ["A"], 1)]}
    assert C.eval_line_items(c, _cart(("A", 1), ("B", 1))).status == "PASS"
    assert C.eval_line_items(c, _cart(("A", 2), ("B", 1))).status == "FAIL"


def test_merchant_matching_like_upstream() -> None:
    a = {"id": "m1", "name": "A", "website": "https://a"}
    assert C.merchant_matches(a, {"id": "m1", "name": "Other"})
    assert not C.merchant_matches(a, {"id": "m2", "name": "A", "website": "https://a"})
    assert C.merchant_matches(
        {"name": "A", "website": "https://a"}, {"id": "x", "name": "A", "website": "https://a"}
    )
    assert not C.merchant_matches({"name": "A"}, {"name": "A"})


def test_execution_date_parsing() -> None:
    c = {"not_before": "2026-03-31T00:00:00Z", "not_after": "2026-04-30T23:59:59Z"}
    assert C.eval_execution_date(c, "2026-04-01").status == "PASS"
    assert C.eval_execution_date(c, "2026-04-01T09:00:00+09:00").status == "PASS"
    assert C.eval_execution_date(c, "2026-03-30").status == "FAIL"
    assert C.eval_execution_date(c, None).status == "PASS"
    assert "plain strings" in C.eval_execution_date(c, "next tuesday").detail


def test_clean_and_md_escape() -> None:
    assert clean("a\x1b[31mb") == "a\\x1b[31mb"
    assert clean("x‮y") == "x\\u202ey"
    assert clean("line1\nline2") == "line1 line2"  # whitespace collapsed
    assert clean("line1\nline2", collapse=False) == "line1\\x0aline2"
    assert clean("a" + " " * 80 + "b") == "a b"
    assert md("a|b`c*d_e<f>") == "a\\|b\\`c\\*d\\_e\\<f\\>"
    assert len(clean("x" * 1000, 10)) < 60
