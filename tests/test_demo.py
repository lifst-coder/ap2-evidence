from __future__ import annotations

import json

import pytest

from ap2_evidence import load_trusted_keys
from ap2_evidence.checks import REGISTRY
from ap2_evidence.demo import TAMPER_MODES, build_demo_bundle
from ap2_evidence.jose import public_jwk
from helpers import KEYS, NOW, build, other_key_jwk, statuses, verify

# Each scenario must be caught by a different check family.
TAMPER_EXPECT = {
    "amount": {"PM32", "XC01"},
    "receipt": {"PR04"},
    "disclosure": {"CM04"},
    "key": {"PM08"},
}


def test_demo_verified() -> None:
    r = verify(build_demo_bundle())
    assert r.verdict == "VERIFIED", r.to_text()
    assert r.exit_code == 0
    assert [c.id for c in r.checks] == list(REGISTRY)
    # demo keys come from the bundle: the caveat says so in plain words
    assert "keys that came inside the file itself" in r.conclusion
    assert "Whoever assembled the file could have put any keys there" in r.conclusion


@pytest.mark.parametrize("mode", sorted(TAMPER_MODES))
def test_tamper_modes(mode: str) -> None:
    r = verify(build_demo_bundle(mode))
    st = statuses(r)
    fails = {k for k, v in st.items() if v == "FAIL"}
    assert r.verdict == "FAILED"
    assert TAMPER_EXPECT[mode] <= fails, fails
    if mode in ("amount", "receipt", "key"):
        assert fails == TAMPER_EXPECT[mode], fails
    # signatures of the tampered artifacts are still valid where the scenario says so
    if mode == "amount":
        assert st["PM08"] == "PASS" and st["PR02"] == "PASS"
    if mode == "receipt":
        assert st["PR02"] == "PASS"


def test_tamper_families_differ() -> None:
    families = [{REGISTRY[c].group + c[:2] for c in ids} for ids in TAMPER_EXPECT.values()]
    primary = [sorted(f)[0] for f in families]
    assert len(set(primary)) == len(primary)


def test_unknown_tamper() -> None:
    with pytest.raises(ValueError):
        build_demo_bundle("nope")


def test_every_result_has_metadata() -> None:
    r = verify(build_demo_bundle("disclosure"))
    for c in r.checks:
        assert c.spec_ref and c.title and c.detail
        if c.status in ("FAIL", "WARN") and c.id not in ("XC03",):
            assert c.hint, c.id


def _trusted(**roles: list[dict[str, object]]) -> object:
    return load_trusted_keys(json.dumps(roles))


def test_trusted_keys_take_precedence_and_provenance() -> None:
    bundle = build()
    trusted = _trusted(
        mandate_issuer=[public_jwk(KEYS.issuer, KEYS.issuer_kid)],
        merchant=[public_jwk(KEYS.merchant, KEYS.merchant_kid)],
        payment_processor=[public_jwk(KEYS.processor, KEYS.processor_kid)],
    )
    r = verify(bundle, trusted_keys=trusted)
    assert r.verdict == "VERIFIED"
    assert r.check("CM03").key_provenance == "trusted"
    assert r.check("CM08").key_provenance == "mandate"
    assert "inside the file" not in r.conclusion
    assert "keys that the person running the tool supplied (pinned keys" in r.conclusion


def test_pinned_key_beats_forged_bundle_key() -> None:
    # Someone re-signed the merchant receipt with their own key and put that key in the bundle.
    from cryptography.hazmat.primitives.asymmetric import ec

    from ap2_evidence.demo import DemoBuilder

    fake = ec.generate_private_key(ec.SECP256R1())
    b = DemoBuilder(keys=KEYS, now=NOW)
    b.checkout_receipt_signer = fake
    bundle = b.build().bundle
    bundle["keys"]["merchant"] = [public_jwk(fake, KEYS.merchant_kid)]
    r_bundle_only = verify(bundle)
    assert r_bundle_only.check("CR02").status == "PASS"  # the forger's key verifies its own receipt
    trusted = _trusted(merchant=[public_jwk(KEYS.merchant, KEYS.merchant_kid)])
    r = verify(bundle, trusted_keys=trusted)
    assert r.check("CR02").status == "FAIL"
    assert r.check("CR02").key_provenance == "trusted"
    assert "ignored because --trusted-keys pins" in r.check("CR02").detail


def test_kid_mismatch_is_fail_when_the_role_has_keys() -> None:
    # Review finding A4: a kid that matches no supplied key must not downgrade to SKIP.
    bundle = build()
    bundle["keys"]["merchant"] = [other_key_jwk("some-other-kid")]
    r = verify(bundle)
    for cid in ("CM32", "CR02"):
        assert r.check(cid).status == "FAIL" and r.check(cid).reason == "signature_invalid"
        assert "matches none of them" in r.check(cid).detail


def test_key_without_kid_is_tried() -> None:
    bundle = build()
    bundle["keys"]["merchant"] = [public_jwk(KEYS.merchant)]  # no kid
    assert statuses(verify(bundle))["CM32"] == "PASS"


def test_no_keys_incomplete() -> None:
    bundle = build()
    del bundle["keys"]
    r = verify(bundle)
    assert r.verdict == "INCOMPLETE"
    assert {"CM03", "PM03", "CM32", "CR02", "PR02"} <= {n["id"] for n in r.not_verified()}


def test_missing_receipt_is_incomplete_and_says_so() -> None:
    bundle = build()
    del bundle["checkout_receipt"]
    r = verify(bundle)
    assert r.verdict == "INCOMPLETE"
    assert "Checkout Receipt is missing" in r.conclusion  # plain name of checkout_receipt
    assert "Ask the merchant for the Checkout Receipt." in r.effective_next_steps()


def test_direct_single_segment_mandate() -> None:
    def m(b: object) -> None:
        b.direct_payment = True  # type: ignore[attr-defined]

    r = verify(build(mutate=m))
    st = statuses(r)
    assert r.verdict == "VERIFIED", r.to_text()
    for cid in ("PM20", "PM03", "PM04", "PM11", "PM13", "PM30", "PR04"):
        assert st[cid] == "PASS", cid
    for cid in ("PM05", "PM06", "PM07", "PM08", "PM09", "PM14", "PM16", "PM31", "PM32"):
        assert st[cid] == "SKIP", cid
        assert r.check(cid).required is False, cid
    assert "directly signed" in r.check("PM08").detail


def test_more_than_two_segments_is_incomplete() -> None:
    from helpers import segments

    bundle = build()
    s = segments(bundle["checkout_mandate"])
    bundle["checkout_mandate"] = s[0][:-1] + "~~" + s[1][:-1] + "~~" + s[1]
    r = verify(bundle)
    assert r.check("CM20").status == "SKIP" and r.check("CM20").required
    assert r.check("CM08").blocked_by == "CM20"


def test_issuer_jwt_hash_binding_accepted() -> None:
    def m(b: object) -> None:
        b.binding["payment"] = "issuer_jwt_hash"  # type: ignore[attr-defined]

    r = verify(build(mutate=m))
    assert r.check("PM09").status == "PASS"
    assert "issuer_jwt_hash" in r.check("PM09").detail


def test_both_binding_claims_fail() -> None:
    def m(b: object) -> None:
        b.closed_checkout_kb["issuer_jwt_hash"] = "x"  # type: ignore[attr-defined]

    assert statuses(verify(build(mutate=m)))["CM09"] == "FAIL"


def test_prose_form_receipt_reference_accepted() -> None:
    def m(b: object) -> None:
        b.reference_form["payment"] = "prose"  # type: ignore[attr-defined]

    r = verify(build(mutate=m))
    assert r.check("PR04").status == "PASS"
    assert "prose form" in r.check("PR04").detail
    assert r.verdict == "VERIFIED"


def test_receipt_reference_to_open_mandate_is_explained() -> None:
    from ap2_evidence.jose import hash_b64, sign_es256
    from helpers import decode_jwt, segments

    bundle = build()
    open_jwt = segments(bundle["payment_mandate"])[0].split("~", 1)[0]
    header, payload = decode_jwt(bundle["payment_receipt"])
    payload["reference"] = hash_b64(open_jwt)
    bundle["payment_receipt"] = sign_es256(header, payload, KEYS.processor)
    r = verify(bundle)
    assert r.check("PR02").status == "PASS"
    assert r.check("PR04").status == "FAIL"
    assert "OPEN mandate" in r.check("PR04").detail


def test_line_items_wildcard_and_hidden() -> None:
    def empty(b: object) -> None:
        b.open_checkout["constraints"][0]["items"][0]["acceptable_items"] = []  # type: ignore[attr-defined]

    r = verify(build(mutate=empty))
    assert r.check("CM35").status == "PASS"
    assert "any item" in r.check("CM35").detail

    def hidden(bundle: dict[str, object]) -> None:
        from helpers import segments

        chain = bundle["checkout_mandate"]
        s = segments(chain)  # type: ignore[arg-type]
        parts = s[0].split("~")
        # drop the acceptable item disclosure (#1): it is then undisclosed, not empty
        s[0] = "~".join([parts[0], *parts[2:]])
        bundle["checkout_mandate"] = s[0][:-1] + "~~" + s[1]

    r2 = verify(build(post=hidden))
    assert r2.check("CM35").status == "FAIL"


def test_at_option_iso() -> None:
    from ap2_evidence.constraints import parse_when

    at = int(parse_when("2026-01-01T00:00:00Z").timestamp())  # type: ignore[union-attr]
    r = verify(build(), at=at)
    assert r.check("CM19").status == "FAIL"
