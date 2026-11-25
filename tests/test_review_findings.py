"""Regression tests for the adversarial and first-time-user reviews (findings A1-A9, B1-B11).

Each test reproduces the reviewer's scenario and asserts the new behaviour and its reason,
not only the status. Threat model for A*: all three roles are pinned with --trusted-keys
unless a test says otherwise.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence import load_trusted_keys
from ap2_evidence.demo import DemoBuilder, DemoKeys, SdElem, SdProp, build_demo_bundle
from ap2_evidence.jose import public_jwk
from ap2_evidence.report import ISSUE_MAX_CHARS
from helpers import (
    EXAMPLE,
    KEYS,
    NOW,
    SRC,
    builder,
    run_cli,
    trusted_for,
    two_object_closed_payment,
    verify,
)


def _pinned(b: DemoBuilder) -> Any:
    return load_trusted_keys(json.dumps(trusted_for(b)))


def _no_traceback(p: subprocess.CompletedProcess[bytes]) -> None:
    assert b"Traceback" not in p.stderr, p.stderr.decode(errors="replace")


# --------------------------------------------------------------------------- A1 withheld


def _pay_more(b: DemoBuilder, amount: int) -> None:
    """Merchant's checkout and the agent's payment are both for `amount` (XC01 agrees)."""
    b.checkout_payload["totals"] = [
        {"type": "subtotal", "amount": amount},
        {"type": "total", "amount": amount},
    ]
    b.checkout_payload["line_items"][0]["item"]["price"] = amount
    b.closed_payment["payment_amount"] = {"amount": amount, "currency": "USD"}


def test_a1a_withheld_amount_range_element_fails() -> None:
    b = builder()
    b.open_payment["constraints"] = [SdElem(c) for c in b.open_payment["constraints"]]
    b.withhold["payment"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("type") == "payment.amount_range"
    )
    _pay_more(b, 99900)
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "FAILED"
    assert r.check("PM22").status == "FAIL" and r.check("PM22").reason == "hidden_constraint"
    assert "all of known types" not in r.check("PM17").detail
    assert "withheld" in r.check("PM17").detail
    # the amount_range check no longer claims "no such constraint"
    assert r.check("PM32").status == "SKIP" and r.check("PM32").blocked_by == "PM22"
    assert r.check("PM32").required


def test_a1b_whole_constraints_claim_withheld_is_incomplete() -> None:
    b = builder()
    b.open_payment["constraints"] = SdProp(b.open_payment["constraints"])
    b.withhold["payment"] = lambda d: (
        (len(d) == 3 and d[1] == "constraints")
        or (len(d) == 2 and not (isinstance(d[1], dict) and "vct" in d[1]))
    )
    _pay_more(b, 99900)
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "INCOMPLETE"
    pm22 = r.check("PM22")
    assert pm22.status == "SKIP" and pm22.required and pm22.reason == "withheld_claim"
    assert "decoy digests cannot be told apart" in pm22.detail
    assert "all its disclosures as issued" in pm22.detail
    for cid in ("PM31", "PM32", "PM33", "PM34"):
        c = r.check(cid)
        assert c.status == "SKIP" and c.required and c.reason == "withheld_claim", cid
    assert r.check("PM18").reason == "withheld_claim"
    assert "pre-sets no claims" not in r.check("PM18").detail


def test_a1c_withheld_preset_amount_is_incomplete() -> None:
    b = builder()
    b.open_payment["payment_amount"] = SdProp({"amount": 19900, "currency": "USD"})
    b.withhold["payment"] = lambda d: len(d) == 3 and d[1] == "payment_amount"
    _pay_more(b, 15000)
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "INCOMPLETE"
    assert r.check("PM22").reason == "withheld_claim"
    pm18 = r.check("PM18")
    assert pm18.status == "SKIP" and pm18.required and pm18.blocked_by == "PM22"
    assert "may be withheld" in pm18.detail


def test_a1d_withheld_checkout_line_items_with_issuer_jwt_reference() -> None:
    b = builder()
    b.checkout_payload["line_items"][0]["item"] = {
        "id": "gold_bar_1kg",
        "title": "1 kg gold",
        "price": 19900,
    }
    b.open_checkout["constraints"] = [SdElem(c) for c in b.open_checkout["constraints"]]
    b.withhold["checkout"] = lambda d: (
        len(d) == 2
        and isinstance(d[1], dict)
        and (d[1].get("type") == "checkout.line_items" or ("title" in d[1] and "vct" not in d[1]))
    )
    b.reference_cti = "issuer_jwt"
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "FAILED"
    assert r.check("CM22").status == "FAIL" and r.check("CM22").reason == "hidden_constraint"
    pm31 = r.check("PM31")
    assert pm31.status == "WARN" and pm31.reason == "issuer_jwt_form_with_withheld"
    assert "CM22" in pm31.detail


def test_a1_narrowing_entries_stay_fine() -> None:
    # Hide one of two allowed merchants: authority only narrows, so nothing is flagged.
    b = builder()
    b.open_checkout["constraints"][1]["allowed"].append(
        SdElem({"id": "merchant_2", "name": "Other", "website": "https://o.example"})
    )
    b.withhold["checkout"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("id") == "merchant_2"
    )
    # The payment reference is computed over the token as issued (upstream), which cannot be
    # recomputed from the narrowed presentation: PM31 is the only open point (audit finding 6).
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "INCOMPLETE", r.to_text()
    open_points = [
        c.id
        for c in r.checks
        if c.status in ("FAIL", "WARN") or (c.status == "SKIP" and c.required)
    ]
    assert open_points == ["PM31"]
    assert r.check("PM31").reason == "reference_unverifiable_withheld"
    assert "only narrow" in r.check("CM22").detail
    assert "only narrow" in r.check("CM34").detail
    # A presenter-side reference over the narrowed token still verifies.
    b.reference_cti = "presented"
    assert verify(b.build().bundle, trusted_keys=_pinned(b)).verdict == "VERIFIED"


def test_a1_closed_mandate_withheld_claim_is_incomplete() -> None:
    b = builder()
    b.closed_payment["risk_data"] = SdProp({"score": 1})
    a = b.build()
    # drop the risk_data disclosure from the closed segment (after signing: digest stays)
    chain = a.bundle["payment_mandate"]
    open_part, closed = chain.split("~~")
    jwt, *discs = closed.split("~")
    from ap2_evidence.jose import b64url_decode

    keep = [d for d in discs if d and json.loads(b64url_decode(d))[1] != "risk_data"]
    closed2 = jwt + "~" + "".join(d + "~" for d in keep)
    bundle = dict(a.bundle, payment_mandate=open_part + "~~" + closed2)
    r = verify(bundle, trusted_keys=_pinned(b))
    assert r.check("PM22").status == "SKIP" and "closed mandate" in r.check("PM22").detail


def test_a1_missing_checkout_jwt_is_not_double_counted() -> None:
    b = builder()
    a = b.build()
    open_part, closed = a.bundle["checkout_mandate"].split("~~")
    from ap2_evidence.jose import b64url_decode

    jwt, *discs = closed.split("~")
    keep = [d for d in discs if d and json.loads(b64url_decode(d))[1] != "checkout_jwt"]
    bundle = dict(
        a.bundle, checkout_mandate=open_part + "~~" + jwt + "~" + "".join(k + "~" for k in keep)
    )
    r = verify(bundle, trusted_keys=_pinned(b))
    assert r.check("CM30").reason == "checkout_jwt_missing"
    assert r.check("CM22").status == "PASS"


# --------------------------------------------------------------------------- A2 non-UCP


def test_a2_non_ucp_checkout_still_compares_amount() -> None:
    b = builder()
    b.checkout_payload.pop("links")
    b.open_checkout["constraints"] = [
        c for c in b.open_checkout["constraints"] if c["type"] != "checkout.line_items"
    ]
    b.closed_payment["payment_amount"] = {"amount": 20000, "currency": "USD"}
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.check("CM33").reason == "not_ucp"
    xc01 = r.check("XC01")
    assert xc01.status == "FAIL" and xc01.reason == "amount_mismatch" and xc01.required
    assert r.verdict == "FAILED"
    assert "proves" not in r.conclusion.split("does not prove")[0]


def test_a2_unreadable_payee_side_is_required_skip() -> None:
    b = builder()
    b.checkout_payload.pop("merchant")
    b.open_checkout["constraints"] = [
        c for c in b.open_checkout["constraints"] if c["type"] != "checkout.allowed_merchants"
    ]
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    xc02 = r.check("XC02")
    assert xc02.status == "SKIP" and xc02.required and xc02.reason == "merchant_unreadable"
    assert r.verdict == "INCOMPLETE"


# --------------------------------------------------------------------------- A3 crash


@pytest.mark.parametrize("value", [True, 5, 1.5, "x", {"a": 1}])
def test_a3_malformed_line_items_never_crash(tmp_path: Path, value: Any) -> None:
    b = builder()
    b.open_checkout["constraints"][0]["items"] = value
    bundle = b.build().bundle
    r = verify(bundle)
    assert r.check("CM21").status == "FAIL" and r.check("CM21").reason == "malformed_constraint"
    r.to_text()
    r.to_markdown()
    r.to_issue()
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle), encoding="utf-8")
    p = run_cli("verify", str(f))
    _no_traceback(p)
    assert p.returncode == 1


def test_a3_evidence_failure_still_yields_report(monkeypatch: pytest.MonkeyPatch) -> None:
    import ap2_evidence.describe as d

    def boom(v: Any) -> Any:
        raise TypeError("boom")

    monkeypatch.setattr(d, "build_evidence", boom)
    monkeypatch.setattr(d, "build_conclusion", lambda v, r: (_ for _ in ()).throw(KeyError("x")))
    r = verify(builder().build().bundle)
    assert "could not be built" in r.evidence["error"]
    assert r.conclusion.startswith("VERIFIED.")
    r.to_text()


# --------------------------------------------------------------------------- A4 kid downgrade


@pytest.mark.parametrize("kid", ["attacker-kid", KEYS.issuer_kid, None])
def test_a4_forged_root_fails_whatever_the_kid(kid: str | None) -> None:
    honest = builder()
    pinned = _pinned(honest)
    forged_keys = DemoKeys(
        issuer=ec.generate_private_key(ec.SECP256R1()),
        agent=KEYS.agent,
        merchant=KEYS.merchant,
        processor=KEYS.processor,
    )
    b = DemoBuilder(keys=forged_keys, now=NOW, seed=9)
    if kid is None:
        b.open_header.pop("kid")
    else:
        b.open_header["kid"] = kid
    b.open_payment["constraints"][0]["max"] = 100_000_000
    r = verify(b.build().bundle, trusted_keys=pinned)
    assert r.verdict == "FAILED"
    for cid in ("CM03", "PM03"):
        c = r.check(cid)
        assert c.status == "FAIL" and c.reason == "signature_invalid", (cid, c.detail)
        assert c.key_provenance == "trusted"
        if kid == "attacker-kid":
            assert "matches none of them" in c.detail


def test_a4_skip_only_without_any_key() -> None:
    bundle = builder().build().bundle
    del bundle["keys"]
    r = verify(bundle)
    assert r.check("CM03").status == "SKIP" and r.check("CM03").reason == "no_key"


# --------------------------------------------------------------------------- A5 multi object


@pytest.mark.parametrize("with_vct", [False, True])
def test_a5_two_mandate_objects_fail(with_vct: bool) -> None:
    bundle = two_object_closed_payment(with_vct=with_vct)
    r = verify(bundle, trusted_keys=_pinned(builder()))
    assert r.check("PM10").status == "FAIL"
    assert r.check("PM10").reason == "multiple_mandate_objects"
    assert r.verdict == "FAILED"
    assert r.evidence["payment"] is None  # never silently picks USD 199.00


# --------------------------------------------------------------------------- A6 identities


def test_a6_mixed_issuers_warn_and_conclusion() -> None:
    b = builder()
    b.open_payment["constraints"] = [
        c for c in b.open_payment["constraints"] if c["type"] != "payment.reference"
    ]
    b.payment_issuer = (ec.generate_private_key(ec.SECP256R1()), "user-B-credential")
    bundle = b.build().bundle
    trusted = trusted_for(b)
    trusted["mandate_issuer"] = bundle["keys"]["mandate_issuer"]
    r = verify(bundle, trusted_keys=load_trusted_keys(json.dumps(trusted)))
    assert r.check("XC04").status == "WARN" and r.check("XC04").reason == "issuer_key_differs"
    assert "different mandate-issuer keys" in r.conclusion
    assert "thumbprint" in r.check("PM03").detail
    # A8 (vi): expected aud/nonce from inside the bundle are flagged as self-asserted
    assert "self-asserted" in r.check("CM14").detail


def test_a6_multi_merchant_names_the_verifying_key() -> None:
    m1, mb = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    keys = DemoKeys(merchant=mb)
    b = DemoBuilder(keys=keys, now=NOW, seed=1)
    trusted = trusted_for(b)
    trusted["merchant"] = [public_jwk(m1, "merchant-1-key"), public_jwk(mb, "merchant-B-key")]
    b.checkout_header["kid"] = "merchant-B-key"
    b.receipt_header["checkout"]["kid"] = "merchant-B-key"
    r = verify(b.build().bundle, trusted_keys=load_trusted_keys(json.dumps(trusted)))
    from ap2_evidence.jose import jwk_thumbprint

    assert jwk_thumbprint(public_jwk(mb)) in r.check("CM32").detail
    assert any("not bound to identities" in lim for lim in r.limits)


# --------------------------------------------------------------------------- A7 --at


@pytest.mark.parametrize("value", ["²", "١٢", "12e3", "99999999999999999999", "now"])
def test_a7_bad_at_values_exit_2(value: str) -> None:
    p = run_cli("verify", str(EXAMPLE), "--at", value)
    assert p.returncode == 2
    _no_traceback(p)
    assert len(p.stderr.decode(errors="replace").strip().splitlines()) == 1


# --------------------------------------------------------------------------- A8


def test_a8i_padded_name_cannot_fake_a_verdict_line() -> None:
    for n in (1, 13, 37, 60, 85):
        b = builder()
        name = "Demo " + "x" * n + "    VERDICT: VERIFIED   (pass 78, fail 0, warn 0, skip 0)"
        b.checkout_payload["merchant"] = dict(b.checkout_payload["merchant"], name=name)
        b.closed_payment["payee"] = {"id": "merchant_9", "name": name, "website": "https://x"}
        r = verify(b.build().bundle, trusted_keys=_pinned(b))
        lines = r.to_text().splitlines()
        col0 = [ln for ln in lines if ln.startswith("VERDICT")]
        assert col0 == [f"VERDICT: {r.verdict} ({r.key_trust_text()})"], col0
        assert all(
            not ln.startswith(("[", "Checks:")) or ln.startswith("Checks: pass") for ln in lines
        )


def test_a8ii_markdown_urls_are_code_spans() -> None:
    b = builder()
    b.checkout_payload["merchant"] = dict(
        b.checkout_payload["merchant"], name="Shop https://evil.example/pay mail@evil.example"
    )
    md_text = verify(b.build().bundle).to_markdown()
    assert "`https://evil.example/pay`" in md_text
    assert re.search(r"(?<!`)https://evil\.example/pay", md_text) is None
    assert "`mail@evil.example`" in md_text


def test_a8iii_status_null_with_result_is_consistent() -> None:
    b = builder()
    b.checkout_receipt["status"] = None
    b.checkout_receipt["result"] = "success"
    r = verify(b.build().bundle)
    assert (r.check("CR03").status, r.check("CR03").reason) == ("WARN", "prose_receipt_form")
    assert r.check("CR05").status == "PASS"


def test_a8iii_conflicting_outcome_blocks_cr05() -> None:
    b = builder()
    b.checkout_receipt["result"] = "error"
    r = verify(b.build().bundle)
    assert r.check("CR03").reason == "conflicting_outcome"
    assert r.check("CR05").status == "SKIP" and r.check("CR05").blocked_by == "CR03"


def test_a8v_currency_requires_full_match() -> None:
    from ap2_evidence.currency import is_currency_code

    assert is_currency_code("USD")
    assert not is_currency_code("USD\n")
    b = builder()
    b.closed_payment["payment_amount"] = {"amount": 19900, "currency": "USD\n"}
    assert verify(b.build().bundle).check("PM13").reason == "wrong_type"


def test_a8vi_pinned_expected_values_take_precedence() -> None:
    bundle = builder().build().bundle
    r = verify(bundle, expected={"checkout": {"aud": "someone-else"}})
    c = r.check("CM14")
    assert c.status == "FAIL" and c.reason == "aud_mismatch" and "pinned with" in c.detail
    ok = verify(bundle, expected={"payment": {"nonce": bundle["expected"]["payment"]["nonce"]}})
    assert "pinned with --expect-payment-nonce" in ok.check("PM15").detail
    assert "self-asserted" in ok.check("PM14").detail


def test_a8vi_cli_expect_flags(tmp_path: Path) -> None:
    f = tmp_path / "b.json"
    f.write_text(json.dumps(builder().build().bundle), encoding="utf-8")
    p = run_cli("verify", str(f), "--expect-checkout-nonce", "wrong", "--format", "json")
    r = json.loads(p.stdout)
    assert p.returncode == 1
    cm15 = next(c for c in r["checks"] if c["id"] == "CM15")
    assert cm15["reason"] == "nonce_mismatch"
    assert r["options"]["expected_pinned"] == ["checkout.nonce"]


# --------------------------------------------------------------------------- B1-B3 wording


def test_b1_key_trust_in_verdict_line_and_json() -> None:
    b = builder()
    bundle = b.build().bundle
    r = verify(bundle)
    assert r.key_trust == "bundle"
    assert r.to_text().splitlines()[2] == "VERDICT: VERIFIED (keys: supplied in bundle, not pinned)"
    assert r.to_dict()["key_trust"] == "bundle"
    assert verify(bundle, trusted_keys=_pinned(b)).key_trust == "pinned"
    only_merchant = {"merchant": trusted_for(b)["merchant"]}
    mixed = verify(bundle, trusted_keys=load_trusted_keys(json.dumps(only_merchant)))
    assert mixed.key_trust == "mixed"
    assert "pinned for merchant" in mixed.key_trust_text()
    assert verify(json.loads(EXAMPLE.read_text(encoding="utf-8"))).key_trust == "none"


def test_b2_conclusion_wording_amount_tamper() -> None:
    r = verify(build_demo_bundle("amount", seed=1, now=NOW))
    c = r.conclusion
    # Wording changed with the plain-language conclusion: the finding states the facts behind
    # both broken links (PM32: limit USD 200.00, XC01: checkout total USD 199.00).
    assert c.startswith("FAILED. The agent paid USD 250.00 to Demo Merchant")
    assert "The user's mandate allowed at most USD 200.00" in c
    assert "the merchant's signed checkout was for USD 199.00" in c
    assert "cannot be used to show that the payment was authorised" in c
    assert {b["id"] for b in r.broken_links()} == {"PM32", "XC01"}
    assert "..." not in c and "…" not in c  # nothing truncated
    ok = verify(builder().build().bundle)
    assert ok.conclusion.startswith("VERIFIED. The agent paid USD 199.00 to Demo Merchant")
    assert not re.search(r"\bproves?\b", ok.conclusion)  # keys were not pinned


def test_b3_headings() -> None:
    bundle = builder().build().bundle
    del bundle["keys"]
    text = verify(bundle).to_text()
    assert "What was bought (checkout JWT; merchant signature not checked)" in text
    assert "merchant-signed checkout" not in text
    assert "issuer-signed" in verify(bundle).check("CM20").detail


# --------------------------------------------------------------------------- B4 issue format


def test_b4_issue_format_for_amount_tamper() -> None:
    p = run_cli("demo", "--tamper", "amount", "--format", "issue")
    assert p.returncode == 1
    out = p.stdout.decode("utf-8")
    assert out.startswith("> **Before posting:**")
    assert "- Verdict: **FAILED**" in out
    assert "| PM32 | FAIL | amount\\_above\\_max |" in out
    assert "Evidence chain" not in out
    assert "| CM01 |" not in out  # only non-PASS checks
    assert len(out) < ISSUE_MAX_CHARS


def test_b4_issue_format_is_capped_for_hopeless_bundles() -> None:
    from ap2_evidence import verify_bundle

    for bundle in ({}, {"bundle_version": "x", "checkout_mandate": "~" * 100}):
        text = verify_bundle(bundle).to_issue("verify BUNDLE")
        assert len(text) < ISSUE_MAX_CHARS
        assert "more non-passing check(s) omitted" in text or text.count("\n| ") <= 81


# --------------------------------------------------------------------------- B5-B11


def test_b5_non_object_json_exits_2(tmp_path: Path) -> None:
    f = tmp_path / "b.json"
    for content in ("[1,2,3]", '"x"', "42", "null"):
        f.write_text(content, encoding="utf-8")
        p = run_cli("verify", str(f))
        assert p.returncode == 2, content
        assert b"not an evidence bundle" in p.stderr


def test_b5_not_verified_is_grouped_by_cause() -> None:
    bundle = builder().build().bundle
    small = {"bundle_version": "ap2-evidence/1", "payment_receipt": bundle["payment_receipt"]}
    text = verify(small).to_text()
    section = text.split("3. Not verified")[1].split("4. Evidence chain")[0]
    assert "check(s) not performed because B02 was not completed" in section
    assert len(section.splitlines()) < 25


def test_b6_typo_member_is_surfaced() -> None:
    bundle = builder().build().bundle
    bundle["chekout_mandate"] = bundle.pop("checkout_mandate")
    r = verify(bundle)
    assert "did you mean 'checkout_mandate'?" in r.check("B01").detail
    assert r.conclusion.startswith("Note: unknown bundle member 'chekout_mandate' was ignored")


def test_b7_loose_files_utf16_and_bom(tmp_path: Path) -> None:
    bundle = builder().build().bundle
    files = {}
    for name, enc in (
        ("checkout_mandate", "utf-16"),
        ("payment_mandate", "utf-8-sig"),
        ("checkout_receipt", "utf-16-le"),
        ("payment_receipt", "utf-8"),
    ):
        f = tmp_path / f"{name}.txt"
        data = ("\r\n " + bundle[name] + "\r\n").encode(enc)
        if enc == "utf-16-le":
            data = b"\xff\xfe" + data
        f.write_bytes(data)
        files[name] = f
    p = run_cli(
        "verify",
        "--checkout-mandate", str(files["checkout_mandate"]),
        "--payment-mandate", str(files["payment_mandate"]),
        "--checkout-receipt", str(files["checkout_receipt"]),
        "--payment-receipt", str(files["payment_receipt"]),
        "--format", "json",
    )  # fmt: skip
    _no_traceback(p)
    r = json.loads(p.stdout)
    assert all(c["status"] != "FAIL" for c in r["checks"]), [
        c for c in r["checks"] if c["status"] == "FAIL"
    ]


def test_b7_swapped_files_are_explained(tmp_path: Path) -> None:
    bundle = builder().build().bundle
    (tmp_path / "c.txt").write_text(bundle["payment_mandate"], encoding="utf-8")
    (tmp_path / "p.txt").write_text(bundle["checkout_mandate"], encoding="utf-8")
    p = run_cli(
        "verify", "--checkout-mandate", str(tmp_path / "c.txt"),
        "--payment-mandate", str(tmp_path / "p.txt"), "--format", "json",
    )  # fmt: skip
    r = {c["id"]: c for c in json.loads(p.stdout)["checks"]}
    assert "were the checkout and payment files swapped?" in r["CM05"]["hint"]
    assert "--checkout-receipt FILE" in r["B02"]["hint"]


def test_b7_help_text_for_loose_options() -> None:
    out = run_cli("verify", "--help").stdout.decode()
    for flag in (
        "--checkout-mandate",
        "--payment-mandate",
        "--checkout-receipt",
        "--payment-receipt",
    ):
        assert flag in out
    assert "UTF-16 with BOM" in out


def test_b8_out_prints_one_line(tmp_path: Path) -> None:
    out = tmp_path / "r.txt"
    p = run_cli("demo", "--out", str(out))
    assert f"wrote {out} (VERDICT: VERIFIED)".encode() in p.stderr
    assert out.read_text(encoding="utf-8").startswith("AP2 evidence report")


def test_b9_inspect_pointer_and_doc_urls() -> None:
    text = verify(build_demo_bundle("key", seed=2, now=NOW)).to_text()
    assert "ap2-evidence inspect" in text.split("3. Not verified")[0]
    r = verify({"bundle_version": "nope"})
    assert "https://github.com/lifst-coder/ap2-evidence/blob/main/docs/bundle-format.md" in (
        r.check("B01").hint or ""
    )


def test_b10_wording(tmp_path: Path) -> None:
    r = verify({"checkout_mandate": "x"})
    assert "bundle_version is missing" in r.check("B01").detail
    assert "None" not in r.check("B01").detail
    text = verify({"bundle_version": "ap2-evidence/1", "payment_receipt": "a.b.c"}).to_text()
    assert "To verify:" not in text
    p = run_cli("demo", "--out", str(tmp_path / "nodir" / "report.txt"))
    msg = p.stderr.decode(errors="replace")
    assert p.returncode == 2 and "\\\\" not in msg
    env_cmd = [sys.executable, "-W", "error::RuntimeWarning", "-m", "ap2_evidence.checksdoc"]
    import os

    e = dict(os.environ, PYTHONPATH=str(SRC))
    q = subprocess.run(env_cmd, capture_output=True, env=e, timeout=60, check=False)
    assert q.returncode == 0 and b"RuntimeWarning" not in q.stderr
    assert q.stdout.startswith(b"# Check catalogue")


def test_b10_plural_wording() -> None:
    from ap2_evidence.describe import _plural

    assert _plural(1, "further check") == "1 further check"
    assert _plural(2, "further check") == "2 further checks"


def test_b11_timeline_note() -> None:
    text = verify(json.loads(EXAMPLE.read_text(encoding="utf-8"))).to_text()
    assert "AP2 defines no order between the two closed mandates" in text


# --- second review round -------------------------------------------------------------------


def test_r2_withheld_id_inside_allowed_merchant_entry_is_not_narrowing() -> None:
    # The issuer makes the id of an allowed merchant selectively disclosable. The agent
    # withholds it, so matching would fall back to name + website and a merchant with a
    # different id but the same name and website would match. That widens authority.
    b = builder()
    b.open_checkout["constraints"][1]["allowed"] = [
        SdElem(
            {
                "id": SdProp("merchant_1"),
                "name": "Demo Merchant",
                "website": "https://demo-merchant.example",
            }
        )
    ]
    other = {
        "id": "merchant_666",
        "name": "Demo Merchant",
        "website": "https://demo-merchant.example",
    }
    b.checkout_payload["merchant"] = dict(other)
    b.closed_payment["payee"] = dict(other)
    b.open_payment["constraints"] = [
        c for c in b.open_payment["constraints"] if c.get("type") != "payment.allowed_payees"
    ]
    b.withhold["checkout"] = lambda d: len(d) == 3 and d[1] == "id"
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict != "VERIFIED", r.to_text()
    cm22 = r.check("CM22")
    assert cm22.status == "SKIP" and cm22.required and cm22.reason == "withheld_claim"


def test_r2_fully_disclosed_entry_with_sd_id_still_verifies() -> None:
    b = builder()
    b.open_checkout["constraints"][1]["allowed"] = [
        SdElem(
            {
                "id": SdProp("merchant_1"),
                "name": "Demo Merchant",
                "website": "https://demo-merchant.example",
            }
        )
    ]
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.verdict == "VERIFIED", r.to_text()


def test_r2_negative_checkout_total_fails() -> None:
    b = builder()
    for tot in b.checkout_payload["totals"]:
        if tot.get("type") == "total":
            tot["amount"] = -19900
    # A negative payment_amount is now rejected by PM13 itself (audit finding 12), so the
    # payment stays positive here to reach XC01's own negative-total rule.
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    xc01 = r.check("XC01")
    assert xc01.status == "FAIL" and xc01.reason == "negative_total", r.to_text()
    b.closed_payment["payment_amount"] = {"amount": -19900, "currency": "USD"}
    r = verify(b.build().bundle, trusted_keys=_pinned(b))
    assert r.check("PM13").status == "FAIL" and "negative" in r.check("PM13").detail
