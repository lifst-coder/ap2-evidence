"""Regression tests for the final pre-publication review (findings F1-F12)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence import batch
from ap2_evidence.bundle import InputError, load_trusted_keys, parse_bundle_text
from ap2_evidence.checks import REGISTRY
from ap2_evidence.cli import main
from ap2_evidence.demo import AUTO, DemoBuilder, build_demo_bundle
from ap2_evidence.describe import NO_RECEIPT
from ap2_evidence.fileio import _write_error_reason, write_text
from ap2_evidence.keys import parse_key_text
from ap2_evidence.report import NOTHING_MORE, RECEIPT_GATE, Report
from helpers import NOW, ROOT, builder, trusted_for, verify

FX = ROOT / "tests" / "fixtures"
SDK = FX / "upstream-sdk"
CARD_KEYS = SDK / "card" / "trusted_keys.json"
K7 = SDK / "tamper" / "K7_error_receipt" / "bundle.json"

ERR = {"status": "Error", "error": "card_declined", "error_description": "Insufficient funds"}
PAY_ISS = "pay.demo-processor.example"
MERCHANT_ISS = "https://demo-merchant.example"


def _run(b: DemoBuilder) -> Report:
    return verify(b.build().bundle, trusted_keys=trusted_for(b))


def _sdk_error(b: DemoBuilder, kind: str) -> None:
    rec = getattr(b, f"{kind}_receipt")
    rec.update(ERR)
    for k in ("psp_confirmation_id", "network_confirmation_id", "order_id"):
        rec.pop(k, None)


def _prose(result: str, iss: str, **extra: Any) -> dict[str, Any]:
    return {"result": result, "iss": iss, "reference": AUTO, **extra}


def _cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def _headline(r: Report) -> str:
    """The receipts' part of a VERIFIED finding (before the warnings clause)."""
    return r.finding.split(" Every required check passed")[0]


# --------------------------------------------------------------------------- F1


def test_f1_prose_checkout_error_next_to_sdk_payment_success_is_conflicting() -> None:
    b = builder()
    b.checkout_receipt = _prose("error", MERCHANT_ISS, error="x")
    r = _run(b)
    assert r.verdict == "VERIFIED" and r.outcome == "conflicting"
    assert r.verdict_label == "VERIFIED - RECEIPTS DISAGREE"
    assert r.receipt_counts("checkout") and r.receipt_counts("payment")
    sdk = builder()
    _sdk_error(sdk, "checkout")
    ref = _run(sdk)
    assert ref.outcome == "conflicting"
    assert _headline(r) == _headline(ref)
    assert NO_RECEIPT not in r.finding and "Nothing more is needed" not in " ".join(r.next_steps)
    assert r.next_steps == ref.next_steps


def test_f1_both_prose_errors_are_declined() -> None:
    b = builder()
    b.payment_receipt = _prose("error", PAY_ISS, error="x")
    b.checkout_receipt = _prose("error", MERCHANT_ISS, error="x")
    r = _run(b)
    assert r.outcome == "declined" and r.verdict_label == "VERIFIED - PAYMENT DECLINED"
    sdk = builder()
    _sdk_error(sdk, "payment")
    _sdk_error(sdk, "checkout")
    ref = _run(sdk)
    assert ref.outcome == "declined"
    assert _headline(r) == _headline(ref)
    # the only warning left to review is the prose form; the decline is the headline
    assert r.finding.endswith("with 1 warning to review: a receipt uses an older form.")


def test_f1_prose_payment_error_next_to_sdk_checkout_success_matches_sdk_form() -> None:
    # the reviewer's p3_prose case: same outcome and wording as the SDK-form K7 shape
    b = builder()
    b.payment_receipt = _prose("error", PAY_ISS, error="x")
    r = _run(b)
    sdk = builder()
    _sdk_error(sdk, "payment")
    ref = _run(sdk)
    assert r.outcome == ref.outcome == "conflicting"
    assert _headline(r) == _headline(ref)
    detail = r.check("PR05").detail
    assert "reports an error: 'x' (no description given)" in detail
    assert "'null'" not in detail


def test_f1_prose_success_counts_like_sdk_success() -> None:
    b = builder()
    b.payment_receipt = _prose("success", PAY_ISS)
    r = _run(b)
    assert r.check("PR03").reason == "prose_receipt_form"
    assert r.check("PR06").status == "SKIP"
    assert r.outcome == "success"
    assert r.finding.startswith("The agent paid USD 199.00")


def test_f1_prose_receipt_with_failing_gate_still_does_not_count() -> None:
    b = builder()
    b.payment_receipt = _prose("error", PAY_ISS, error="x")
    b.payment_receipt_signer = ec.generate_private_key(ec.SECP256R1())
    r = _run(b)
    assert r.check("PR02").status == "FAIL"
    assert not r.receipt_counts("payment") and r.outcome == "unknown"


def _all_fixture_reports() -> list[tuple[str, Report]]:
    out = []
    for p in sorted(FX.rglob("*.json")):
        text = p.read_text("utf-8-sig")
        if '"bundle_version"' not in text:
            continue
        try:
            bundle = parse_bundle_text(text)
        except InputError:
            continue
        tk = p.parent / "trusted_keys.json"
        keys = json.loads(tk.read_text("utf-8")) if tk.exists() else None
        out.append((str(p), verify(bundle, trusted_keys=keys)))
    return out


def test_f1_never_says_no_receipt_when_one_counts() -> None:
    reports = _all_fixture_reports()
    for prose_kind in ("payment", "checkout"):
        for result in ("success", "error"):
            b = builder()
            iss = PAY_ISS if prose_kind == "payment" else MERCHANT_ISS
            extra = {"error": "x"} if result == "error" else {}
            setattr(b, f"{prose_kind}_receipt", _prose(result, iss, **extra))
            reports.append((f"prose {prose_kind} {result}", _run(b)))
    for name, r in reports:
        if r.receipt_counts("payment") or r.receipt_counts("checkout"):
            assert NO_RECEIPT not in r.finding, name
            assert "no receipt in this bundle can be relied on" not in r.meaning, name


# --------------------------------------------------------------------------- F2


def test_f2_gate_is_signature_fields_reference_time() -> None:
    assert RECEIPT_GATE == ("02", "03", "04", "06")
    doc = Report.outcome.__doc__ or ""
    assert "signature, required fields, reference and time checks" in doc
    assert "PR07" in doc and "do not decide" in doc


@pytest.mark.parametrize("both", [True, False])
def test_f2_issuer_warning_is_named_in_declined_and_conflicting(both: bool) -> None:
    b = builder()
    _sdk_error(b, "payment")
    if both:
        _sdk_error(b, "checkout")
    b.payment_receipt["iss"] = "evil.example"
    r = _run(b)
    assert r.check("PR07").reason == "issuer_mismatch"
    assert r.receipt_counts("payment")  # PR07 is a warning only, not part of the gate
    assert r.outcome == ("declined" if both else "conflicting")
    assert "with 1 warning to review: a receipt was issued by an unexpected party." in r.finding
    assert "Warning: The Payment Receipt was issued by an unexpected party." in r.meaning


# --------------------------------------------------------------------------- F3


def test_f3_write_error_reason_names_the_real_cause(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-folder" / "r.txt"
    with pytest.raises(InputError, match="its folder does not exist"):
        write_text(str(missing), "x")
    # the folder exists: never say it does not
    reason, _hint = _write_error_reason(str(tmp_path / "r.txt"), FileNotFoundError(2, "x"))
    assert "folder does not exist" not in reason and "too long" in reason


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH is a Windows limit")
def test_f3_long_report_name_is_written(tmp_path: Path) -> None:
    src = tmp_path / "in"
    src.mkdir()
    data = (ROOT / "examples" / "demo-valid.bundle.json").read_bytes()
    for name in ("a.json", "m" + "x" * 200 + ".json", "z.json"):
        Path("\\\\?\\" + str(src / name)).write_bytes(data)
    out = tmp_path / ("o" * 60)
    code, stdout, _ = _cli(
        "verify", str(src), "--out-dir", str(out), "--summary-csv", str(tmp_path / "s.csv")
    )
    assert code == 0, stdout
    assert len(os.listdir("\\\\?\\" + str(out))) == 3
    assert (tmp_path / "s.csv").read_text("utf-8").count("VERIFIED") == 3


def test_f3_one_unwritable_report_does_not_stop_the_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "in"
    src.mkdir()
    data = (ROOT / "examples" / "demo-valid.bundle.json").read_bytes()
    for name in ("a.json", "m.json", "z.json"):
        (src / name).write_bytes(data)
    real = batch.write_text

    def flaky(path: str, text: str, **kw: Any) -> None:
        if Path(path).name.startswith("m."):
            raise InputError(f"cannot write {path}: the path is too long; use a shorter path")
        real(path, text, **kw)

    monkeypatch.setattr(batch, "write_text", flaky)
    csv = tmp_path / "s.csv"
    code, stdout, stderr = _cli(
        "verify", str(src), "--out-dir", str(tmp_path / "r"), "--summary-csv", str(csv)
    )
    assert code == 2
    assert sorted(os.listdir(tmp_path / "r")) == ["a.report.txt", "z.report.txt"]
    rows = csv.read_text("utf-8").splitlines()
    assert len(rows) == 4 and all(",VERIFIED," in r for r in rows[1:])
    m_row = next(r for r in rows if "m.json" in r)
    assert "report not written" in m_row
    assert "report not written" in stdout and "1 report(s) could not be written" in stdout
    assert "wrote 2 report(s)" in stderr


# --------------------------------------------------------------------------- F4


@pytest.mark.parametrize("fmt", ["text", "md", "html"])
def test_f4_disagreeing_receipts_conclusion(fmt: str) -> None:
    code, out, _ = _cli("verify", str(K7), "--trusted-keys", str(CARD_KEYS), "--format", fmt)
    assert code == 0
    assert "Nothing more is needed" not in out
    assert "no issuer named" not in out
    assert "(issuer not named)" in out
    assert "warning to review" not in out  # the decline is the headline, nothing else warns
    r = verify(
        parse_bundle_text(K7.read_text("utf-8")),
        trusted_keys=json.loads(CARD_KEYS.read_text("utf-8")),
    )
    assert "on its own it shows" not in r.finding and "Warning:" not in r.meaning
    assert NOTHING_MORE not in r.next_steps


def test_f4_declined_lists_other_warnings_but_not_the_decline() -> None:
    b = builder()
    _sdk_error(b, "payment")
    _sdk_error(b, "checkout")
    r = _run(b)
    assert r.outcome == "declined"
    assert "warning to review" not in r.finding
    assert NOTHING_MORE not in r.next_steps
    b2 = builder()
    _sdk_error(b2, "payment")
    _sdk_error(b2, "checkout")
    b2.payment_receipt["iss"] = "evil.example"
    r2 = _run(b2)
    assert "1 warning to review: a receipt was issued by an unexpected party" in r2.finding
    assert "says the payment was declined; on its own" not in r2.finding


# --------------------------------------------------------------------------- F5


def test_f5_key_tamper_does_not_attribute_the_payment_to_the_agent() -> None:
    r = verify(build_demo_bundle("key", seed=3, now=NOW))
    assert r.check("PM08").status == "FAIL"
    assert "the agent paid" not in r.finding.lower()
    assert "the agent approved" not in r.finding.lower()
    assert (
        "The payment concerned: USD 199.00 to Demo Merchant for checkout 'demo-checkout-0001', "
        "approved with a key that is not the agent key the user authorised." in r.finding
    )


def test_f5_checkout_side_is_not_attributed_to_the_agent() -> None:
    b = builder()
    b.closed_checkout_signer = ec.generate_private_key(ec.SECP256R1())
    r = _run(b)
    assert r.check("CM08").status == "FAIL"
    assert (
        "for checkout 'demo-checkout-0001' (that checkout was approved with a key that is not "
        "the agent key the user authorised)" in r.finding
    )


# --------------------------------------------------------------------------- F6


def test_f6_receipt_outcome_titles_are_neutral() -> None:
    assert REGISTRY["PR05"].title == "Payment receipt outcome"
    assert REGISTRY["CR05"].title == "Checkout receipt outcome"
    checks_md = (ROOT / "docs" / "checks.md").read_text("utf-8")
    assert "outcome is Success" not in checks_md
    code, out, _ = _cli("explain", "PR05")
    assert code == 0 and "Payment receipt outcome" in out and "outcome is Success" not in out


def test_f6_receipt_for_another_mandate_passes_say_so() -> None:
    r = verify(build_demo_bundle("receipt", seed=3, now=NOW))
    assert r.check("PR04").status == "FAIL"
    for cid in ("PR05", "PR06"):
        c = r.check(cid)
        assert c.status == "PASS"
        assert "PR04 found that it refers to another mandate" in c.detail
        assert "says nothing about this payment" in c.detail
    assert "PR04" not in verify(build_demo_bundle(None, seed=3, now=NOW)).check("PR05").detail


# --------------------------------------------------------------------------- F7

_REPR = re.compile(r"'null'|null\)|'None'|\bNone\b")


def _reprs(text: str) -> list[str]:
    # "None." on its own line is the report's word for an empty section
    lines = [ln for ln in text.splitlines() if ln.strip() not in ("None.", "- None.")]
    return [ln for ln in lines if _REPR.search(ln)]


def test_f7_no_python_or_json_reprs_in_text_output(tmp_path: Path) -> None:
    texts: dict[str, str] = {}
    for rel in (
        "third-party/cuichangquan/O2O5.AGENT_BEFORE_S01.bundle.json",
        "third-party/goodmeta/receipts.payment_receipt_error_without_error_code.bundle.json",
    ):
        _code, out, err = _cli("verify", str(FX / rel))
        texts[rel] = out + err
    b = builder()
    b.payment_receipt = _prose("error", PAY_ISS, error="x")
    texts["prose error without description"] = _run(b).to_text()
    b = builder()
    b.payment_receipt.update(status="Error", error=None, error_description=None)
    texts["SDK error without code"] = _run(b).to_text()
    b = builder()
    b.payment_receipt.pop("iss")
    texts["receipt without iss"] = _run(b).to_text()
    demo = tmp_path / "demo.json"
    demo.write_text(json.dumps(build_demo_bundle(None, seed=3, now=NOW)), "utf-8")
    for name, jwk in (
        ("ec", {"kty": "EC"}),
        ("kty-null", {"kty": None}),
        ("crv-num", {"kty": "EC", "crv": 5}),
    ):
        f = tmp_path / f"{name}.json"
        f.write_text(json.dumps(jwk), "utf-8")
        for flag in ("--expect-agent-key", "--issuer-key"):
            code, out, err = _cli("verify", str(demo), flag, str(f))
            assert code == 2
            texts[f"{flag} {name}"] = out + err
    with pytest.raises(InputError) as exc:
        verify(build_demo_bundle(None, seed=3, now=NOW), expected={"agent_key": {"kty": "EC"}})
    texts["API expected.agent_key"] = str(exc.value)
    with pytest.raises(InputError) as exc:
        parse_key_text(json.dumps({"kty": "EC"}), "k.json")
    texts["key loader"] = str(exc.value)
    bad = {k: v for k, v in texts.items() if _reprs(v)}
    assert not bad, {k: _reprs(v)[:3] for k, v in bad.items()}
    assert "missing" in texts["API expected.agent_key"]
    assert "no EC curve (no crv member)" in texts["key loader"]


# --------------------------------------------------------------------------- F8


def _item(path: str, rel: str | None = None) -> batch.Item:
    return batch.Item(path, path, rel or Path(path).name, rel is not None)


def test_f8_report_names_use_the_parent_folder_when_file_names_collide() -> None:
    items = [
        _item(str(SDK / "tamper" / "K1_amount_over_cap" / "bundle.json")),
        _item(str(SDK / "tamper" / "K2_payee_changed" / "bundle.json")),
        _item(str(SDK / "card" / "bundle.json")),
        _item(str(SDK / "card" / "bundle.json")),  # the same file twice: last resort -2
        _item(str(ROOT / "examples" / "demo-valid.bundle.json")),
        _item(str(SDK / "a" / "x" / "bundle.json"), "x/bundle.json"),
        _item(str(SDK / "b" / "x" / "bundle.json"), "x/bundle.json"),
    ]
    assert batch.report_names(items, "txt") == [
        "K1_amount_over_cap__bundle.report.txt",
        "K2_payee_changed__bundle.report.txt",
        "card__bundle.report.txt",
        "card__bundle-2.report.txt",
        "demo-valid.bundle.report.txt",
        "a__x__bundle.report.txt",
        "b__x__bundle.report.txt",
    ]


def test_f8_text_summary_names_each_report(tmp_path: Path) -> None:
    code, out, _ = _cli(
        "verify",
        str(SDK / "card" / "bundle.json"),
        str(K7),
        "--trusted-keys",
        str(CARD_KEYS),
        "--out-dir",
        str(tmp_path / "r"),
    )
    assert code == 0
    assert "FILE  (REPORT)  [CHECKS]" in out
    assert "(card__bundle.report.txt)" in out and "(K7_error_receipt__bundle.report.txt)" in out
    _code, plain, _ = _cli("verify", str(SDK / "card" / "bundle.json"), str(K7))
    assert "(REPORT)" not in plain


# --------------------------------------------------------------------------- F9


def test_f9_every_readable_fixture_bundle_validates_against_the_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "src" / "ap2_evidence" / "schemas" / "bundle.schema.json").read_text("utf-8")
    )
    validator = jsonschema.Draft202012Validator(schema)
    paths = sorted(FX.rglob("*.json")) + sorted((ROOT / "examples").glob("*.json"))
    checked = 0
    for p in paths:
        text = p.read_text("utf-8-sig")
        if '"bundle_version"' not in text:
            continue
        code, _out, _err = _cli("verify", str(p))
        if code == 2:
            continue
        checked += 1
        errors = [e.message[:120] for e in validator.iter_errors(json.loads(text))]
        assert not errors, (str(p), errors)
    assert checked >= 100
    probe = SDK / "probes" / "P3_unsigned_receipt_json_string" / "bundle.json"
    assert isinstance(json.loads(probe.read_text("utf-8"))["payment_receipt"], str)


# --------------------------------------------------------------------------- F10


def test_f10_bundle_given_as_trusted_keys_is_named_as_a_bundle() -> None:
    with pytest.raises(InputError) as exc:
        load_trusted_keys((ROOT / "examples" / "demo-valid.bundle.json").read_bytes())
    msg = str(exc.value)
    assert "evidence bundle" in msg and "not a keys file" in msg
    assert "plain JWKS" not in msg and '"mandate_issuer"' in msg


# --------------------------------------------------------------------------- F11


def test_f11_pm31_skip_hint_uses_plain_names() -> None:
    from ap2_evidence.demo import SdElem

    b = builder()
    b.open_checkout["constraints"][1]["allowed"].append(
        SdElem({"id": "merchant_2", "name": "Other", "website": "https://o.example"})
    )
    b.withhold["checkout"] = lambda d: (
        len(d) == 2 and isinstance(d[1], dict) and d[1].get("id") == "merchant_2"
    )
    r = _run(b)
    c = r.check("PM31")
    assert c.reason == "reference_unverifiable_withheld"
    shown = r.hint_overrides["PM31"]
    assert "segment" not in shown and "checkout instructions" in shown
    assert "payment authorisation" in shown
    assert "segment 1 of payment_mandate" in c.detail  # the locator stays technical
    text = r.to_text()
    section = text[text.index("3. Not verified") : text.index("4. Evidence chain")]
    you_can = section[section.index("What you can do:") :]
    assert "segment 1" not in you_can


# --------------------------------------------------------------------------- F12


def test_f12_output_formats_sample_is_real_demo_output() -> None:
    doc = (ROOT / "docs" / "output-formats.md").read_text("utf-8")
    m = re.search(r"`ap2-evidence demo`, (\d+) checks\) are:\n\n```text\n(.*?)```", doc, re.S)
    assert m
    _code, out, _ = _cli("demo")
    assert out.startswith(m.group(2))
    counts = [int(n) for n in re.findall(r"\d+", m.group(2).splitlines()[-1])]
    assert sum(counts) == int(m.group(1)) == len(REGISTRY)
