"""Evidence minted by the official AP2 SDK and sample code (upstream e1ea56d, v0.2.0).

See tests/fixtures/upstream-sdk/README.md for how the fixtures were produced.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path

import pytest

from ap2_evidence.bundle import load_trusted_keys
from ap2_evidence.verify import verify_bundle
from helpers import ROOT, run_cli

FX = ROOT / "tests" / "fixtures" / "upstream-sdk"
SAMPLE_DB = FX / "samples_hnp_card" / "temp-db"

# case folder -> (verdict, FAIL check IDs). Verdicts with the case's own pinned keys.
EXPECTED: dict[str, tuple[str, set[str]]] = {
    "samples_hnp_card": ("VERIFIED", set()),
    "card": ("VERIFIED", set()),
    "x402": ("VERIFIED", set()),
    "v_issuerhash": ("VERIFIED", set()),
    # budget/recurrence constraints: PM39 needs history (test_audit_findings runs them with it)
    "v_extras_usd": ("INCOMPLETE", set()),
    "v_extras_jpy": ("INCOMPLETE", set()),
    "v_extras_kwd": ("INCOMPLETE", set()),
    "v_hp": ("VERIFIED", set()),
    # the open mandates were presented with constraints redacted (SDK claims_to_disclose)
    # PM31 is a required SKIP there: the reference hashes the token as issued (audit item 6)
    "v_redact": ("FAILED", {"CM34", "CM35"}),
    "tamper/K1_amount_over_cap": ("FAILED", {"PM32", "XC01"}),
    "tamper/K1b_amount_within_cap_not_total": ("FAILED", {"XC01"}),
    "tamper/K2_payee_changed": ("FAILED", {"PM33", "XC02"}),
    "tamper/K3_transaction_id_changed": ("FAILED", {"PM30"}),
    "tamper/K3b_checkout_hash_wrong": ("FAILED", {"CM31", "PM30"}),
    "tamper/K3c_checkout_replaced": ("FAILED", {"PM30", "XC01"}),
    "tamper/K4_receipt_reference_other_mandate": ("FAILED", {"CR04"}),
    "tamper/K4b_payment_receipt_ref_random": ("FAILED", {"PR04"}),
    "tamper/K5_trusted_merchant_key_swapped": ("FAILED", {"CM32", "CR02"}),
    "tamper/K5b_trusted_issuer_key_swapped": ("FAILED", {"CM03", "PM03"}),
    "tamper/K5c_closed_payment_signed_by_rogue_agent": ("FAILED", {"PM08"}),
    "tamper/K5d_open_payment_reissued_by_fake_issuer": ("FAILED", {"PM03"}),
    "tamper/K6_payee_disclosure_withheld_resigned": ("FAILED", {"PM33"}),
    # an authentic Error receipt is intact evidence of a declined payment (PR05 WARN declined)
    "tamper/K7_error_receipt": ("VERIFIED", set()),
    "tamper/K8_wrong_expected_nonce": ("FAILED", {"PM15"}),
    "tamper/N1_amount_disclosure_edit": ("FAILED", {"PM10"}),
    "tamper/N2_drop_payee_disclosure": ("FAILED", {"PM09", "PM33"}),
    "tamper/N3_drop_checkout_jwt_disclosure": ("FAILED", {"CM13", "CM30"}),
    "tamper/N4_receipt_reference_edit": ("FAILED", {"CR02", "CR04"}),
    "tamper/N5_receipts_swapped": ("FAILED", {"CR02", "CR03", "CR04", "PR02", "PR03", "PR04"}),
    "tamper/N6_payment_from_other_txn": ("FAILED", {"PM03", "PM15", "PM30", "PM31", "PR02"}),
    # unsigned receipt shapes emitted by other upstream sample flows, put into the bundle
    # (PR01 is a required SKIP unsigned_receipt: an unsigned receipt proves nothing)
    "probes/P1_x402_psp_receipt_object": ("INCOMPLETE", set()),
    "probes/P2_unsigned_receipt_dict": ("INCOMPLETE", set()),
    "probes/P3_unsigned_receipt_json_string": ("INCOMPLETE", set()),
}


def _args(case: Path) -> list[str]:
    f = case / "args.txt"
    return f.read_text(encoding="utf-8").split() if f.is_file() else []


def _expected_from_args(args: list[str]) -> dict[str, dict[str, str]] | None:
    out: dict[str, dict[str, str]] = {}
    it = iter(args)
    for flag in it:
        m = re.fullmatch(r"--expect-(checkout|payment)-(aud|nonce)", flag)
        assert m, f"unexpected args.txt flag {flag}"
        out.setdefault(m.group(1), {})[m.group(2)] = next(it)
    return out or None


def test_every_fixture_has_an_expectation() -> None:
    found = {str(p.parent.relative_to(FX)).replace("\\", "/") for p in FX.rglob("bundle.json")}
    assert found == set(EXPECTED)
    assert sum(1 for k in EXPECTED if k.startswith("tamper/")) >= 12


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_upstream_verdict(case: str) -> None:
    d = FX / case
    bundle = json.loads((d / "bundle.json").read_text(encoding="utf-8"))
    keys = load_trusted_keys((d / "trusted_keys.json").read_text(encoding="utf-8"))
    report = verify_bundle(bundle, trusted_keys=keys, expected=_expected_from_args(_args(d)))
    verdict, fails = EXPECTED[case]
    assert report.verdict == verdict
    assert {c.id for c in report.checks if c.status == "FAIL"} == fails
    assert report.key_trust == "pinned"


@pytest.mark.parametrize(
    "case", ["samples_hnp_card", "tamper/K8_wrong_expected_nonce", "tamper/K1_amount_over_cap"]
)
def test_upstream_cli(case: str) -> None:
    d = FX / case
    p = run_cli(
        "verify",
        str(d / "bundle.json"),
        "--trusted-keys",
        str(d / "trusted_keys.json"),
        *_args(d),
        "--format",
        "json",
    )
    verdict, fails = EXPECTED[case]
    assert p.returncode == {"VERIFIED": 0, "FAILED": 1, "INCOMPLETE": 3}[verdict]
    r = json.loads(p.stdout)
    assert r["verdict"] == verdict
    assert {c["id"] for c in r["checks"] if c["status"] == "FAIL"} == fails


# --------------------------------------------------------------------------- sample-db import


def _pack_sample(tmp: Path, *extra: str) -> tuple[Path, Path]:
    out, keys = tmp / "sample.bundle.json", tmp / "keys.json"
    p = run_cli(
        "pack",
        "--from-ap2-sample-db",
        str(SAMPLE_DB),
        *extra,
        "--keys-out",
        str(keys),
        "--out",
        str(out),
    )
    assert p.returncode == 0, p.stderr
    return out, keys


def _verify_json(bundle: Path, keys: Path) -> tuple[int, dict[str, object]]:
    p = run_cli("verify", str(bundle), "--trusted-keys", str(keys), "--format", "json")
    return p.returncode, json.loads(p.stdout)


def test_import_sample_db_without_receipts_is_incomplete(tmp_path: Path) -> None:
    out, keys = _pack_sample(tmp_path)
    bundle = json.loads(out.read_text(encoding="utf-8"))
    hand = json.loads((FX / "samples_hnp_card" / "bundle.json").read_text(encoding="utf-8"))
    # chains byte for byte as the sample wrote them, and identical to the hand-assembled bundle
    for kind, f in (("checkout", "chk_*.sdjwt"), ("payment", "pay_*.sdjwt")):
        [src] = SAMPLE_DB.glob(f)
        assert bundle[f"{kind}_mandate"] == src.read_text(encoding="ascii").strip()
        assert bundle[f"{kind}_mandate"] == hand[f"{kind}_mandate"]
    assert "keys" not in bundle  # keys are not copied into the bundle by default
    assert bundle["expected"]["payment"]["nonce"] == hand["expected"]["payment"]["nonce"]
    assert "nonce" not in bundle["expected"]["checkout"]  # not persisted by the samples
    assert json.loads(keys.read_text(encoding="utf-8")) == json.loads(
        (FX / "samples_hnp_card" / "trusted_keys.json").read_text(encoding="utf-8")
    )
    code, r = _verify_json(out, keys)
    assert (code, r["verdict"]) == (3, "INCOMPLETE")
    hand_minus = {k: v for k, v in hand.items() if not k.endswith("_receipt")}
    ref = verify_bundle(
        hand_minus,
        trusted_keys=load_trusted_keys(
            (FX / "samples_hnp_card" / "trusted_keys.json").read_text(encoding="utf-8")
        ),
    )
    assert ref.verdict == "INCOMPLETE"


def test_import_sample_db_with_receipts_is_verified(tmp_path: Path) -> None:
    out, keys = _pack_sample(
        tmp_path,
        "--checkout-receipt",
        str(FX / "samples_hnp_card" / "checkout_receipt.jwt"),
        "--payment-receipt",
        str(FX / "samples_hnp_card" / "payment_receipt.jwt"),
    )
    code, r = _verify_json(out, keys)
    assert (code, r["verdict"]) == (0, "VERIFIED")
    checks = {c["id"]: c for c in r["checks"]}  # type: ignore[attr-defined]
    assert {checks[i]["key_provenance"] for i in ("CM03", "PM03", "CR02", "PR02")} == {"trusted"}
    hand = run_cli(
        "verify",
        str(FX / "samples_hnp_card" / "bundle.json"),
        "--trusted-keys",
        str(FX / "samples_hnp_card" / "trusted_keys.json"),
    )
    assert hand.returncode == code


def test_import_never_opens_private_key_files(tmp_path: Path) -> None:
    db = tmp_path / "temp-db"
    shutil.copytree(SAMPLE_DB, db)
    # a .pem the importer must not open: unreadable garbage that would make any reader fail
    (db / "merchant_signing_key.pem").write_bytes(b"\xff\x00" * 10)
    import builtins
    import io

    from ap2_evidence import importer

    real_open = io.open

    def guarded(file: object, *a: object, **k: object) -> object:
        if str(file).endswith(".pem"):
            raise AssertionError(f"importer opened {file}")
        return real_open(file, *a, **k)  # type: ignore[call-overload]

    mp = pytest.MonkeyPatch()
    mp.setattr(builtins, "open", guarded)
    mp.setattr(io, "open", guarded)
    try:
        imp = importer.import_sample_db(str(db), None, None)
    finally:
        mp.undo()
    assert imp.checkout is not None and imp.payment is not None
    assert {r: len(v) for r, v in imp.keys.keys.items()} == {
        "mandate_issuer": 1,
        "merchant": 1,
        "payment_processor": 1,
    }


def _ambiguous_db(tmp: Path) -> Path:
    db = tmp / "temp-db"
    shutil.copytree(SAMPLE_DB, db)
    for f in list(db.glob("chk_*.sdjwt")) + list(db.glob("pay_*.sdjwt")):
        shutil.copy(f, db / f.name.replace("_", "_2nd", 1))
    return db


def test_import_ambiguous_refuses_to_guess(tmp_path: Path) -> None:
    db = _ambiguous_db(tmp_path)
    p = run_cli(
        "pack", "--from-ap2-sample-db", str(db), "--embed-keys", "--out", str(tmp_path / "b")
    )
    assert p.returncode == 2
    err = p.stderr.decode("utf-8", "replace")
    assert len(err.strip().splitlines()) == 1
    assert "refusing to guess" in err and "--checkout chk_" in err and "--payment pay_" in err
    assert not (tmp_path / "b").exists()
    [chk] = db.glob("chk_2nd*.sdjwt")
    [pay] = db.glob("pay_2nd*.sdjwt")
    p = run_cli(
        "pack",
        "--from-ap2-sample-db",
        str(db),
        "--checkout",
        chk.stem,
        "--payment",
        pay.name,
        "--keys-out",
        str(tmp_path / "k.json"),
        "--out",
        str(tmp_path / "b.json"),
    )
    assert p.returncode == 0, p.stderr
    p = run_cli("pack", "--from-ap2-sample-db", str(db), "--checkout", "chk_nope", "--out", "x")
    assert p.returncode == 2 and b"no such chain" in p.stderr


def test_import_unlinked_pair_refuses(tmp_path: Path) -> None:
    db = tmp_path / "temp-db"
    shutil.copytree(SAMPLE_DB, db)
    [pay] = db.glob("pay_*.sdjwt")
    other = json.loads((FX / "card" / "bundle.json").read_text(encoding="utf-8"))
    pay.write_text(other["payment_mandate"], encoding="ascii")
    p = run_cli(
        "pack", "--from-ap2-sample-db", str(db), "--embed-keys", "--out", str(tmp_path / "b")
    )
    assert p.returncode == 2
    assert b"no hash-linked pair" in p.stderr


def test_import_not_a_sample_dir(tmp_path: Path) -> None:
    p = run_cli("pack", "--from-ap2-sample-db", str(tmp_path), "--out", str(tmp_path / "b.json"))
    assert p.returncode == 2
    assert b"TEMP_DB_DIR" in p.stderr
    p = run_cli("pack", "--from-ap2-sample-db", str(tmp_path / "nope"), "--out", "b.json")
    assert p.returncode == 2 and b"does not exist" in p.stderr


def test_import_unsigned_receipt_is_reported(tmp_path: Path) -> None:
    hp = json.loads((FX / "probes" / "P1_x402_psp_receipt_object" / "bundle.json").read_text())
    rec = tmp_path / "psp_receipt.json"
    rec.write_text(json.dumps(hp["payment_receipt"]), encoding="utf-8")
    out, keys = tmp_path / "b.json", tmp_path / "k.json"
    p = run_cli(
        "pack",
        "--from-ap2-sample-db",
        str(SAMPLE_DB),
        "--payment-receipt",
        str(rec),
        "--keys-out",
        str(keys),
        "--out",
        str(out),
    )
    assert p.returncode == 0, p.stderr
    text = p.stderr.decode("utf-8", "replace")  # pack's warnings go to stderr
    assert "this flow produced no signed payment receipt" in text
    stored = json.loads(out.read_text(encoding="utf-8"))["payment_receipt"]
    assert stored == hp["payment_receipt"]  # kept as the object it is
    code, r = _verify_json(out, keys)
    assert (code, r["verdict"]) == (3, "INCOMPLETE")
    pr01 = {c["id"]: c for c in r["checks"]}["PR01"]  # type: ignore[attr-defined]
    assert pr01["reason"] == "unsigned_receipt"


# ------------------------------------------------------------------- no private key material


def _b64_json(chunk: str) -> object:
    try:
        raw = base64.urlsafe_b64decode(chunk + "=" * (-len(chunk) % 4))
        return json.loads(raw)
    except ValueError:
        return None


def _has_d(v: object) -> bool:
    if isinstance(v, dict):
        return "d" in v or any(_has_d(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_d(x) for x in v)
    return False


def test_fixture_tree_holds_no_private_key_material() -> None:
    """Fails if any file under tests/fixtures/upstream-sdk holds private key material."""
    files = [p for p in FX.rglob("*") if p.is_file()]
    assert len(files) > 50
    for f in files:
        assert f.suffix.lower() not in (".pem", ".key", ".p12", ".pfx") or f.parent.name == "loose"
        assert f.name != "private_keys.json", f
        text = f.read_bytes().decode("utf-8", "replace")
        assert not re.search(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY", text, re.IGNORECASE), f
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        assert not _has_d(value), f
        # decode every base64url run (JWT parts, disclosures, JSON string values)
        for chunk in re.findall(r"[A-Za-z0-9_-]{16,}", text):
            assert not _has_d(_b64_json(chunk)), (f, chunk[:20])
    # the PEM files in loose/ are public keys
    for pem in (FX / "loose").glob("*.pem"):
        assert pem.read_text().startswith("-----BEGIN PUBLIC KEY-----")
