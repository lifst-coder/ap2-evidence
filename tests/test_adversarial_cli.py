"""Regression tests for the CLI-layer findings of the adversarial review (C1-C6)."""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ap2_evidence import batch
from ap2_evidence.bundle import InputError
from ap2_evidence.jose import public_jwk
from ap2_evidence.keys import parse_key_text
from helpers import ROOT
from helpers import run_cli as _run_cli

FX = ROOT / "tests" / "fixtures" / "upstream-sdk"
CARD = FX / "card" / "bundle.json"
CARD_KEYS = str(FX / "card" / "trusted_keys.json")


def run_cli(*args: str) -> Any:
    return _run_cli(*args, env={"PYTHONIOENCODING": "utf-8"})


def _pub_pem(k: ec.EllipticCurvePrivateKey) -> str:
    return (
        k.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _cert_pem(k: ec.EllipticCurvePrivateKey) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    t0 = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(k.public_key())
        .serial_number(7)
        .not_valid_before(t0)
        .not_valid_after(t0 + datetime.timedelta(days=1))
        .sign(k, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _priv_pem(k: ec.EllipticCurvePrivateKey) -> str:
    return k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _one_line_error(p: Any) -> str:
    err = p.stderr.decode("utf-8", "replace")
    assert p.returncode == 2, (p.stdout, err)
    assert "Traceback" not in err
    lines = err.strip().splitlines()
    assert len(lines) == 1, err
    return lines[0]


# C1: every PEM block is imported, not the first one repeatedly
@pytest.mark.parametrize("n", [2, 3])
def test_c1_pem_with_several_keys(n: int) -> None:
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(n)]
    got = parse_key_text("\n".join(_pub_pem(k) for k in keys), "f")
    assert [g.jwk["x"] for g in got] == [public_jwk(k)["x"] for k in keys]


def test_c1_mixed_certificate_and_public_key() -> None:
    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    got = parse_key_text(_cert_pem(a) + _pub_pem(b), "f")
    assert [g.jwk["x"] for g in got] == [public_jwk(a)["x"], public_jwk(b)["x"]]
    assert got[0].notes and not got[1].notes


@pytest.mark.parametrize("pos", [0, 1, 2])
def test_c1_private_block_anywhere_is_refused(pos: int) -> None:
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    blocks = [_pub_pem(k) for k in keys]
    blocks[pos] = _priv_pem(keys[pos])
    with pytest.raises(InputError, match="PRIVATE key"):
        parse_key_text("".join(blocks), "f")


# C2: outputs that name the same file (case-insensitively) or an input are refused
def test_c2_same_file_outputs_refused(tmp_path: Path) -> None:
    out = tmp_path / "c.json"
    p = run_cli(
        "pack",
        "--payment-mandate",
        str(FX / "loose" / "payment_mandate.txt"),
        "--issuer-key",
        str(FX / "loose" / "issuer.pem"),
        "--out",
        str(out),
        "--keys-out",
        str(tmp_path / ("C.JSON" if os.name == "nt" else "c.json")),
        "--force",
    )
    assert "same file" in _one_line_error(p)
    assert not out.exists()
    src = tmp_path / "chk.txt"
    shutil.copy(FX / "loose" / "checkout_mandate.txt", src)
    p = run_cli("pack", "--checkout-mandate", str(src), "--out", str(src), "--force")
    assert "is also the input" in _one_line_error(p)
    assert src.read_bytes() == (FX / "loose" / "checkout_mandate.txt").read_bytes()
    b = tmp_path / "b.json"
    shutil.copy(CARD, b)
    assert "is also the input" in _one_line_error(run_cli("verify", str(b), "--out", str(b)))
    assert b.read_bytes() == CARD.read_bytes()
    s = tmp_path / "s.txt"
    p = run_cli("verify", str(b), str(b), "--out", str(s), "--summary-csv", str(s))
    assert "same file" in _one_line_error(p)


# C3: existing reports in --out-dir are not replaced without --force
def test_c3_out_dir_refuses_existing_reports(tmp_path: Path) -> None:
    out = tmp_path / "reports"
    args = ["verify", str(CARD), str(FX / "x402" / "bundle.json"), "--out-dir", str(out)]
    assert run_cli(*args).returncode == 3
    first = {f.name: f.read_bytes() for f in out.iterdir()}
    # same file name in two folders: the parent folder tells the reports apart (F8)
    assert set(first) == {"card__bundle.report.txt", "x402__bundle.report.txt"}
    (out / "card__bundle.report.txt").write_text("mine", encoding="utf-8")
    line = _one_line_error(run_cli(*args))
    assert "card__bundle.report.txt" in line and "--force" in line
    assert (out / "card__bundle.report.txt").read_text(encoding="utf-8") == "mine"
    assert run_cli(*args, "--force").returncode == 3
    assert {f.name for f in out.iterdir()} == set(first)
    assert (out / "card__bundle.report.txt").read_text(encoding="utf-8") != "mine"


# C4: a bundle behind a path longer than MAX_PATH is still read; one bad file never aborts
def test_c4_long_path_and_unreadable_file_in_batch(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    shutil.copy(CARD, root / "a.json")
    (root / "b.json").write_text("{broken", encoding="utf-8")
    deep = os.path.abspath(root)
    while len(deep) < 300:
        deep = os.path.join(deep, "d" * 60)
    long_dir = "\\\\?\\" + deep if os.name == "nt" else deep
    try:
        os.makedirs(long_dir)
        shutil.copy(CARD, os.path.join(long_dir, "long.json"))
    except OSError:
        pytest.skip("cannot create long paths here")
    p = run_cli("verify", str(root), "--recursive", "--trusted-keys", CARD_KEYS, "--format", "json")
    s = json.loads(p.stdout)
    rows = {Path(r["file"]).name: r["verdict"] for r in s["bundles"]}
    assert rows == {"a.json": "VERIFIED", "b.json": "ERROR", "long.json": "VERIFIED"}
    assert p.returncode == 2  # an unreadable bundle makes the batch exit 2, as before


# C5: the batch summary handles every outcome value
def test_c5_outcomes_in_summary() -> None:
    rows = [
        batch.Row("a.json", "VERIFIED", "pinned", "success", {"fail": 0, "skip": 1}),
        batch.Row("b.json", "VERIFIED", "pinned", "declined", {"fail": 0, "skip": 1}),
        batch.Row("c.json", "VERIFIED", "pinned", "conflicting", {"fail": 0, "skip": 1}),
        batch.Row("d.json", "FAILED", "pinned", "conflicting", {"fail": 1, "skip": 1}),
        batch.Row("e.json", "INCOMPLETE", "none", "unknown", {"fail": 0, "skip": 9}),
    ]
    b = batch.Batch(rows, [])
    text = batch.render_text(b)
    lines = text.splitlines()
    assert lines[3].split()[:2] == ["VERIFIED", "conflicting"]
    assert lines[4].split()[:2] == ["FAILED", "-"]
    assert "payment declined (per the payment receipt)" in text
    conflict = next(ln for ln in lines if "outcome conflicting" in ln)
    assert "receipts disagree" in conflict and "did not go through" not in conflict
    assert text.count("did not go through") == 1  # only the declined sentence
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "src/ap2_evidence/schemas/batch-summary.schema.json").read_text())
    jsonschema.validate(batch.to_dict(b), schema)
    assert "conflicting" in batch.render_csv(b)


# C6: folder links and junctions are not followed; the tool's own output is not re-read
def _link_dir(target: Path, link: Path) -> bool:
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
        )
        return r.returncode == 0
    return False


def test_c6_links_not_followed_and_own_output_ignored(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copy(CARD, outside / "elsewhere.json")
    root = tmp_path / "in"
    root.mkdir()
    shutil.copy(CARD, root / "a.json")
    if not _link_dir(outside, root / "link"):
        pytest.skip("cannot create directory links here")
    items = batch.collect([str(root)], True)
    assert [Path(i.path).name for i in items] == ["a.json"]
    out = root / "reports"
    for fmt in ("json", "json"):  # the second run must not pick up the first run's reports
        p = run_cli(
            "verify",
            str(root),
            "--recursive",
            "--out-dir",
            str(out),
            "--format",
            fmt,
            "--out",
            str(root / "summary.json"),
            "--force",
        )
        assert p.returncode == 3, p.stderr
    s = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    assert [Path(r["file"]).name for r in s["bundles"]] == ["a.json"]
