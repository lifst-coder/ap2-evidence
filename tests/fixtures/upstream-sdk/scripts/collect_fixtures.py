"""Copy upstream-minted evidence into tests/fixtures/upstream-sdk/ (public material only).

usage: python collect_fixtures.py INTEROP_OUT_DIR FIXTURE_DIR

INTEROP_OUT_DIR is the ``out`` folder written by run_all.ps1 / run_tamper.ps1 /
drive_samples.py / probes.py. Copied per case: bundle.json, trusted_keys.json and, for
tamper and probe cases, desc.txt and args.txt. From samples_hnp_card/temp-db every file
except the private key files is copied; files ending in ``.pem`` are skipped by name and
never opened (in the AP2 samples they hold PRIVATE JWKs). ``private_keys.json``,
``report.json`` and logs are never copied. Every copied file is checked for private key
material and the script stops if it finds any.

It also writes ``loose/``: the card case as separate token files plus PEM
(SubjectPublicKeyInfo) public keys, for the ``pack`` examples, and the receipts of
samples_hnp_card as separate files for the sample-db import example.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CASES = [
    "samples_hnp_card",
    "card",
    "x402",
    "v_issuerhash",
    "v_extras_usd",
    "v_extras_jpy",
    "v_extras_kwd",
    "v_hp",
    "v_redact",
]
CASE_FILES = ("bundle.json", "trusted_keys.json", "desc.txt", "args.txt")


def has_private_material(text: str) -> bool:
    """Crude but strict: any PEM private key, or any JSON object with a 'd' member."""
    if "PRIVATE KEY" in text.upper():
        return True

    def walk(v: object) -> bool:
        if isinstance(v, dict):
            return "d" in v or any(walk(x) for x in v.values())
        if isinstance(v, list):
            return any(walk(x) for x in v)
        return False

    try:
        return walk(json.loads(text))
    except ValueError:
        return False


def copy(src: Path, dst: Path) -> None:
    text = src.read_text(encoding="utf-8")
    if has_private_material(text):
        raise SystemExit(f"refusing to copy {src}: it holds private key material")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text.replace("\r\n", "\n"), encoding="utf-8", newline="\n")


def pem_of(jwk: dict[str, str]) -> str:
    from base64 import urlsafe_b64decode

    def b(s: str) -> int:
        return int.from_bytes(urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")

    key = ec.EllipticCurvePublicNumbers(b(jwk["x"]), b(jwk["y"]), ec.SECP256R1()).public_key()
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def main(out: Path, fx: Path) -> None:
    for name in CASES:
        for f in CASE_FILES:
            if (out / name / f).is_file():
                copy(out / name / f, fx / name / f)
    for group in ("tamper", "probes"):
        # only cases written by tamper.py / probes.py (they write desc.txt)
        for case in sorted(p for p in (out / group).iterdir() if (p / "desc.txt").is_file()):
            for f in CASE_FILES:
                if (case / f).is_file():
                    copy(case / f, fx / group / case.name / f)
    src_db, dst_db = out / "samples_hnp_card" / "temp-db", fx / "samples_hnp_card" / "temp-db"
    if dst_db.exists():
        shutil.rmtree(dst_db)
    for f in sorted(src_db.iterdir()):
        if f.is_file() and not f.name.endswith(".pem"):
            copy(f, dst_db / f.name)
    # receipts of the sample run, as the sample's callers received them
    hnp = json.loads((out / "samples_hnp_card" / "bundle.json").read_text(encoding="utf-8"))
    for member in ("checkout_receipt", "payment_receipt"):
        (fx / "samples_hnp_card" / f"{member}.jwt").write_text(hnp[member] + "\n", newline="\n")
    # loose files + PEM public keys from the card case
    card = json.loads((out / "card" / "bundle.json").read_text(encoding="utf-8"))
    keys = json.loads((out / "card" / "trusted_keys.json").read_text(encoding="utf-8"))
    loose = fx / "loose"
    loose.mkdir(parents=True, exist_ok=True)
    for member, fname in (
        ("checkout_mandate", "checkout_mandate.txt"),
        ("payment_mandate", "payment_mandate.txt"),
        ("checkout_receipt", "checkout_receipt.jwt"),
        ("payment_receipt", "payment_receipt.jwt"),
    ):
        (loose / fname).write_text(card[member] + "\n", newline="\n")
    for role, fname in (
        ("mandate_issuer", "issuer.pem"),
        ("merchant", "merchant.pem"),
        ("payment_processor", "processor.pem"),
    ):
        (loose / fname).write_text(pem_of(keys[role][0]), newline="\n")
    (loose / "expected.json").write_text(json.dumps(card["expected"], indent=2) + "\n")
    # the agent's public key, as bound in cnf.jwk of the card case's open payment mandate
    from base64 import urlsafe_b64decode

    open_seg = card["payment_mandate"].split("~~")[0]
    for disc in open_seg.split("~")[1:]:
        if not disc:
            continue
        value = json.loads(urlsafe_b64decode(disc + "=" * (-len(disc) % 4)))[-1]
        if isinstance(value, dict) and isinstance(value.get("cnf"), dict):
            (loose / "agent.jwk").write_text(json.dumps(value["cnf"]["jwk"]) + "\n")
            break
    # the unsigned settlement object the x402 PSP sample returns instead of a receipt JWT
    p1 = out / "probes" / "P1_x402_psp_receipt_object" / "bundle.json"
    psp = json.loads(p1.read_text(encoding="utf-8"))["payment_receipt"]
    (loose / "x402_psp_settlement.json").write_text(json.dumps(psp, indent=2) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
