"""``pack``, key import (JWK / JWKS / PEM / X.509) and the role key flags."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from ap2_evidence.bundle import InputError
from ap2_evidence.jose import public_jwk
from ap2_evidence.keys import parse_key_text
from helpers import ROOT
from helpers import run_cli as _run_cli

FX = ROOT / "tests" / "fixtures" / "upstream-sdk"
LOOSE = FX / "loose"


def run_cli(*args: str) -> Any:
    return _run_cli(*args, env={"PYTHONIOENCODING": "utf-8"})


CARD_KEYS = json.loads((FX / "card" / "trusted_keys.json").read_text(encoding="utf-8"))


def _err(p: object) -> str:
    err = p.stderr.decode("utf-8", "replace")  # type: ignore[attr-defined]
    assert "Traceback" not in err, err
    return err


def _pem_private(key: object) -> str:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _pem_public(key: object) -> str:
    return (
        key.public_key()
        .public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )


def _cert(key: ec.EllipticCurvePrivateKey) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test merchant")])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))  # long expired: not validated
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ----------------------------------------------------------------------------- key parsing


def test_parse_jwk_jwks_pem_cert() -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk(k, "kid-1")
    [a] = parse_key_text(json.dumps(jwk), "f")
    assert a.jwk == jwk
    [b, c] = parse_key_text(json.dumps({"keys": [jwk, public_jwk(k)]}), "f")
    assert b.thumbprint == c.thumbprint
    [d] = parse_key_text(_pem_public(k), "f")
    assert d.thumbprint == a.thumbprint and "kid" not in d.jwk
    [e] = parse_key_text(_cert(k), "f")
    assert e.thumbprint == a.thumbprint
    assert any("NOT validated" in n for n in e.notes)
    [f] = parse_key_text(json.dumps(dict(jwk, ext=True)), "f")  # non-AP2 member dropped
    assert "ext" not in f.jwk and f.notes


@pytest.mark.parametrize(
    "text",
    [
        _pem_private(ec.generate_private_key(ec.SECP256R1())),
        json.dumps(dict(public_jwk(ec.generate_private_key(ec.SECP256R1())), d="AAAA")),
        json.dumps({"keys": [dict(public_jwk(ec.generate_private_key(ec.SECP256R1())), d="x")]}),
        "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        json.dumps({"kty": "oct", "k": "c2VjcmV0"}),
    ],
)
def test_private_key_refused(text: str) -> None:
    with pytest.raises(InputError, match="PRIVATE key.*public key is expected.*Never share") as e:
        parse_key_text(text, "key file x")
    assert "AAAA" not in str(e.value) and "c2VjcmV0" not in str(e.value)


@pytest.mark.parametrize(
    ("text", "what"),
    [
        (_pem_public(ec.generate_private_key(ec.SECP384R1())), "secp384r1"),
        (_pem_public(rsa.generate_private_key(public_exponent=65537, key_size=2048)), "RSA"),
        (_pem_public(ed25519.Ed25519PrivateKey.generate()), "Ed25519"),
        (json.dumps({"kty": "RSA", "n": "AQAB", "e": "AQAB"}), "'RSA'"),
        (json.dumps({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}), "'P-384'"),
        (json.dumps({"kty": "OKP", "crv": "Ed25519", "x": "AA"}), "'OKP'"),
    ],
)
def test_unsupported_keys(text: str, what: str) -> None:
    with pytest.raises(InputError, match="unsupported") as e:
        parse_key_text(text, "f")
    assert what in str(e.value) and "P-256" in str(e.value)


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("", "empty"),
        ("-----BEGIN PUBLIC KEY-----\nAAAA", "truncated"),
        ("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", "not a valid public key"),
        ("-----BEGIN FOO-----\nAAAA\n-----END FOO-----", "not supported"),
        ("[1, 2]", "not a JWK"),
        ("{not json", "neither PEM nor valid JSON"),
        ('{"keys": []}', "no keys"),
        (json.dumps(CARD_KEYS), "--trusted-keys"),
        (json.dumps({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}), "not a usable"),
    ],
)
def test_bad_key_files(text: str, msg: str) -> None:
    with pytest.raises(InputError, match=msg):
        parse_key_text(text, "f")


# ----------------------------------------------------------------------------- CLI: verify


def test_verify_with_role_key_flags(tmp_path: Path) -> None:
    bundle = str(FX / "card" / "bundle.json")
    p = run_cli(
        "verify",
        bundle,
        "--issuer-key",
        str(LOOSE / "issuer.pem"),
        "--merchant-key",
        str(LOOSE / "merchant.pem"),
        "--processor-key",
        str(LOOSE / "processor.pem"),
        "--format",
        "json",
    )
    assert p.returncode == 0, _err(p)
    r = json.loads(p.stdout)
    checks = {c["id"]: c for c in r["checks"]}
    assert {checks[i]["key_provenance"] for i in ("CM03", "PM03", "CR02", "PR02")} == {"trusted"}
    # the role decides: a merchant key given as processor key does not verify the receipt
    p = run_cli(
        "verify",
        bundle,
        "--issuer-key",
        str(LOOSE / "issuer.pem"),
        "--processor-key",
        str(LOOSE / "merchant.pem"),
        "--format",
        "json",
    )
    assert p.returncode == 1
    fails = {c["id"] for c in json.loads(p.stdout)["checks"] if c["status"] == "FAIL"}
    assert "PR02" in fails
    # JWKS and a certificate as role keys, repeatable flag
    jwks = tmp_path / "issuer.jwks"
    jwks.write_text(json.dumps({"keys": CARD_KEYS["mandate_issuer"]}), encoding="utf-8")
    p = run_cli(
        "verify",
        bundle,
        "--issuer-key",
        str(jwks),
        "--issuer-key",
        str(LOOSE / "issuer.pem"),
        "--trusted-keys",
        str(FX / "card" / "trusted_keys.json"),
    )
    assert p.returncode == 0, _err(p)


def test_private_key_on_cli_exit_2(tmp_path: Path) -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    secret = _pem_private(k)
    f = tmp_path / "merchant.pem"
    f.write_text(secret, encoding="ascii")
    jwk_d = tmp_path / "merchant.jwk"
    jwk_d.write_text(json.dumps(dict(public_jwk(k), d="SECRETSECRET")), encoding="utf-8")
    tk = tmp_path / "trusted.json"
    tk.write_text(json.dumps({"merchant": [dict(public_jwk(k), d="SECRETSECRET")]}))
    for args in (
        ["verify", str(FX / "card" / "bundle.json"), "--merchant-key", str(f)],
        ["verify", str(FX / "card" / "bundle.json"), "--merchant-key", str(jwk_d)],
        ["verify", str(FX / "card" / "bundle.json"), "--trusted-keys", str(tk)],
        [
            "pack",
            "--checkout-mandate",
            str(LOOSE / "checkout_mandate.txt"),
            "--out",
            str(tmp_path / "b.json"),
            "--keys-out",
            str(tmp_path / "k.json"),
            "--merchant-key",
            str(f),
        ],
    ):
        p = run_cli(*args)
        err = _err(p)
        assert p.returncode == 2, (args, err)
        assert len(err.strip().splitlines()) == 1
        assert "PRIVATE key" in err and "public key is expected" in err and "Never share" in err
        body = secret.splitlines()[1]
        assert body not in err and "SECRETSECRET" not in err and body.encode() not in p.stdout
    assert not (tmp_path / "b.json").exists()


def test_cert_note_printed(tmp_path: Path) -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    f = tmp_path / "cert.pem"
    f.write_text(_cert(k), encoding="ascii")
    p = run_cli("verify", str(FX / "card" / "bundle.json"), "--merchant-key", str(f))
    assert p.returncode == 1  # a different key: the merchant signatures fail
    assert "NOT validated" in _err(p)


def test_binary_key_file(tmp_path: Path) -> None:
    f = tmp_path / "key.der"
    f.write_bytes(b"\x30\x59\x30\x13\x00\x01" * 20)
    p = run_cli("verify", str(FX / "card" / "bundle.json"), "--issuer-key", str(f))
    assert p.returncode == 2 and "binary" in _err(p)


# ----------------------------------------------------------------------------- CLI: pack


def _pack_loose(tmp: Path, *extra: str) -> object:
    return run_cli(
        "pack",
        "--checkout-mandate",
        str(LOOSE / "checkout_mandate.txt"),
        "--payment-mandate",
        str(LOOSE / "payment_mandate.txt"),
        "--checkout-receipt",
        str(LOOSE / "checkout_receipt.jwt"),
        "--payment-receipt",
        str(LOOSE / "payment_receipt.jwt"),
        *extra,
        "--out",
        str(tmp / "b.json"),
    )


def test_pack_loose_with_pem_keys(tmp_path: Path) -> None:
    p = _pack_loose(
        tmp_path,
        "--issuer-key",
        str(LOOSE / "issuer.pem"),
        "--merchant-key",
        str(LOOSE / "merchant.pem"),
        "--processor-key",
        str(LOOSE / "processor.pem"),
        "--keys-out",
        str(tmp_path / "k.json"),
        "--expect-payment-nonce",
        "n-1",
        "--note",
        "case 42",
    )
    assert p.returncode == 0, _err(p)  # type: ignore[attr-defined]
    out = p.stdout.decode()  # type: ignore[attr-defined]
    assert "next:" in out and f"--trusted-keys {tmp_path / 'k.json'}" in out.replace('"', "")
    b = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    card = json.loads((FX / "card" / "bundle.json").read_text(encoding="utf-8"))
    for m in ("checkout_mandate", "payment_mandate", "checkout_receipt", "payment_receipt"):
        assert b[m] == card[m]  # byte-exact apart from the trailing newline
    assert "keys" not in b
    assert b["expected"] == {"payment": {"nonce": "n-1"}}
    assert b["note"] == "case 42"
    keys = json.loads((tmp_path / "k.json").read_text(encoding="utf-8"))
    assert keys == {
        r: [{k: v for k, v in j.items() if k != "kid"} for j in js] for r, js in CARD_KEYS.items()
    }
    v = run_cli("verify", str(tmp_path / "b.json"), "--trusted-keys", str(tmp_path / "k.json"))
    assert v.returncode == 1  # the pinned nonce n-1 is not the one in the mandate
    assert b"PM15" in v.stdout
    # validates against the bundle schema
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "src/ap2_evidence/schemas/bundle.schema.json").read_text())
    jsonschema.validate(b, schema)


def test_pack_whitespace_and_utf16(tmp_path: Path) -> None:
    raw = (LOOSE / "checkout_mandate.txt").read_text(encoding="ascii").strip()
    f = tmp_path / "chk.txt"
    f.write_bytes(b"\xff\xfe" + ("  \r\n" + raw + "\r\n\r\n").encode("utf-16-le"))
    p = run_cli("pack", "--checkout-mandate", str(f), "--out", str(tmp_path / "b.json"))
    assert p.returncode == 0, _err(p)
    assert json.loads((tmp_path / "b.json").read_text())["checkout_mandate"] == raw
    assert b"payment_mandate" in p.stdout  # listed as missing


def test_pack_keys_need_destination(tmp_path: Path) -> None:
    p = _pack_loose(tmp_path, "--issuer-key", str(LOOSE / "issuer.pem"))
    err = _err(p)
    assert p.returncode == 2  # type: ignore[attr-defined]
    assert "--keys-out" in err and "--embed-keys" in err
    assert not (tmp_path / "b.json").exists()


def test_pack_embed_keys_warns(tmp_path: Path) -> None:
    p = _pack_loose(
        tmp_path, "--trusted-keys", str(FX / "card" / "trusted_keys.json"), "--embed-keys"
    )
    assert p.returncode == 0  # type: ignore[attr-defined]
    assert "self-asserted" in _err(p)
    b = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert b["keys"] == CARD_KEYS
    v = run_cli("verify", str(tmp_path / "b.json"), "--format", "json")
    assert v.returncode == 0
    checks = {c["id"]: c for c in json.loads(v.stdout)["checks"]}
    assert checks["CR02"]["key_provenance"] == "bundle"


def test_pack_refuses_overwrite_and_bad_inputs(tmp_path: Path) -> None:
    (tmp_path / "b.json").write_text("keep", encoding="utf-8")
    p = _pack_loose(tmp_path)
    assert p.returncode == 2 and "--force" in _err(p)  # type: ignore[attr-defined]
    assert (tmp_path / "b.json").read_text() == "keep"
    assert _pack_loose(tmp_path, "--force").returncode == 0  # type: ignore[attr-defined]
    empty = tmp_path / "e.txt"
    empty.write_text("  \n", encoding="utf-8")
    bundle = tmp_path / "bundle-in.json"
    bundle.write_text((FX / "card" / "bundle.json").read_text(), encoding="utf-8")
    quoted = tmp_path / "q.jwt"
    quoted.write_text(json.dumps((LOOSE / "payment_receipt.jwt").read_text().strip()))
    for args, msg in (
        (["pack", "--out", str(tmp_path / "x.json")], "nothing to pack"),
        (["pack", "--checkout-mandate", str(empty), "--out", "x.json"], "is empty"),
        (["pack", "--checkout-mandate", str(bundle), "--out", "x.json"], "holds JSON"),
        (["pack", "--payment-receipt", str(quoted), "--out", "x.json"], "JSON-quoted"),
        (
            ["pack", "--checkout-mandate", str(tmp_path / "missing.txt"), "--out", "x.json"],
            "file not found",
        ),
        (["pack", "--checkout", "chk_1", "--out", "x.json"], "--from-ap2-sample-db"),
        (
            [
                "pack",
                "--checkout-mandate",
                str(LOOSE / "checkout_mandate.txt"),
                "--out",
                str(tmp_path / "s.json"),
                "--trusted-keys",
                str(FX / "card" / "trusted_keys.json"),
                "--keys-out",
                str(tmp_path / "s.json"),
            ],
            "different files",
        ),
    ):
        p = run_cli(*args)
        assert p.returncode == 2, (args, p.stderr)
        assert msg in _err(p), (args, p.stderr)
    assert not (tmp_path / "x.json").exists()


@pytest.mark.parametrize(
    "receipt",
    [
        {"transaction_id": "0x1", "status": "SETTLED"},
        json.dumps({"iss": "x", "status": "Success"}),
    ],
)
def test_pack_unsigned_receipt_stored_as_object(tmp_path: Path, receipt: object) -> None:
    f = tmp_path / "r.json"
    f.write_text(json.dumps(receipt), encoding="utf-8")
    p = run_cli(
        "pack",
        "--payment-mandate",
        str(LOOSE / "payment_mandate.txt"),
        "--payment-receipt",
        str(f),
        "--out",
        str(tmp_path / "b.json"),
    )
    assert p.returncode == 0, _err(p)
    err = _err(p)  # the warning goes to stderr, the summary keeps a short marker
    assert "this flow produced no signed payment receipt" in err
    assert "proves nothing" in p.stdout.decode()
    b = json.loads((tmp_path / "b.json").read_text())
    want = receipt if isinstance(receipt, dict) else json.loads(receipt)
    assert b["payment_receipt"] == want  # an object, not a string
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "src/ap2_evidence/schemas/bundle.schema.json").read_text())
    jsonschema.validate(b, schema)
    v = run_cli("verify", str(tmp_path / "b.json"), "--format", "json")
    assert v.returncode == 3, _err(v)
    pr01 = {c["id"]: c for c in json.loads(v.stdout)["checks"]}["PR01"]
    assert (pr01["status"], pr01["reason"]) == ("SKIP", "unsigned_receipt")


def test_pack_warns_on_swapped_or_broken_tokens(tmp_path: Path) -> None:
    p = run_cli(
        "pack",
        "--checkout-mandate",
        str(LOOSE / "checkout_receipt.jwt"),
        "--checkout-receipt",
        str(LOOSE / "checkout_mandate.txt"),
        "--out",
        str(tmp_path / "b.json"),
    )
    assert p.returncode == 0, _err(p)
    out, err = p.stdout.decode(), _err(p)  # warnings on stderr, markers in the summary
    assert "does not look like an SD-JWT mandate chain" in err
    assert "swapped" in err
    assert out.count("(unparsed)") == 2 and "warning:" not in out
