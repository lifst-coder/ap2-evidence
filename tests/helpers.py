"""Shared helpers for the test-suite (not a test module)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ap2_evidence.demo import DemoBuilder, DemoKeys
from ap2_evidence.jose import b64url_decode, b64url_encode, public_jwk, sign_es256
from ap2_evidence.report import Report
from ap2_evidence.verify import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OFFICIAL = ROOT / "tests" / "fixtures" / "official"
EXAMPLE = ROOT / "examples" / "official-ap2-v0.2-docs.bundle.json"

NOW = 1_780_000_000
KEYS = DemoKeys()


def builder() -> DemoBuilder:
    """A builder with shared keys and a fixed clock (fast and deterministic)."""
    return DemoBuilder(keys=KEYS, now=NOW, seed=7)


def build(
    mutate: Callable[[DemoBuilder], Any] | None = None,
    post: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    b = builder()
    if mutate is not None:
        mutate(b)
    bundle = b.build().bundle
    if post is not None:
        post(bundle)
    return bundle


def verify(bundle: Any, **kw: Any) -> Report:
    return verify_bundle(bundle, **kw)


def statuses(report: Report) -> dict[str, str]:
    return {c.id: c.status for c in report.checks}


def segments(chain: str) -> list[str]:
    """Split a chain into its segments with the stripped '~' restored."""
    parts = chain.split("~~")
    return [p if i == len(parts) - 1 else p + "~" for i, p in enumerate(parts)]


def join(segs: list[str]) -> str:
    return "~~".join(s[:-1] if i < len(segs) - 1 else s for i, s in enumerate(segs))


def disclosure(arr: list[Any]) -> str:
    return b64url_encode(json.dumps(arr).encode("utf-8"))


def add_disclosure(chain: str, seg: int, disc: str) -> str:
    segs = segments(chain)
    segs[seg] = segs[seg] + disc + "~"
    return join(segs)


def decode_jwt(jwt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    h, p, _ = jwt.split(".")
    return json.loads(b64url_decode(h)), json.loads(b64url_decode(p))


def other_key_jwk(kid: str | None) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import ec

    return public_jwk(ec.generate_private_key(ec.SECP256R1()), kid)


def resign(jwt: str, key: Any, header: dict[str, Any] | None = None) -> str:
    h, p = decode_jwt(jwt)
    return sign_es256(header or h, p, key)


def run_cli(
    *args: str, env: dict[str, str] | None = None, stdin: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SRC)
    e.pop("PYTHONIOENCODING", None)
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, "-m", "ap2_evidence", *args],
        capture_output=True,
        env=e,
        input=stdin,
        timeout=120,
        check=False,
    )


def trusted_for(b: DemoBuilder) -> dict[str, Any]:
    """All three roles pinned (the threat model of the adversarial review)."""
    k = b.keys
    return {
        "mandate_issuer": [public_jwk(k.issuer, k.issuer_kid)],
        "merchant": [public_jwk(k.merchant, k.merchant_kid)],
        "payment_processor": [public_jwk(k.processor, k.processor_kid)],
    }


def two_object_closed_payment(with_vct: bool) -> dict[str, Any]:
    """Agent-signed closed payment whose delegate_payload holds two mandate objects.

    [0] pays USD 999.00 (vct missing, or 'mandate.payment.1 ' with a space),
    [1] pays USD 199.00 with the exact vct. Receipt re-signed for that leaf.
    """
    from ap2_evidence.demo import SdElem, _SdIssuer
    from ap2_evidence.jose import hash_b64

    b = builder()
    a = b.build()
    open_seg = segments(a.bundle["payment_mandate"])[0]
    good = dict(b.closed_payment, transaction_id=hash_b64(a.checkout_jwt))
    evil = dict(good, payment_amount={"amount": 99900, "currency": "USD"})
    if with_vct:
        evil["vct"] = "mandate.payment.1 "
    else:
        evil.pop("vct")
    iss = _SdIssuer(None)
    payload = {
        "delegate_payload": iss.encode([SdElem(evil), SdElem(good)]),
        "_sd_alg": "sha-256",
        **b.closed_payment_kb,
        "sd_hash": hash_b64(open_seg),
    }
    closed = sign_es256({"alg": "ES256", "typ": "kb+sd-jwt"}, payload, KEYS.agent)
    closed += "~" + "".join(d + "~" for d in iss.disclosures)
    receipt = dict(b.payment_receipt, reference=hash_b64(closed.split("~", 1)[0]))
    return dict(
        a.bundle,
        payment_mandate=open_seg[:-1] + "~~" + closed,
        payment_receipt=sign_es256(b.receipt_header["payment"], receipt, KEYS.processor),
    )
