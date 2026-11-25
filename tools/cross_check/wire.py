"""Small, dependency-free helpers for reading AP2 wire material as data."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

#: Members a public JWK may carry (``types/jwk.json`` plus the usual metadata).
PUBLIC_JWK_MEMBERS = frozenset({"kty", "crv", "x", "y", "kid", "use", "alg", "key_ops"})


def b64d(text: str) -> bytes:
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64e(data: bytes) -> str:
    """Encode as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jdec(text: str) -> Any:
    """Decode a base64url JSON value; ``None`` when it is not one."""
    try:
        return json.loads(b64d(text))
    except (ValueError, UnicodeDecodeError):
        return None


def sha_b64(text: str) -> str:
    """Base64url SHA-256 of a UTF-8 string."""
    return b64e(hashlib.sha256(text.encode("utf-8")).digest())


def load_json(path: Path) -> Any:
    """Read a JSON file."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def jws_payload(token: str) -> Any:
    """Decoded payload of a compact JWS, or ``None``."""
    parts = token.split(".")
    return jdec(parts[1]) if len(parts) == 3 else None


def public_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    """Keep only public JWK members (drops ``d`` and anything unknown)."""
    return {k: v for k, v in jwk.items() if k in PUBLIC_JWK_MEMBERS}


def pem_to_jwk(pem: str) -> dict[str, str]:
    """Convert a P-256 SubjectPublicKeyInfo PEM to a JWK by walking the DER bytes."""
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    der = base64.b64decode(body)
    idx = der.find(b"\x03\x42\x00\x04")
    if idx < 0 or b"PRIVATE" in pem.encode():
        raise ValueError("not an uncompressed P-256 public key")
    point = der[idx + 4 : idx + 4 + 64]
    return {"kty": "EC", "crv": "P-256", "x": b64e(point[:32]), "y": b64e(point[32:])}


def chain_objects(chain: str) -> list[dict[str, Any]]:
    """Every JSON object found in a chain's JWS payloads and disclosures, in order."""
    out: list[dict[str, Any]] = []
    for seg in chain.split("~~"):
        parts = seg.split("~")
        payload = jws_payload(parts[0])
        if isinstance(payload, dict):
            out.append(payload)
            for item in payload.get("delegate_payload") or []:
                if isinstance(item, dict) and "vct" in item:
                    out.append(item)
        for disc in parts[1:]:
            value = jdec(disc) if disc else None
            if isinstance(value, list) and value and isinstance(value[-1], dict):
                out.append(value[-1])
    return out


def mandate(chain: str, vct: str) -> dict[str, Any] | None:
    """The first mandate object with the given ``vct`` in a chain."""
    return next((o for o in chain_objects(chain) if o.get("vct") == vct), None)


def slot_for(chain: str) -> str | None:
    """Bundle member for a chain, from the ``vct`` of its first mandate."""
    vct = next((str(o["vct"]) for o in chain_objects(chain) if "vct" in o), "")
    if "checkout" in vct:
        return "checkout_mandate"
    if "payment" in vct:
        return "payment_mandate"
    return None


def closed_amount(chain: str) -> dict[str, Any] | None:
    """``payment_amount`` of the closed payment mandate in a chain."""
    m = mandate(chain, "mandate.payment.1")
    amount = m.get("payment_amount") if m else None
    return amount if isinstance(amount, dict) else None


def new_bundle(note: str) -> dict[str, Any]:
    """An empty ``ap2-evidence/1`` bundle."""
    return {
        "bundle_version": "ap2-evidence/1",
        "note": note,
        "keys": {"mandate_issuer": [], "merchant": [], "payment_processor": []},
    }
