"""Refuse to redistribute private key material.

Looks for JWKs with a private member, PEM private keys and DER private keys (PKCS#8 / SEC1),
in plain JSON, in strings, and inside base64url segments of JWS / SD-JWT strings (headers,
payloads and disclosures are decoded and searched recursively).
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from wire import jdec

PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")
PEM_PRIVATE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# DER prefixes of PKCS#8 / SEC1 EC private keys in standard or url-safe base64.
DER_PRIVATE = re.compile(r"(?:MIG[HT]AgEA|MC4CAQAw|MHcCAQEE|MIIE[a-zA-Z0-9+/_-]{2}AgEA)")
SEGMENT = re.compile(r"[A-Za-z0-9_-]{16,}")


def find_private_keys(value: Any, where: str = "$", depth: int = 0) -> list[str]:
    """Return a description of every private-key hit inside a JSON value."""
    hits: list[str] = []
    if depth > 12:
        return hits
    if isinstance(value, dict):
        if "kty" in value and any(m in value for m in PRIVATE_JWK_MEMBERS):
            hits.append(f"{where}: JWK with a private member")
        for k, v in value.items():
            hits += find_private_keys(v, f"{where}.{k}", depth + 1)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            hits += find_private_keys(v, f"{where}[{i}]", depth + 1)
    elif isinstance(value, str):
        if PEM_PRIVATE.search(value):
            hits.append(f"{where}: PEM private key")
        if DER_PRIVATE.search(value):
            hits.append(f"{where}: DER private key in base64")
        for seg in SEGMENT.findall(value):
            decoded = jdec(seg)
            if isinstance(decoded, (dict, list)):
                hits += find_private_keys(decoded, f"{where}<b64>", depth + 1)
            else:
                hits += _scan_text(seg, where)
    return hits


def _scan_text(seg: str, where: str) -> list[str]:
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError):
        return []
    text = raw.decode("latin-1")
    return [f"{where}<b64>: PEM private key"] if PEM_PRIVATE.search(text) else []
