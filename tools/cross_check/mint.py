"""Minimal minter for re-wrapping decoded third-party mandate payloads into AP2 v0.2 wire form.

Independent of ap2_evidence: root SD-JWT (issuer) ``~~`` KB-SD-JWT (agent), serialised as the
upstream SDK does (``code/sdk/python/ap2/sdk/mandate.py:390-400`` at AP2 commit e1ea56d), with
``sd_hash`` over ``issuer_jwt~disclosure~``. Keys and salts are derived from fixed labels, so the
re-signed material is the same on every run except for the (randomised) ECDSA signatures.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from wire import b64e

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class Key:
    """A P-256 signing key derived deterministically from a label."""

    def __init__(self, label: str) -> None:
        """Derive the key for ``label`` (also used as ``kid``)."""
        self.kid = label
        digest = hashlib.sha256(b"ap2-evidence cross_check " + label.encode()).digest()
        seed = int.from_bytes(digest, "big")
        self._sk = ec.derive_private_key(seed % (_P256_ORDER - 1) + 1, ec.SECP256R1())
        nums = self._sk.public_key().public_numbers()
        self.jwk: dict[str, str] = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64e(nums.x.to_bytes(32, "big")),
            "y": b64e(nums.y.to_bytes(32, "big")),
            "kid": label,
        }

    def public_no_kid(self) -> dict[str, str]:
        """The public JWK without ``kid`` (the form placed in ``cnf.jwk``)."""
        return {k: v for k, v in self.jwk.items() if k != "kid"}

    def sign(self, header: dict[str, Any], payload: Any) -> str:
        """Compact ES256 JWS."""
        h = b64e(json.dumps(header, separators=(",", ":")).encode())
        p = b64e(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
        der = self._sk.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{h}.{p}.{b64e(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def sign_jwt(self, payload: Any) -> str:
        """Compact ES256 JWS with ``typ: JWT`` (checkout JWT shape)."""
        return self.sign({"alg": "ES256", "typ": "JWT", "kid": self.kid}, payload)


def _disclosure(value: Any, label: str) -> tuple[str, str]:
    salt = b64e(hashlib.sha256(b"salt " + label.encode()).digest()[:16])
    disc = b64e(json.dumps([salt, value], separators=(",", ":"), ensure_ascii=False).encode())
    return disc, b64e(hashlib.sha256(disc.encode()).digest())


def root_sdjwt(issuer: Key, mandate: dict[str, Any], label: str) -> str:
    """Issuer-signed SD-JWT whose ``delegate_payload`` discloses ``mandate``."""
    disc, digest = _disclosure(mandate, label + "/root")
    payload = {"delegate_payload": [{"...": digest}], "_sd_alg": "sha-256"}
    jws = issuer.sign({"alg": "ES256", "typ": "example+sd-jwt", "kid": issuer.kid}, payload)
    return f"{jws}~{disc}~"


def kb_sdjwt(
    agent: Key, prev: str, mandate: dict[str, Any], aud: str, nonce: str, iat: int, label: str
) -> str:
    """Agent-signed KB-SD-JWT bound to ``prev`` by ``sd_hash``."""
    disc, digest = _disclosure(mandate, label + "/kb")
    payload = {
        "delegate_payload": [{"...": digest}],
        "_sd_alg": "sha-256",
        "sd_hash": sd_hash(prev),
        "aud": aud,
        "nonce": nonce,
        "iat": iat,
    }
    jws = agent.sign({"alg": "ES256", "typ": "kb+sd-jwt", "kid": agent.kid}, payload)
    return f"{jws}~{disc}~"


def join(root: str, kb: str) -> str:
    """Serialise a two-segment chain."""
    return root[:-1] + "~~" + kb


def sd_hash(segment: str) -> str:
    """``sd_hash`` of a serialised segment."""
    return b64e(hashlib.sha256(segment.encode()).digest())
