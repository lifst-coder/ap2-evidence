"""Minimal, strict JOSE primitives: base64url, compact JWS, ES256 and P-256 JWKs.

Only what AP2 v0.2 uses is implemented: compact JWS with ``alg`` ES256
(ECDSA P-256 / SHA-256, raw ``r||s`` 64-byte signatures) and EC P-256 public
keys in JWK form. Anything else is rejected rather than guessed at.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from . import strictjson

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")

HASH_ALGS: dict[str, Callable[[bytes], Any]] = {
    "sha-256": hashlib.sha256,
    "sha-384": hashlib.sha384,
    "sha-512": hashlib.sha512,
}
"""``_sd_alg`` names (IANA "Named Information Hash Algorithm") supported."""

JWK_MEMBERS = frozenset(
    {"kty", "crv", "x", "y", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256"}
)
"""Members allowed by upstream ``code/sdk/schemas/ap2/types/jwk.json`` (no others allowed)."""

MAX_TOKEN_CHARS = 1024 * 1024
"""Upper bound for one compact token (1 MiB of characters)."""


class JoseError(ValueError):
    """Raised for malformed base64url, JWS or JWK input."""


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode canonical unpadded base64url.

    Rejects padding, characters outside the base64url alphabet, impossible
    lengths and non-canonical encodings (non-zero unused trailing bits), so
    that every byte string has exactly one accepted textual form.

    Raises:
        JoseError: If ``text`` is not canonical unpadded base64url.
    """
    if not isinstance(text, str):
        raise JoseError("expected a base64url string")
    if "=" in text:
        raise JoseError("base64url must not be padded with '='")
    if not _B64URL_RE.fullmatch(text):
        raise JoseError("contains characters outside the base64url alphabet")
    if len(text) % 4 == 1:
        raise JoseError("impossible base64url length")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:  # pragma: no cover - regex guards this
        raise JoseError(f"invalid base64url ({exc})") from None
    if b64url_encode(raw) != text:
        raise JoseError("non-canonical base64url (unused trailing bits are not zero)")
    return raw


def hash_b64(data: str, alg: str = "sha-256") -> str:
    """Return base64url(H(ASCII bytes of ``data``)) for an ``_sd_alg`` name.

    Raises:
        JoseError: If ``alg`` is unsupported or ``data`` is not ASCII.
    """
    try:
        fn = HASH_ALGS[alg]
    except KeyError:
        raise JoseError(f"unsupported hash algorithm {alg!r}") from None
    try:
        raw = data.encode("ascii")
    except UnicodeEncodeError:
        raise JoseError("value to hash contains non-ASCII characters") from None
    return b64url_encode(fn(raw).digest())


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class CompactJws:
    """A parsed compact JWS ``header.payload.signature``."""

    header_b64: str
    payload_b64: str
    signature_b64: str
    header: dict[str, Any]
    payload: Any
    signature: bytes

    @property
    def raw(self) -> str:
        """The compact serialisation exactly as received."""
        return f"{self.header_b64}.{self.payload_b64}.{self.signature_b64}"

    @property
    def signing_input(self) -> bytes:
        """The JWS signing input (ASCII ``header.payload``)."""
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")

    @property
    def alg(self) -> Any:
        """The ``alg`` header value (untrusted, may be any JSON type)."""
        return self.header.get("alg")


def parse_compact(token: Any, *, require_object_payload: bool = True) -> CompactJws:
    """Parse a compact JWS without verifying it.

    Args:
        token: Candidate compact JWS string.
        require_object_payload: Reject payloads that are not JSON objects.

    Raises:
        JoseError: If the token is not a well-formed compact JWS.
    """
    if not isinstance(token, str):
        raise JoseError(f"expected a string, got {type(token).__name__}")
    if not token:
        raise JoseError("empty token")
    if len(token) > MAX_TOKEN_CHARS:
        raise JoseError(f"token longer than {MAX_TOKEN_CHARS} characters")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError(
            f"expected 3 dot-separated parts (header.payload.signature), got {len(parts)}"
        )
    h64, p64, s64 = parts
    try:
        header_bytes = b64url_decode(h64)
    except JoseError as exc:
        raise JoseError(f"header: {exc}") from None
    try:
        payload_bytes = b64url_decode(p64)
    except JoseError as exc:
        raise JoseError(f"payload: {exc}") from None
    try:
        signature = b64url_decode(s64)
    except JoseError as exc:
        raise JoseError(f"signature: {exc}") from None
    try:
        header = strictjson.loads(header_bytes)
    except strictjson.StrictJsonError as exc:
        raise JoseError(f"header: {exc}") from None
    if not isinstance(header, dict):
        raise JoseError("header is not a JSON object")
    try:
        payload = strictjson.loads(payload_bytes)
    except strictjson.StrictJsonError as exc:
        raise JoseError(f"payload: {exc}") from None
    if require_object_payload and not isinstance(payload, dict):
        raise JoseError("payload is not a JSON object")
    return CompactJws(h64, p64, s64, header, payload, signature)


@dataclass(frozen=True)
class PublicKey:
    """A validated EC P-256 public key with its JWK form."""

    jwk: dict[str, Any]
    key: ec.EllipticCurvePublicKey

    @property
    def kid(self) -> str | None:
        """The ``kid`` member, if it is a string."""
        kid = self.jwk.get("kid")
        return kid if isinstance(kid, str) else None

    @property
    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint (SHA-256, base64url)."""
        return jwk_thumbprint(self.jwk)


def got_member(obj: dict[str, Any], name: str) -> str:
    """The end of a "must be X" message: ", got 'Y'" or ", but it is missing" (never None)."""
    value = obj.get(name)
    if value is None:
        return ", but it is missing" if name not in obj else ", but it is empty"
    if isinstance(value, str):
        return f", got {value[:60]!r}"
    kind = {bool: "boolean", dict: "object", list: "array"}.get(type(value), "number")
    return f", got a JSON {kind} ({json.dumps(value)[:40]})"


def load_public_jwk(jwk: Any) -> PublicKey:
    """Validate an EC P-256 public JWK and load it.

    Members not allowed by upstream ``jwk.json`` are rejected.

    Args:
        jwk: Candidate JWK object.

    Raises:
        JoseError: If the JWK is not a usable P-256 public key.
    """
    if not isinstance(jwk, dict):
        raise JoseError(f"JWK must be a JSON object, got {type(jwk).__name__}")
    if "d" in jwk:
        raise JoseError("JWK contains private key material ('d'); only public keys are accepted")
    extra = sorted(set(jwk) - JWK_MEMBERS)
    if extra:
        raise JoseError(f"JWK has members not allowed by AP2 jwk.json: {', '.join(extra)}")
    if jwk.get("kty") != "EC":
        raise JoseError(f"JWK kty must be 'EC'{got_member(jwk, 'kty')}")
    if jwk.get("crv") != "P-256":
        raise JoseError(f"JWK crv must be 'P-256'{got_member(jwk, 'crv')}")
    if "alg" in jwk and jwk["alg"] != "ES256":
        raise JoseError(f"JWK alg must be 'ES256' when present, got {jwk['alg']!r}")
    coords: list[int] = []
    for name in ("x", "y"):
        value = jwk.get(name)
        if not isinstance(value, str):
            raise JoseError(f"JWK member {name!r} missing or not a string")
        try:
            raw = b64url_decode(value)
        except JoseError as exc:
            raise JoseError(f"JWK member {name!r}: {exc}") from None
        if len(raw) != 32:
            raise JoseError(f"JWK member {name!r} must decode to 32 bytes, got {len(raw)}")
        coords.append(int.from_bytes(raw, "big"))
    try:
        key = ec.EllipticCurvePublicNumbers(coords[0], coords[1], ec.SECP256R1()).public_key()
    except ValueError:
        raise JoseError("JWK x/y is not a point on the P-256 curve") from None
    return PublicKey(dict(jwk), key)


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 thumbprint of an EC JWK."""
    required = {k: jwk.get(k) for k in ("crv", "kty", "x", "y")}
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return b64url_encode(hashlib.sha256(canonical.encode("ascii")).digest())


def verify_es256(jws: CompactJws, key: PublicKey) -> bool:
    """Verify an ES256 compact JWS signature (raw 64-byte ``r||s``)."""
    if jws.alg != "ES256" or len(jws.signature) != 64:
        return False
    r = int.from_bytes(jws.signature[:32], "big")
    s = int.from_bytes(jws.signature[32:], "big")
    if r == 0 or s == 0:
        return False
    der = encode_dss_signature(r, s)
    try:
        key.key.verify(der, jws.signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _json_segment(value: Any) -> str:
    # Python's default separators, as in the upstream sample tokens.
    return b64url_encode(json.dumps(value).encode("utf-8"))


def sign_es256(
    header: Mapping[str, Any], payload: Any, private_key: ec.EllipticCurvePrivateKey
) -> str:
    """Create an ES256 compact JWS (used by the demo builder and tests)."""
    signing_input = f"{_json_segment(dict(header))}.{_json_segment(payload)}"
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{signing_input}.{b64url_encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def public_jwk(private_key: ec.EllipticCurvePrivateKey, kid: str | None = None) -> dict[str, Any]:
    """Return the public JWK of a P-256 private key (member order as in upstream samples)."""
    numbers = private_key.public_key().public_numbers()
    jwk: dict[str, Any] = {
        "crv": "P-256",
        "kty": "EC",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }
    if kid is not None:
        jwk["kid"] = kid
    return jwk
