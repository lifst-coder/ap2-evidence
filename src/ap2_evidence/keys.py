"""Import public keys for the role flags ``--issuer-key``, ``--merchant-key``, ``--processor-key``.

Accepted per file: one public JWK, a JWKS (``{"keys": [...]}``), or PEM holding a
SubjectPublicKeyInfo ``PUBLIC KEY`` or an X.509 ``CERTIFICATE`` (the public key is taken
from it; the certificate itself and its chain are *not* validated). Only EC P-256 keys
(ES256) are supported. Private key material is refused with a loud message and is
never echoed. The role is given by the flag, never guessed from the file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from . import strictjson
from .bundle import (
    CHECK_FILE,
    MAX_KEYS_PER_ROLE,
    PRIVATE_KEY_MESSAGE,
    ROLES,
    TRUSTED,
    InputError,
    KeyEntry,
    KeyStore,
    contains_private_jwk,
)
from .fileio import decode_text, read_bytes
from .jose import JWK_MEMBERS, JoseError, b64url_encode, jwk_thumbprint, load_public_jwk

MAX_KEY_FILE_BYTES = 1024 * 1024
"""Size cap for one key file."""

ROLE_FLAGS: dict[str, str] = {
    "mandate_issuer": "--issuer-key",
    "merchant": "--merchant-key",
    "payment_processor": "--processor-key",
}
"""CLI flag that assigns a key file to each role."""

UNSUPPORTED = "only EC P-256 keys (ES256) are supported, as in AP2 v0.2"

CERT_NOTE = (
    "public key taken from an X.509 certificate; the certificate itself (validity dates, "
    "issuer, chain, revocation, names) was NOT validated"
)

_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]{1,40})-----\s*(.*?)\s*-----END \1-----", re.DOTALL | re.ASCII
)


@dataclass(frozen=True)
class ImportedKey:
    """One public key read from a file: its JWK, a short source label and notes."""

    jwk: dict[str, Any]
    source: str
    notes: tuple[str, ...] = ()

    @property
    def thumbprint(self) -> str:
        """RFC 7638 thumbprint, for display."""
        return jwk_thumbprint(self.jwk)


@dataclass
class RoleKeys:
    """Imported keys by role, deduplicated by thumbprint within a role."""

    keys: dict[str, list[ImportedKey]] = field(default_factory=lambda: {r: [] for r in ROLES})

    def add(self, role: str, items: list[ImportedKey]) -> None:
        """Add keys to a role, skipping keys already present for that role."""
        have = {k.thumbprint for k in self.keys[role]}
        for item in items:
            if item.thumbprint not in have:
                self.keys[role].append(item)
                have.add(item.thumbprint)
        if len(self.keys[role]) > MAX_KEYS_PER_ROLE:
            raise InputError(
                f"more than {MAX_KEYS_PER_ROLE} {role} keys given; pin only the keys of the "
                "parties to this transaction"
            )

    def add_role_map(self, value: dict[str, list[dict[str, Any]]], source: str) -> None:
        """Add keys from an already validated ``{"role": [JWK, ...]}`` map."""
        for role, jwks in value.items():
            self.add(role, [ImportedKey(dict(j), f"{source} ({role})") for j in jwks])

    def count(self) -> int:
        """Number of keys over all roles."""
        return sum(len(v) for v in self.keys.values())

    def notes(self) -> list[str]:
        """All notes attached to imported keys (with their source)."""
        return [f"{k.source}: {n}" for v in self.keys.values() for k in v for n in k.notes]

    def role_map(self) -> dict[str, list[dict[str, Any]]]:
        """The ``{"role": [JWK, ...]}`` form used by trusted-keys files and bundles."""
        return {role: [dict(k.jwk) for k in items] for role, items in self.keys.items() if items}

    def to_keystore(self, base: KeyStore | None = None) -> KeyStore | None:
        """Add these keys as pinned (trusted) keys to ``base`` (or a new store)."""
        if not self.count():
            return base
        store = base if base is not None else KeyStore()
        for role, items in self.keys.items():
            for item in items:
                pub = load_public_jwk(item.jwk)
                store.entries.append(KeyEntry(pub, role, TRUSTED, item.source))
        return store


def _unsupported_key(key: Any, where: str) -> InputError:
    if isinstance(key, ec.EllipticCurvePublicKey):
        what = f"an EC key on curve {key.curve.name}"
    elif isinstance(key, rsa.RSAPublicKey):
        what = f"an RSA key ({key.key_size} bits)"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        what = "an Ed25519 key"
    elif isinstance(key, ed448.Ed448PublicKey):
        what = "an Ed448 key"
    else:
        what = f"a {type(key).__name__.lstrip('_')} key"
    return InputError(f"unsupported key in {where}: it is {what}; {UNSUPPORTED}")


def _jwk_from_public_key(key: Any, where: str) -> dict[str, Any]:
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise _unsupported_key(key, where)
    n = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(n.x.to_bytes(32, "big")),
        "y": b64url_encode(n.y.to_bytes(32, "big")),
    }


def _from_pem(text: str, where: str) -> list[ImportedKey]:
    blocks = list(_PEM_BLOCK.finditer(text))
    if not blocks:
        raise InputError(
            f"{where} looks like PEM but has no complete '-----BEGIN ...-----' / "
            "'-----END ...-----' block; check that the file was not truncated"
        )
    if any("PRIVATE" in m.group(1) for m in blocks):
        raise InputError(PRIVATE_KEY_MESSAGE.format(where=where))
    out: list[ImportedKey] = []
    for m in blocks:
        label = m.group(1)
        pem = m.group(0).encode("ascii", "replace")  # this block's own text
        if label in ("EC PARAMETERS",):
            continue
        if label in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            try:
                key: Any = serialization.load_pem_public_key(pem)
            except (ValueError, TypeError):
                raise InputError(
                    f"{where}: the PEM '{label}' block is not a valid public key; check that "
                    "the file was not edited or truncated"
                ) from None
            except Exception:  # noqa: BLE001 - e.g. UnsupportedAlgorithm
                raise InputError(f"unsupported key in {where}; {UNSUPPORTED}") from None
            out.append(ImportedKey(_jwk_from_public_key(key, where), f"{where} (PEM public key)"))
        elif label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
            try:
                cert = x509.load_pem_x509_certificate(pem)
                key = cert.public_key()
            except (ValueError, TypeError):
                raise InputError(
                    f"{where}: the PEM certificate block is not a valid X.509 certificate"
                ) from None
            except Exception:  # noqa: BLE001 - e.g. UnsupportedAlgorithm
                raise InputError(f"unsupported certificate key in {where}; {UNSUPPORTED}") from None
            out.append(
                ImportedKey(
                    _jwk_from_public_key(key, where), f"{where} (X.509 certificate)", (CERT_NOTE,)
                )
            )
        else:
            raise InputError(
                f"{where}: PEM block '{label}' is not supported; give a 'PUBLIC KEY' or a "
                "'CERTIFICATE'"
            )
        if len(out) > MAX_KEYS_PER_ROLE:
            raise InputError(f"{where} holds more than {MAX_KEYS_PER_ROLE} keys")
    if not out:
        raise InputError(f"{where} holds no public key or certificate")
    return out


def _member(jwk: dict[str, Any], name: str, label: str) -> str:
    """Name a JWK member's value for a message, e.g. "key type (kty) 'RSA'"; never None."""
    value = jwk.get(name)
    if value is None:
        return (
            f"no {label} (no {name} member)"
            if name not in jwk
            else f"no {label} (the {name} member is empty)"
        )
    shown = repr(value[:60]) if isinstance(value, str) else json.dumps(value)[:40]
    return f"{label} ({name}) {shown}"


def _from_jwk(jwk: Any, where: str) -> ImportedKey:
    if not isinstance(jwk, dict):
        raise InputError(f"{where}: a key must be a JSON object (JWK)")
    if jwk.get("kty") != "EC":
        raise InputError(
            f"unsupported key in {where}: {_member(jwk, 'kty', 'key type')}; {UNSUPPORTED}"
        )
    if jwk.get("crv") != "P-256":
        raise InputError(
            f"unsupported key in {where}: {_member(jwk, 'crv', 'EC curve')}; {UNSUPPORTED}"
        )
    if "alg" in jwk and jwk["alg"] != "ES256":
        raise InputError(
            f"unsupported key in {where}: {_member(jwk, 'alg', 'algorithm')}; {UNSUPPORTED}"
        )
    kept = {k: v for k, v in jwk.items() if k in JWK_MEMBERS}
    dropped = sorted(set(jwk) - JWK_MEMBERS)
    try:
        load_public_jwk(kept)
    except JoseError as exc:
        raise InputError(f"{where}: not a usable P-256 public key: {exc}") from None
    notes = (f"ignored JWK members not allowed by AP2 jwk.json: {', '.join(dropped)}",)
    return ImportedKey(kept, f"{where} (JWK)", notes if dropped else ())


def _from_json(text: str, where: str, flag: str) -> list[ImportedKey]:
    try:
        value = strictjson.loads(text, max_bytes=MAX_KEY_FILE_BYTES)
    except strictjson.StrictJsonError as exc:
        raise InputError(
            f"{where} is neither PEM nor valid JSON ({exc}); give a JWK, a JWKS or a PEM "
            "public key or certificate"
        ) from None
    if contains_private_jwk(value):
        raise InputError(PRIVATE_KEY_MESSAGE.format(where=where))
    if isinstance(value, dict) and isinstance(value.get("keys"), list):
        jwks = value["keys"]
        if not jwks:
            raise InputError(f"{where} is a JWKS with no keys")
        if len(jwks) > MAX_KEYS_PER_ROLE:
            raise InputError(f"{where} holds more than {MAX_KEYS_PER_ROLE} keys")
        return [_from_jwk(j, f"{where} keys[{i}]") for i, j in enumerate(jwks)]
    if isinstance(value, dict) and "kty" in value:
        return [_from_jwk(value, where)]
    if isinstance(value, dict) and set(value) & set(ROLES):
        raise InputError(
            f"{where} is a trusted-keys file that assigns roles itself; pass it with "
            f"--trusted-keys instead of {flag}"
        )
    raise InputError(f'{where} is JSON but not a JWK or a JWKS ({{"keys": [...]}})')


def parse_key_text(text: str, where: str, flag: str = "--issuer-key") -> list[ImportedKey]:
    """Parse the text of one key file (JWK, JWKS or PEM) into public P-256 keys.

    Raises:
        InputError: For private key material, unsupported keys and malformed files.
    """
    if "PRIVATE KEY" in text.upper():
        raise InputError(PRIVATE_KEY_MESSAGE.format(where=where))
    stripped = text.strip()
    if not stripped:
        raise InputError(f"{where} is empty; {CHECK_FILE}")
    if "-----BEGIN" in stripped:
        return _from_pem(stripped, where)
    return _from_json(stripped, where, flag)


def load_key_file(path: str, flag: str) -> list[ImportedKey]:
    """Read and parse one key file given with a role flag.

    Raises:
        InputError: If the file cannot be read or holds no usable public key.
    """
    data = read_bytes(path, "key file", MAX_KEY_FILE_BYTES)
    if b"\x00" in data[:4096] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise InputError(
            f"key file {path} is binary (DER?); convert it to PEM, for example "
            "'openssl pkey -pubin -inform DER -in FILE -out key.pem'"
        )
    where = f"key file {Path(path).name}"
    text = decode_text(data, f"key file {path}")
    items = parse_key_text(text, where, flag)
    return [
        ImportedKey(k.jwk, f"{flag} {k.source.removeprefix('key file ')}", k.notes) for k in items
    ]


def collect_role_keys(files: dict[str, list[str]]) -> RoleKeys:
    """Load every ``--issuer-key`` / ``--merchant-key`` / ``--processor-key`` file by role."""
    out = RoleKeys()
    for role, paths in files.items():
        for path in paths:
            out.add(role, load_key_file(path, ROLE_FLAGS[role]))
    return out
