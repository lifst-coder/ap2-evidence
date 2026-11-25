"""Evidence bundle format ``ap2-evidence/1`` and key handling.

AP2 defines no container for dispute evidence, so this tool defines one (see
``docs/bundle-format.md`` and ``schemas/bundle.schema.json``). Keys can come
from two places with different trust: keys inside the bundle are
*self-asserted* by whoever assembled it; keys passed with ``--trusted-keys``
are *pinned* by the person running the verifier and take precedence.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from typing import Any

from . import strictjson
from .constraints import u
from .jose import JoseError, PublicKey, load_public_jwk

BUNDLE_VERSION = "ap2-evidence/1"

DOCS_URL = "https://github.com/lifst-coder/ap2-evidence/blob/main/docs"
"""Where the documentation is published (used in hints)."""
"""The only bundle version understood by this release."""

ARTIFACTS = ("checkout_mandate", "payment_mandate", "checkout_receipt", "payment_receipt")
"""Bundle members that carry tokens."""

ROLES = ("mandate_issuer", "merchant", "payment_processor")
"""Key roles."""

KNOWN_MEMBERS = frozenset({"bundle_version", *ARTIFACTS, "keys", "expected", "note"})

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
"""Size cap for a bundle file."""

MAX_KEYS_PER_ROLE = 64

TRUSTED = "trusted"
BUNDLE = "bundle"
MANDATE = "mandate"


class InputError(ValueError):
    """Unreadable input that should end the CLI with exit code 2."""


CHECK_FILE = "check that the right file was given"
"""Hint that ends every "... is empty" message."""


PRIVATE_KEY_MESSAGE = (
    "{where} holds a PRIVATE key, but a public key is expected here. Never share or pass "
    "around this file: anyone who has it can sign as its owner. Export only the public part "
    "(a JWK without 'd', or a PEM 'PUBLIC KEY') and use that file"
)
"""One-line refusal used wherever private key material turns up instead of a public key."""

_SECRET_JWK_MEMBERS = ("d", "k", "p", "q", "dp", "dq", "qi", "oth")


def contains_private_jwk(value: Any, _depth: int = 0) -> bool:
    """True if ``value`` is or contains a JWK with private or secret members (``d``, ``k``...)."""
    if _depth > 8:
        return False
    if isinstance(value, dict):
        if ("kty" in value or "crv" in value or "x" in value) and any(
            m in value for m in _SECRET_JWK_MEMBERS
        ):
            return True
        return any(contains_private_jwk(v, _depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(contains_private_jwk(v, _depth + 1) for v in value[: MAX_KEYS_PER_ROLE * 4])
    return False


def json_error_position(text: str | bytes) -> str | None:
    """``"line L, column C (reason)"`` for text that is not valid JSON, else ``None``."""
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return f"line {exc.lineno}, column {exc.colno} ({exc.msg})"
    except (ValueError, TypeError, RecursionError):
        return None
    return None


def _json_problem(data: str | bytes, exc: strictjson.StrictJsonError) -> str:
    where = json_error_position(data) if str(exc).startswith("not valid JSON") else None
    return f"not valid JSON at {where}" if where else str(exc)


def parse_bundle_text(data: bytes | str, where: str = "input") -> Any:
    """Parse bundle bytes as strict JSON; ``where`` names the input in the empty message.

    Raises:
        InputError: If the input is empty or not strict JSON.
    """
    if not (data.strip() if isinstance(data, (bytes, str)) else data):
        raise InputError(f"{where} is empty; {CHECK_FILE}")
    try:
        value = strictjson.loads(data, max_bytes=MAX_BUNDLE_BYTES)
    except strictjson.StrictJsonError as exc:
        raise InputError(
            f"not a JSON evidence bundle: {_json_problem(data, exc)}; a bundle is one JSON "
            f"object (see {DOCS_URL}/bundle-format.md), or use 'ap2-evidence pack' to make one"
        ) from None
    if not isinstance(value, dict):
        raise InputError(
            f"not an evidence bundle: the file holds a JSON {_json_type(value)}, expected an "
            f"object with bundle_version {BUNDLE_VERSION!r} (see {DOCS_URL}/bundle-format.md)"
        )
    return value


def looks_like_key_file(value: Any) -> bool:
    """True for a trusted-keys file (role map), a JWKS or a single JWK."""
    if not isinstance(value, dict):
        return False
    return bool(set(value) & set(ROLES)) or isinstance(value.get("keys"), list) or "kty" in value


def require_bundle_object(value: dict[str, Any], where: str) -> None:
    """CLI guard: a JSON object without ``bundle_version`` is not an evidence bundle.

    (``verify_bundle`` itself still reports such input as FAILED; only the CLI refuses it.)

    Raises:
        InputError: If ``bundle_version`` is missing, naming the right flag for key files.
    """
    if "bundle_version" in value:
        return
    if looks_like_key_file(value):
        raise InputError(
            f"{where} is not an ap2-evidence bundle: no bundle_version member; this looks like "
            "a key file: pass it with --trusted-keys (keys grouped by role) or with "
            "--issuer-key / --merchant-key / --processor-key (a JWK or JWKS)"
        )
    raise InputError(
        f"{where} is not an ap2-evidence bundle: no bundle_version member (expected "
        f"{BUNDLE_VERSION!r}); see {DOCS_URL}/bundle-format.md, or build one with "
        "'ap2-evidence pack'"
    )


def _json_type(value: Any) -> str:
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    return "number"


def suggest_member(name: str) -> str | None:
    """Closest known bundle member to a misspelt one, if any."""
    found = difflib.get_close_matches(name, sorted(KNOWN_MEMBERS), n=1, cutoff=0.75)
    return found[0] if found else None


@dataclass
class KeyEntry:
    """One usable public key with its role, provenance and a label for reports."""

    key: PublicKey
    role: str
    provenance: str
    label: str


@dataclass
class KeyStore:
    """Keys by role. Pinned (trusted) keys of a role hide bundle keys of that role."""

    entries: list[KeyEntry] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_role_map(self, value: Any, provenance: str, source: str) -> None:
        """Add keys from a ``{"role": [JWK, ...]}`` object, collecting problems."""
        if not isinstance(value, dict):
            self.problems.append(f"{source} must be an object mapping roles to arrays of JWKs")
            return
        for role, keys in value.items():
            if role not in ROLES:
                self.warnings.append(
                    f"{source}.{role}: unknown role ignored (roles: {', '.join(ROLES)})"
                )
                continue
            if not isinstance(keys, list):
                self.problems.append(f"{source}.{role} must be an array of JWKs")
                continue
            if len(keys) > MAX_KEYS_PER_ROLE:
                self.problems.append(f"{source}.{role} has more than {MAX_KEYS_PER_ROLE} keys")
                continue
            for i, jwk in enumerate(keys):
                label = f"{source}.{role}[{i}]"
                try:
                    pub = load_public_jwk(jwk)
                except JoseError as exc:
                    self.problems.append(f"{label}: {exc}")
                    continue
                self.entries.append(KeyEntry(pub, role, provenance, label))

    def has_trusted(self) -> bool:
        """True if any pinned key was supplied."""
        return any(e.provenance == TRUSTED for e in self.entries)

    def candidates(self, role: str, kid: Any) -> tuple[list[KeyEntry], str]:
        """Return the keys to try for a signature and a note on how they were chosen."""
        trusted = [e for e in self.entries if e.role == role and e.provenance == TRUSTED]
        bundled = [e for e in self.entries if e.role == role and e.provenance == BUNDLE]
        pool = trusted or bundled
        note = ""
        if trusted and bundled:
            note = (
                f"{len(bundled)} bundle-supplied {role} key(s) ignored because --trusted-keys pins "
                "this role. "
            )
        if isinstance(kid, str) and pool:
            match = [e for e in pool if e.key.kid == kid]
            if match:
                return match, note
            kids = ", ".join(repr(e.key.kid) if e.key.kid else "no kid" for e in pool)
            return pool, note + (
                f"header kid {u(kid, 60)!r} matches none of the supplied {role} keys "
                f"(kids: {kids}), so all of them were tried. "
            )
        return pool, note


def load_trusted_keys(data: bytes | str, where: str = "the trusted keys file") -> KeyStore:
    """Load a ``--trusted-keys`` file (``{"role": [JWK, ...]}``); ``where`` names it if empty.

    Raises:
        InputError: If the file is not valid or contains an invalid key.
    """
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    if "-----BEGIN" in text:
        if "PRIVATE KEY" in text.upper():
            raise InputError(PRIVATE_KEY_MESSAGE.format(where="the trusted keys file"))
        raise InputError(
            "the trusted keys file is PEM, which does not say whose key it is; --trusted-keys "
            "takes a JSON file with keys grouped by role, so pass a PEM public key or "
            "certificate with --issuer-key, --merchant-key or --processor-key instead"
        )
    if not text.lstrip("\ufeff").strip():
        raise InputError(f"{where} is empty; {CHECK_FILE}")
    try:
        value = strictjson.loads(data, max_bytes=MAX_BUNDLE_BYTES)
    except strictjson.StrictJsonError as exc:
        raise InputError(
            f"trusted keys file: {_json_problem(data, exc)}; it must be JSON like "
            '{"mandate_issuer": [JWK...], "merchant": [...], "payment_processor": [...]}; '
            "single key files (JWK, JWKS, PEM) go with --issuer-key, --merchant-key or "
            "--processor-key"
        ) from None
    if contains_private_jwk(value):
        raise InputError(PRIVATE_KEY_MESSAGE.format(where="the trusted keys file"))
    if isinstance(value, dict) and "bundle_version" in value:
        raise InputError(
            "the trusted keys file is an evidence bundle (it has a bundle_version member), not a "
            "keys file; give the bundle as the file to verify, and give --trusted-keys a JSON "
            'file with the public keys you trust, grouped by role: {"mandate_issuer": [JWK...], '
            '"merchant": [...], "payment_processor": [...]}'
        )
    if isinstance(value, dict) and "keys" in value and not set(value) & set(ROLES):
        raise InputError(
            'trusted keys file looks like a plain JWKS ({"keys": [...]}), which does not say '
            "whose keys they are; pass it with --issuer-key, --merchant-key or --processor-key "
            'instead, or group the keys by role: {"mandate_issuer": [...], "merchant": [...], '
            '"payment_processor": [...]}'
        )
    if isinstance(value, dict) and "kty" in value:
        raise InputError(
            "trusted keys file holds a single JWK, which does not say whose key it is; pass it "
            "with --issuer-key, --merchant-key or --processor-key instead"
        )
    store = KeyStore()
    store.add_role_map(value, TRUSTED, "--trusted-keys")
    if store.problems:
        raise InputError("trusted keys file: " + "; ".join(store.problems))
    if store.warnings:
        raise InputError("trusted keys file: " + "; ".join(store.warnings))
    return store


def loose_bundle(files: dict[str, str]) -> dict[str, Any]:
    """Build a bundle from loose token strings (``--checkout-mandate FILE`` etc.)."""
    bundle: dict[str, Any] = {"bundle_version": BUNDLE_VERSION}
    for name, text in files.items():
        bundle[name] = text.strip()
    return bundle
