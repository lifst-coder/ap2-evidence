"""Import evidence from the directory the official AP2 Python samples write (``temp-db``).

Layout written by upstream ``code/samples/python`` at commit ``e1ea56d`` (v0.2.0), directory
``$TEMP_DB_DIR`` (default ``.temp-db``):

- ``chk_<id>.sdjwt`` / ``pay_<id>.sdjwt``: checkout / payment mandate chains (open~~closed),
  written by ``shopping_agent_v2/shopping_agent/mandate_tools.py`` ``_persist_mandate``.
  The same chains are also stored under a hash-named file without extension, and the open
  mandates alone as ``open_chk_*`` / ``open_pay_*``; those copies are not needed.
- ``agent_provider_signing_key.pub`` (mandate issuer), ``merchant_signing_key.pub``
  (merchant), ``merchant_payment_processor_signing_key.pub`` (payment processor): public
  JWKs. The ``*.pem`` files next to them hold the PRIVATE JWKs; this module never opens them.
- ``ap2_token_store.json``: the credentials provider's token store, which records the
  ``payment_nonce`` each payment mandate was verified against.

Receipts are not persisted by the samples; they are passed separately.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import strictjson
from .bundle import MAX_BUNDLE_BYTES, InputError
from .fileio import decode_text, os_error_reason, read_bytes
from .jose import JoseError, hash_b64
from .keys import ImportedKey, RoleKeys, load_key_file
from .sdjwt import SdJwtError, mandate_items, parse_chain, resolve

SAMPLE_KEY_FILES: dict[str, str] = {
    "agent_provider_signing_key.pub": "mandate_issuer",
    "merchant_signing_key.pub": "merchant",
    "merchant_payment_processor_signing_key.pub": "payment_processor",
}
"""Public key files of the samples and the role each one verifies."""

TOKEN_STORE = "ap2_token_store.json"

SAMPLE_AUD = {"checkout": "merchant", "payment": "credential-provider"}
"""The aud values the sample servers verify closed mandates against (hard-coded there)."""

MAX_CHAIN_FILES = 2000
"""Refuse directories with more chain files than this (not a sample temp-db)."""

MAX_CHAIN_BYTES = 4 * 1024 * 1024


@dataclass
class SampleChain:
    """One ``chk_*.sdjwt`` or ``pay_*.sdjwt`` file and the hash links read from it."""

    kind: str
    id: str
    path: Path
    text: str = ""
    error: str | None = None
    links: set[str] = field(default_factory=set)
    transaction_id: str | None = None


@dataclass
class SampleImport:
    """What was taken from a sample directory."""

    checkout: SampleChain | None
    payment: SampleChain | None
    keys: RoleKeys
    expected: dict[str, dict[str, str]]
    expected_sources: list[str]
    notes: list[str]
    warnings: list[str]


def _read_chain(kind: str, path: Path) -> SampleChain:
    ch = SampleChain(kind, path.name.removesuffix(".sdjwt"), path)
    try:
        ch.text = decode_text(read_bytes(str(path), "mandate chain", MAX_CHAIN_BYTES), path.name)
        ch.text = ch.text.strip()
    except InputError as exc:
        ch.error = str(exc)
        return ch
    try:
        segments = parse_chain(ch.text)
    except SdJwtError as exc:
        ch.error = f"not an SD-JWT chain ({exc.where}: {exc})"
        return ch
    res = resolve(segments[-1])
    items = [m for m in mandate_items(res.payload or {}) if isinstance(m, dict)]
    if not items:
        ch.error = "closed mandate could not be read"
        return ch
    m = items[0]
    if kind == "checkout":
        if isinstance(m.get("checkout_hash"), str):
            ch.links.add(m["checkout_hash"])
        cj = m.get("checkout_jwt")
        if isinstance(cj, str):
            with contextlib.suppress(JoseError):
                ch.links.add(hash_b64(cj))
    elif isinstance(m.get("transaction_id"), str):
        ch.transaction_id = m["transaction_id"]
    return ch


def _scan(root: Path, pattern: str, kind: str) -> list[SampleChain]:
    try:
        paths = sorted(p for p in root.glob(pattern) if p.is_file())
    except OSError as exc:
        reason, hint = os_error_reason(exc)
        raise InputError(f"cannot list {root}: {reason}; {hint}") from None
    if len(paths) > MAX_CHAIN_FILES:
        raise InputError(
            f"{root} holds more than {MAX_CHAIN_FILES} {pattern} files; this does not look "
            "like one sample run's temp-db"
        )
    return [_read_chain(kind, p) for p in paths]


def _select(chains: list[SampleChain], sel: str, flag: str) -> SampleChain:
    name = Path(sel).name.removesuffix(".sdjwt")
    for ch in chains:
        if ch.id == name:
            if ch.error:
                raise InputError(f"{flag} {sel}: {ch.path.name} is unusable: {ch.error}")
            return ch
    have = ", ".join(c.id for c in chains[:20]) or "none"
    raise InputError(f"{flag} {sel}: no such chain in the sample directory (found: {have})")


def _fmt_pairs(pairs: list[tuple[SampleChain, SampleChain]]) -> str:
    shown = "; ".join(f"--checkout {c.id} --payment {p.id}" for c, p in pairs[:10])
    more = f"; and {len(pairs) - 10} more" if len(pairs) > 10 else ""
    return shown + more


def _pair(
    chks: list[SampleChain], pays: list[SampleChain], sel_c: str | None, sel_p: str | None
) -> tuple[SampleChain | None, SampleChain | None, list[str]]:
    warnings: list[str] = []
    good_c = [c for c in chks if not c.error]
    good_p = [p for p in pays if not p.error]
    for ch in chks + pays:
        if ch.error:
            warnings.append(f"skipped {ch.path.name}: {ch.error}")
    pairs = [(c, p) for c in good_c for p in good_p if p.transaction_id in c.links]
    chosen_c = _select(chks, sel_c, "--checkout") if sel_c else None
    chosen_p = _select(pays, sel_p, "--payment") if sel_p else None
    if chosen_c is not None and chosen_p is not None:
        if not any(c is chosen_c and p is chosen_p for c, p in pairs):
            warnings.append(
                f"{chosen_p.id} is not hash-linked to {chosen_c.id} (its transaction_id is not "
                "that checkout's hash); packed as selected, verify will report the broken link"
            )
        return chosen_c, chosen_p, warnings
    fixed = chosen_c or chosen_p
    if fixed is not None:
        matches = [(c, p) for c, p in pairs if fixed is c or fixed is p]
        if len(matches) == 1:
            return matches[0][0], matches[0][1], warnings
        if len(matches) > 1:
            raise InputError(
                f"{fixed.id} is hash-linked to {len(matches)} chains, so the pair is ambiguous; "
                f"choose one of: {_fmt_pairs(matches)}"
            )
        other = "payment" if chosen_c else "checkout"
        warnings.append(f"no {other} chain in the directory is hash-linked to {fixed.id}")
        return chosen_c, chosen_p, warnings
    if len(pairs) == 1:
        return pairs[0][0], pairs[0][1], warnings
    if len(pairs) > 1:
        raise InputError(
            f"the sample directory holds {len(pairs)} hash-linked checkout/payment pairs (more "
            f"than one purchase); refusing to guess, choose one with: {_fmt_pairs(pairs)}"
        )
    if not good_c and not good_p:
        problems = f" ({'; '.join(warnings)})" if warnings else ""
        raise InputError(
            "no usable chk_*.sdjwt or pay_*.sdjwt mandate chain in the sample directory"
            f"{problems}; give the folder set as TEMP_DB_DIR when the sample ran (default "
            ".temp-db)"
        )
    if len(good_c) <= 1 and len(good_p) <= 1 and not (good_c and good_p):
        only = good_c[0] if good_c else good_p[0]
        other = "payment" if good_c else "checkout"
        warnings.append(f"the directory holds no {other} mandate chain")
        return (only, None, warnings) if good_c else (None, only, warnings)
    cands = ", ".join(c.id for c in (good_c + good_p)[:20])
    raise InputError(
        f"the sample directory holds {len(good_c)} checkout and {len(good_p)} payment chains "
        f"and no hash-linked pair among them; refusing to guess, choose with --checkout ID "
        f"and/or --payment ID (found: {cands})"
    )


def _store_nonce(root: Path, payment: SampleChain) -> tuple[str | None, list[str]]:
    path = root / TOKEN_STORE
    if not path.is_file():
        return None, [f"{TOKEN_STORE} not found, so no expected payment nonce"]
    try:
        store = strictjson.loads(read_bytes(str(path), "token store"), max_bytes=MAX_BUNDLE_BYTES)
    except (InputError, strictjson.StrictJsonError) as exc:
        return None, [f"{TOKEN_STORE} ignored: {exc}"]
    if not isinstance(store, dict):
        return None, [f"{TOKEN_STORE} ignored: not a JSON object"]
    by_chain: set[str] = set()
    by_txn: set[str] = set()
    for entry in store.values():
        if not isinstance(entry, dict) or not isinstance(entry.get("payment_nonce"), str):
            continue
        nonce = entry["payment_nonce"]
        bundled = entry.get("bundled_payload")
        chain = entry.get("payment_mandate_chain")
        if not isinstance(chain, str) and isinstance(bundled, dict):
            chain = bundled.get("payment_mandate_chain")
        if isinstance(chain, str) and chain.strip() == payment.text:
            by_chain.add(nonce)
        elif payment.transaction_id and entry.get("checkout_jwt_hash") == payment.transaction_id:
            by_txn.add(nonce)
    found = by_chain or by_txn
    if len(found) == 1:
        return next(iter(found)), []
    if len(found) > 1:
        return None, [f"{TOKEN_STORE} records different nonces for {payment.id}; none used"]
    return None, [f"{TOKEN_STORE} has no entry for {payment.id}, so no expected payment nonce"]


def import_sample_db(root_arg: str, sel_c: str | None, sel_p: str | None) -> SampleImport:
    """Read one purchase from a sample ``temp-db`` directory.

    Only ``chk_*.sdjwt``, ``pay_*.sdjwt``, the three ``*_signing_key.pub`` files and
    ``ap2_token_store.json`` are opened. Private key files are never opened.

    Raises:
        InputError: If the directory is unusable or the pairing is ambiguous.
    """
    root = Path(root_arg)
    if not root.is_dir():
        what = "does not exist" if not root.exists() else "is not a directory"
        raise InputError(
            f"--from-ap2-sample-db {root_arg} {what}; give the folder set as TEMP_DB_DIR when "
            "the sample ran (default .temp-db)"
        )
    chks = _scan(root, "chk_*.sdjwt", "checkout")
    pays = _scan(root, "pay_*.sdjwt", "payment")
    checkout, payment, warnings = _pair(chks, pays, sel_c, sel_p)
    keys = RoleKeys()
    notes: list[str] = []
    for name, role in SAMPLE_KEY_FILES.items():
        p = root / name
        if p.is_file():
            items = load_key_file(str(p), "sample")
            keys.add(role, [ImportedKey(k.jwk, f"sample {name}", k.notes) for k in items])
        else:
            warnings.append(f"{name} not found, so no {role} key")
    expected: dict[str, dict[str, str]] = {}
    sources: list[str] = []
    if checkout:
        expected["checkout"] = {"aud": SAMPLE_AUD["checkout"]}
        sources.append(
            "expected.checkout.aud 'merchant': the value the sample merchant server verifies; "
            "the checkout nonce is not persisted by the samples"
        )
    if payment:
        expected["payment"] = {"aud": SAMPLE_AUD["payment"]}
        sources.append(
            "expected.payment.aud 'credential-provider': the value the sample credentials "
            "provider verifies"
        )
        nonce, msgs = _store_nonce(root, payment)
        warnings += msgs
        if nonce is not None:
            expected["payment"]["nonce"] = nonce
            sources.append(f"expected.payment.nonce: from the sample's own {TOKEN_STORE}")
    notes.append(
        "keys taken from the sample's *_signing_key.pub files: pin them only if you trust "
        "this directory; the *.pem private key files were not opened"
    )
    return SampleImport(checkout, payment, keys, expected, sources, notes, warnings)


def describe(imp: SampleImport) -> dict[str, Any]:
    """Short JSON-ready description of an import (for messages and tests)."""
    return {
        "checkout": imp.checkout.id if imp.checkout else None,
        "payment": imp.payment.id if imp.payment else None,
        "keys": {r: len(v) for r, v in imp.keys.keys.items()},
        "expected": imp.expected,
    }
