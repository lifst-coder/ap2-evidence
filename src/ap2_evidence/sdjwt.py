"""SD-JWT (RFC 9901) parsing and disclosure resolution for AP2 delegation chains.

AP2 v0.2 serialises a mandate chain as SD-JWT segments joined by ``~~``::

    <root SD-JWT>~<disc>...~<disc>~~<KB-SD-JWT>~<disc>...~<disc>~

The trailing ``~`` of every non-final segment is removed before joining
(upstream ``code/sdk/python/ap2/sdk/mandate.py:390-400``); :func:`split_chain`
restores it, so each :class:`Segment` carries the exact ``<jwt>~<d1>~...~<dn>~``
string over which ``sd_hash`` is computed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import strictjson
from .jose import HASH_ALGS, CompactJws, JoseError, b64url_decode, hash_b64, parse_compact

MAX_DISCLOSURES = 512
"""Maximum number of disclosures accepted in one segment."""

MAX_SEGMENTS = 8
"""Maximum number of ``~~``-separated segments accepted in one chain."""


class SdJwtError(ValueError):
    """Raised when a chain or segment cannot be parsed. ``where`` locates the problem."""

    def __init__(self, message: str, where: str) -> None:
        """Create the error with a human-readable location such as ``segment 2, disclosure #1``."""
        super().__init__(message)
        self.where = where


class ResolvedList(list[Any]):
    """A list produced by disclosure resolution, remembering undisclosed elements.

    ``hidden`` counts ``{"...": digest}`` placeholders that had no matching
    disclosure (undisclosed elements or decoys), so constraint evaluation can
    distinguish "issuer wrote an empty list" from "nothing was revealed".
    """

    hidden: int = 0


@dataclass(frozen=True)
class Disclosure:
    """One decoded disclosure, in token order (``index`` is 1-based)."""

    index: int
    raw: str
    salt: str
    name: str | None
    value: Any

    @property
    def kind(self) -> str:
        """``"property"`` for ``[salt, name, value]`` or ``"element"`` for ``[salt, value]``."""
        return "element" if self.name is None else "property"

    def digest(self, alg: str) -> str:
        """Digest of this disclosure under ``alg`` (hash of the ASCII base64url string)."""
        return hash_b64(self.raw, alg)


@dataclass
class Segment:
    """One SD-JWT segment of a chain (``index`` is 1-based)."""

    index: int
    presented: str
    jws: CompactJws
    disclosures: list[Disclosure]

    @property
    def issuer_jwt(self) -> str:
        """The issuer-signed JWT of this segment (text before the first ``~``)."""
        return self.jws.raw

    @property
    def sd_alg_raw(self) -> Any:
        """The ``_sd_alg`` claim as found (``None`` when absent)."""
        return self.jws.payload.get("_sd_alg") if isinstance(self.jws.payload, dict) else None

    @property
    def sd_alg(self) -> str:
        """Effective ``_sd_alg`` (``sha-256`` when absent). Not validated here."""
        alg = self.sd_alg_raw
        return alg if isinstance(alg, str) else "sha-256"

    def sd_hash_form(self, alg: str | None = None) -> str:
        """Hash of ``<jwt>~<d1>~...~<dn>~`` as presented (the ``sd_hash`` input)."""
        return hash_b64(self.presented, alg or self.sd_alg)

    def issuer_jwt_hash(self, alg: str | None = None) -> str:
        """Hash of the issuer-signed JWT only (the ``issuer_jwt_hash`` input)."""
        return hash_b64(self.issuer_jwt, alg or self.sd_alg)


def split_chain(chain: str) -> list[str]:
    """Split a ``~~``-joined chain into segments, restoring stripped trailing ``~``.

    Raises:
        SdJwtError: If the chain is empty, has empty segments or too many segments.
    """
    if not isinstance(chain, str):
        raise SdJwtError(f"expected a string, got {type(chain).__name__}", "whole token")
    text = chain.strip()
    if not text:
        raise SdJwtError("empty token", "whole token")
    pieces = text.split("~~")
    if len(pieces) > MAX_SEGMENTS:
        raise SdJwtError(f"more than {MAX_SEGMENTS} segments", "whole token")
    out: list[str] = []
    for i, piece in enumerate(pieces):
        where = f"segment {i + 1}"
        if not piece:
            raise SdJwtError("empty segment (unexpected '~~')", where)
        if piece.startswith("~"):
            raise SdJwtError("segment starts with '~' (stray separator)", where)
        last = i == len(pieces) - 1
        if not last and not piece.endswith("~"):
            piece = piece + "~"
        out.append(piece)
    return out


def parse_segment(text: str, index: int) -> Segment:
    """Parse one normalised segment ``<jwt>~<d1>~...~<dn>~``.

    Raises:
        SdJwtError: If the JWT or any disclosure is malformed.
    """
    where = f"segment {index}"
    if "~" not in text:
        raise SdJwtError(
            "not an SD-JWT: no '~' separator (a plain JWT is not an AP2 mandate)", where
        )
    parts = text.split("~")
    if parts[-1] != "":
        tail = parts[-1]
        if tail.count(".") == 2:
            raise SdJwtError(
                "ends with a trailing KB-JWT; AP2 v0.2 chains end with a kb+sd-jwt segment "
                "and do not use a separate trailing KB-JWT",
                where,
            )
        raise SdJwtError("does not end with '~' (truncated?)", where)
    try:
        jws = parse_compact(parts[0])
    except JoseError as exc:
        raise SdJwtError(f"issuer-signed JWT: {exc}", where) from None
    raw_discs = parts[1:-1]
    if len(raw_discs) > MAX_DISCLOSURES:
        raise SdJwtError(f"more than {MAX_DISCLOSURES} disclosures", where)
    disclosures: list[Disclosure] = []
    for n, raw in enumerate(raw_discs, start=1):
        disclosures.append(_parse_disclosure(raw, n, f"{where}, disclosure #{n}"))
    return Segment(index=index, presented=text, jws=jws, disclosures=disclosures)


def _parse_disclosure(raw: str, n: int, where: str) -> Disclosure:
    if not raw:
        raise SdJwtError("empty disclosure (unexpected '~~' inside a segment)", where)
    try:
        decoded = b64url_decode(raw)
    except JoseError as exc:
        raise SdJwtError(f"disclosure is not base64url: {exc}", where) from None
    try:
        arr = strictjson.loads(decoded)
    except strictjson.StrictJsonError as exc:
        raise SdJwtError(f"disclosure is not valid JSON: {exc}", where) from None
    if not isinstance(arr, list):
        raise SdJwtError("disclosure is not a JSON array", where)
    if len(arr) == 2:
        salt, name, value = arr[0], None, arr[1]
    elif len(arr) == 3:
        salt, name, value = arr[0], arr[1], arr[2]
        if not isinstance(name, str):
            raise SdJwtError("disclosure claim name is not a string", where)
    else:
        raise SdJwtError(f"disclosure array must have 2 or 3 elements, has {len(arr)}", where)
    if not isinstance(salt, str):
        raise SdJwtError("disclosure salt is not a string", where)
    return Disclosure(index=n, raw=raw, salt=salt, name=name, value=value)


def parse_chain(chain: str) -> list[Segment]:
    """Parse a whole chain into segments.

    Raises:
        SdJwtError: On the first malformed part, with its location.
    """
    return [parse_segment(seg, i + 1) for i, seg in enumerate(split_chain(chain))]


@dataclass
class Resolution:
    """Result of resolving a segment's disclosures into its payload.

    ``errors`` and ``codes`` are parallel lists (human text, machine reason).
    ``hidden`` lists every digest that has no matching disclosure: tuples of
    (path in resolved coordinates, ``"sd"`` for an ``_sd`` entry or ``"elem"``
    for a ``{"...": digest}`` array element, count). SD-JWT decoys and
    withheld claims are indistinguishable, so callers decide what they mean.
    """

    payload: dict[str, Any] | None
    sd_alg: str | None
    errors: list[str] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)
    used: dict[int, str] = field(default_factory=dict)
    unreferenced: list[int] = field(default_factory=list)
    hidden: list[tuple[tuple[str | int, ...], str, int]] = field(default_factory=list)

    def error(self, code: str, message: str) -> None:
        """Record a problem."""
        self.codes.append(code)
        self.errors.append(message)


class _ResolveAbort(Exception):
    pass


def fmt_path(path: list[str | int] | tuple[str | int, ...]) -> str:
    """Format a resolved-payload path like ``delegate_payload[0].constraints``."""
    out = ""
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else p)
    return out or "(payload)"


_fmt_path = fmt_path


def resolve(segment: Segment) -> Resolution:
    """Resolve all ``_sd`` / ``{"...": digest}`` references of a segment (RFC 9901 section 7.1).

    Every disclosure must be referenced exactly once, digests must not repeat,
    claim names must not collide, and ``_sd_alg`` must be supported. The
    returned payload has ``_sd`` / ``_sd_alg`` removed and disclosed values
    inserted; problems are collected in ``errors`` instead of raising.
    """
    payload = segment.jws.payload
    if not isinstance(payload, dict):  # pragma: no cover - parse_compact guarantees an object
        r = Resolution(None, None)
        r.error("payload_not_object", "payload is not a JSON object")
        return r
    alg_raw = payload.get("_sd_alg", "sha-256")
    if not isinstance(alg_raw, str) or alg_raw not in HASH_ALGS:
        r = Resolution(None, None)
        r.error(
            "unsupported_sd_alg",
            f"unsupported _sd_alg {alg_raw!r} (supported: {', '.join(HASH_ALGS)})",
        )
        return r
    alg = alg_raw
    res = Resolution(None, alg)
    by_digest: dict[str, Disclosure] = {}
    for d in segment.disclosures:
        dg = d.digest(alg)
        if dg in by_digest:
            res.error(
                "duplicate_disclosure",
                f"disclosure #{d.index} is identical to disclosure #{by_digest[dg].index} "
                "(duplicate digest)",
            )
            continue
        by_digest[dg] = d
    seen_digests: set[str] = set()

    def take(dg: Any, path: list[str | int]) -> Disclosure | None:
        if not isinstance(dg, str):
            res.error("bad_digest", f"non-string digest at {_fmt_path(path)}")
            return None
        if dg in seen_digests:
            res.error(
                "digest_reused",
                f"digest {dg[:12]}... appears more than once (at {_fmt_path(path)})",
            )
            return None
        seen_digests.add(dg)
        return by_digest.get(dg)

    def walk(node: Any, path: list[str | int], depth: int) -> Any:
        if depth > strictjson.MAX_DEPTH:
            res.error(
                "nested_too_deep", f"disclosures nest deeper than {strictjson.MAX_DEPTH} levels"
            )
            raise _ResolveAbort
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                if key == "_sd" or (key == "_sd_alg" and depth == 0):
                    continue
                out[key] = walk(value, [*path, key], depth + 1)
            if "_sd" in node:
                sd = node["_sd"]
                if not isinstance(sd, list):
                    res.error("sd_not_array", f"_sd at {_fmt_path(path)} is not an array")
                else:
                    missing = 0
                    for dg in sd:
                        d = take(dg, path)
                        if d is None:
                            if isinstance(dg, str):
                                missing += 1
                            continue
                        if d.name is None:
                            res.error(
                                "disclosure_kind_mismatch",
                                f"disclosure #{d.index} is an array-element disclosure but is "
                                f"referenced from the _sd array at {_fmt_path(path)}",
                            )
                            continue
                        res.used[d.index] = _fmt_path([*path, d.name])
                        if d.name in ("_sd", "..."):
                            res.error(
                                "reserved_claim_name",
                                f"disclosure #{d.index} uses the reserved claim name {d.name!r}",
                            )
                            continue
                        if d.name in out:
                            res.error(
                                "claim_collision",
                                f"disclosure #{d.index} discloses {d.name!r} at "
                                f"{_fmt_path(path)}, which is already present",
                            )
                            continue
                        out[d.name] = walk(d.value, [*path, d.name], depth + 1)
                    if missing:
                        res.hidden.append((tuple(path), "sd", missing))
            return out
        if isinstance(node, list):
            lst = ResolvedList()
            for elem in node:
                if isinstance(elem, dict) and "..." in elem:
                    if len(elem) != 1:
                        res.error(
                            "bad_placeholder",
                            f"array placeholder at {_fmt_path(path)} has members besides '...'",
                        )
                        continue
                    d = take(elem["..."], path)
                    if d is None:
                        lst.hidden += 1
                        continue
                    if d.name is not None:
                        res.error(
                            "disclosure_kind_mismatch",
                            f"disclosure #{d.index} is an object-property disclosure but is "
                            f"referenced from an array element at {_fmt_path(path)}",
                        )
                        continue
                    res.used[d.index] = _fmt_path([*path, len(lst)])
                    lst.append(walk(d.value, [*path, len(lst)], depth + 1))
                else:
                    lst.append(walk(elem, [*path, len(lst)], depth + 1))
            if lst.hidden:
                res.hidden.append((tuple(path), "elem", lst.hidden))
            return lst
        return node

    try:
        resolved = walk(payload, [], 0)
    except _ResolveAbort:
        return res
    res.payload = resolved
    res.unreferenced = [d.index for d in segment.disclosures if d.index not in res.used]
    for i in res.unreferenced:
        d = segment.disclosures[i - 1]
        label = f"claim {d.name!r}" if d.name is not None else "array element"
        res.error(
            "unreferenced_disclosure",
            f"disclosure #{i} ({label}) is not referenced by any digest in the signed payload: "
            "it was not issued with this token (swapped, altered or added afterwards)",
        )
    return res


def mandate_items(resolved: dict[str, Any]) -> list[Any]:
    """Return the resolved ``delegate_payload`` items (or ``[payload]`` without one)."""
    dp = resolved.get("delegate_payload")
    if dp is None:
        return [resolved] if "vct" in resolved else []
    if not isinstance(dp, list):
        return []
    return list(dp)


def mandate_root(resolved: dict[str, Any]) -> tuple[str | int, ...]:
    """Path of the mandate object inside a resolved payload."""
    return ("delegate_payload", 0) if "delegate_payload" in resolved else ()
