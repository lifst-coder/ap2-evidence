"""Decode tokens without judging them (the ``inspect`` command).

Shows headers, payloads, each disclosure with its digest, the resolved mandate
object and the hashes other artifacts refer to (SHA-256 of the issuer-signed
JWT, and the ``sd_hash``-form hash of ``<jwt>~<disclosures>~``). Works on a
single SD-JWT, a ``~~`` chain, a plain JWT such as a receipt, or a bundle.
"""

from __future__ import annotations

import json
from typing import Any

from . import strictjson
from .bundle import ARTIFACTS, MAX_BUNDLE_BYTES
from .jose import HASH_ALGS, JoseError, hash_b64, parse_compact
from .report import clean
from .sdjwt import SdJwtError, mandate_items, parse_chain, resolve


def _jwt_info(token: str) -> dict[str, Any]:
    try:
        jws = parse_compact(token, require_object_payload=False)
    except JoseError as exc:
        return {"kind": "unreadable", "error": str(exc)}
    out: dict[str, Any] = {
        "kind": "jwt",
        "header": jws.header,
        "payload": jws.payload,
        "signature_bytes": len(jws.signature),
        "hashes": {"sha256_of_jwt": hash_b64(jws.raw, "sha-256")},
    }
    return out


def inspect_token(token: str) -> dict[str, Any]:
    """Decode one token (SD-JWT chain or plain compact JWT) into a JSON-ready dict.

    Never raises for malformed input; problems are reported under ``error``.
    """
    if not isinstance(token, str):
        return {"kind": "unreadable", "error": f"expected a string, got {type(token).__name__}"}
    token = token.strip()
    if "~" not in token:
        return _jwt_info(token)
    try:
        segments = parse_chain(token)
    except SdJwtError as exc:
        return {"kind": "unreadable", "error": f"{exc.where}: {exc}"}
    out_segs: list[dict[str, Any]] = []
    for seg in segments:
        res = resolve(seg)
        alg = seg.sd_alg if seg.sd_alg in HASH_ALGS else "sha-256"
        discs = []
        for d in seg.disclosures:
            entry: dict[str, Any] = {"index": d.index, "salt": d.salt}
            if d.name is not None:
                entry["name"] = d.name
            entry["value"] = d.value
            entry["digest"] = d.digest(alg)
            entry["referenced_at"] = res.used.get(d.index)
            discs.append(entry)
        mandates = (
            [m for m in mandate_items(res.payload) if isinstance(m, dict)] if res.payload else []
        )
        info: dict[str, Any] = {
            "index": seg.index,
            "header": seg.jws.header,
            "payload": seg.jws.payload,
            "disclosures": discs,
            "resolution_errors": res.errors,
            "mandate": mandates[0] if len(mandates) == 1 else mandates,
            "hashes": {
                "sha256_of_issuer_jwt": hash_b64(seg.issuer_jwt, "sha-256"),
                f"{alg}_of_sd_hash_form": hash_b64(seg.presented, alg),
            },
        }
        for m in mandates:
            cj = m.get("checkout_jwt")
            if isinstance(cj, str):
                info["checkout_jwt"] = _jwt_info(cj)
        out_segs.append(info)
    kind = "sd-jwt" if len(out_segs) == 1 else f"sd-jwt chain ({len(out_segs)} segments)"
    return {"kind": kind, "segments": out_segs}


def inspect_input(text: str) -> dict[str, Any]:
    """Inspect a token, a chain or a whole bundle (detected by a leading ``{``)."""
    s = text.strip()
    if s.startswith("{"):
        try:
            bundle = strictjson.loads(s, max_bytes=MAX_BUNDLE_BYTES)
        except strictjson.StrictJsonError as exc:
            return {"kind": "unreadable", "error": f"not a JSON bundle: {exc}"}
        if not isinstance(bundle, dict):
            return {"kind": "unreadable", "error": "bundle is not a JSON object"}
        arts = {}
        for name in ARTIFACTS:
            if isinstance(bundle.get(name), str):
                arts[name] = inspect_token(bundle[name])
        return {"kind": "bundle", "bundle_version": bundle.get("bundle_version"), "artifacts": arts}
    return inspect_token(s)


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def _lines(block: str, indent: str) -> list[str]:
    return [indent + clean(line, 2000, collapse=False) for line in block.splitlines()]


def _render_token(info: dict[str, Any], indent: str) -> list[str]:
    out: list[str] = [f"{indent}kind: {info.get('kind')}"]
    if "error" in info:
        out.append(f"{indent}error: {clean(info['error'])}")
        return out
    if info.get("kind") == "jwt":
        out += [f"{indent}header:"] + _lines(_dump(info["header"]), indent + "  ")
        out += [f"{indent}payload:"] + _lines(_dump(info["payload"]), indent + "  ")
        out.append(f"{indent}signature: {info['signature_bytes']} bytes")
        out.append(f"{indent}SHA-256 of the JWT: {info['hashes']['sha256_of_jwt']}")
        return out
    for seg in info.get("segments", []):
        out.append(f"{indent}segment {seg['index']}:")
        i2 = indent + "  "
        out += [f"{i2}header:"] + _lines(_dump(seg["header"]), i2 + "  ")
        out += [f"{i2}payload:"] + _lines(_dump(seg["payload"]), i2 + "  ")
        for d in seg["disclosures"]:
            name = f" name={clean(d['name'])}" if "name" in d else " (array element)"
            out.append(
                f"{i2}disclosure #{d['index']}: salt={clean(d['salt'])}{name} digest={d['digest']} "
                f"referenced at {clean(d['referenced_at']) if d['referenced_at'] else 'NOWHERE'}"
            )
            out += _lines(_dump(d["value"]), i2 + "    ")
        if seg["resolution_errors"]:
            out.append(f"{i2}disclosure problems:")
            out += [f"{i2}  - {clean(e)}" for e in seg["resolution_errors"]]
        out += [f"{i2}resolved mandate:"] + _lines(_dump(seg["mandate"]), i2 + "  ")
        for k, v in seg["hashes"].items():
            out.append(f"{i2}{k}: {v}")
        if "checkout_jwt" in seg:
            out.append(f"{i2}checkout_jwt (decoded):")
            out += _render_token(seg["checkout_jwt"], i2 + "  ")
    return out


def render_text(info: dict[str, Any]) -> str:
    """Render an :func:`inspect_input` result as plain text (terminal-safe)."""
    lines: list[str] = []
    if info.get("kind") == "bundle":
        lines.append(f"bundle (bundle_version {clean(info.get('bundle_version'))})")
        for name, art in info["artifacts"].items():
            lines.append(f"{name}:")
            lines += _render_token(art, "  ")
    else:
        lines += _render_token(info, "")
    return "\n".join(lines) + "\n"
