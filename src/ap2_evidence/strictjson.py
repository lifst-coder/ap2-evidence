"""Strict JSON parsing for untrusted input.

Everything that comes out of a token, disclosure or bundle goes through
:func:`loads`. Compared with :func:`json.loads` it rejects duplicate object
keys (an attacker could otherwise show one value to one parser and another
value to a different parser), the non-standard constants ``NaN`` /
``Infinity``, nesting deeper than :data:`MAX_DEPTH`, and inputs larger than a
caller-supplied byte limit.
"""

from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 64
"""Maximum nesting depth of arrays/objects accepted anywhere."""

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
"""Default size cap for a single JSON document (2 MiB)."""


class StrictJsonError(ValueError):
    """Raised when a JSON document is malformed or violates a strictness rule."""


def _reject_constant(name: str) -> Any:
    raise StrictJsonError(f"non-standard JSON constant {name} is not allowed")


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise StrictJsonError(f"duplicate object key {key!r}")
        out[key] = value
    return out


def _check_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > MAX_DEPTH:
                raise StrictJsonError(f"JSON nesting deeper than {MAX_DEPTH} levels")
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)


def loads(data: str | bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Parse ``data`` as strict JSON.

    Args:
        data: The JSON text. ``bytes`` must be UTF-8.
        max_bytes: Reject documents larger than this many bytes.

    Returns:
        The parsed value.

    Raises:
        StrictJsonError: If the input is not valid strict JSON.
    """
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise StrictJsonError(f"JSON document larger than {max_bytes} bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictJsonError(f"not valid UTF-8 ({exc.reason})") from None
    else:
        text = data
        if len(text) > max_bytes:
            raise StrictJsonError(f"JSON document larger than {max_bytes} bytes")
    if text.startswith("﻿"):  # a UTF-8 byte order mark
        text = text[1:]
    try:
        value = json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except StrictJsonError:
        raise
    except RecursionError:
        raise StrictJsonError(f"JSON nesting deeper than {MAX_DEPTH} levels") from None
    except json.JSONDecodeError as exc:
        raise StrictJsonError(f"not valid JSON ({exc.msg} at position {exc.pos})") from None
    except ValueError as exc:  # e.g. integer string too long
        raise StrictJsonError(f"not valid JSON ({exc})") from None
    _check_depth(value)
    return value
