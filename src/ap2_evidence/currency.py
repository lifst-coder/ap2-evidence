"""ISO 4217 minor-unit exponents and amount formatting.

AP2 amounts are integers in minor units (``code/sdk/schemas/ap2/types/amount.json``).
Converting them to major units for display, or converting ``payment.budget.max``
(major units, see docs/spec-notes.md) to minor units, needs the currency's
exponent. Only currencies whose exponent differs from 2 are listed; every other
syntactically valid code is assumed to use 2 decimals, and callers are told so.
"""

from __future__ import annotations

import re
from decimal import Decimal

_CODE_RE = re.compile(r"[A-Z]{3}")

ZERO_DECIMAL = frozenset(
    {
        "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG",
        "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF",
    }
)  # fmt: skip
"""ISO 4217 currencies with 0 minor-unit digits."""

THREE_DECIMAL = frozenset({"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"})
"""ISO 4217 currencies with 3 minor-unit digits."""

FOUR_DECIMAL = frozenset({"CLF", "UYW"})
"""ISO 4217 currencies with 4 minor-unit digits."""


def is_currency_code(code: object) -> bool:
    """Return True if ``code`` looks like an ISO 4217 alpha-3 code (three upper-case letters)."""
    return isinstance(code, str) and bool(_CODE_RE.fullmatch(code))


def exponent(code: str) -> tuple[int, bool]:
    """Return ``(exponent, known)``; ``known`` is False when 2 was assumed."""
    if code in ZERO_DECIMAL:
        return 0, True
    if code in THREE_DECIMAL:
        return 3, True
    if code in FOUR_DECIMAL:
        return 4, True
    return 2, False


def format_minor(amount: int, code: str) -> str:
    """Format an integer minor-unit amount as ``"USD 199.00"``."""
    if not is_currency_code(code):
        return f"{amount} minor units of {code!r}"
    exp, _ = exponent(code)
    value = Decimal(amount).scaleb(-exp)
    return f"{code} {value:.{exp}f}"


def major_to_minor(value: int | float, code: str) -> Decimal:
    """Convert a major-unit number (e.g. ``payment.budget.max``) to exact minor units."""
    exp, _ = exponent(code)
    return Decimal(str(value)).scaleb(exp)
