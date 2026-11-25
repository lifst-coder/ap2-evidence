"""Parsing of the verifier-side options of ``verify``: what the person running it asserts.

``--require-pinned``, ``--at``, ``--prior-total`` / ``--prior-uses`` (history under the open
payment mandate) and the relying-party expectations ``--expect-agent-key``,
``--expect-checkout-id``, ``--expect-merchant-id``, ``--expect-total`` and
``--require-constraint``. The verifier does not read these from a bundle, so they are
command-line only (``pack`` does not store them).
"""

from __future__ import annotations

import argparse
import difflib
import re
from typing import Any

from . import currency
from .bundle import InputError
from .constraints import CHECKOUT_TYPES, PAYMENT_TYPES, parse_instant
from .keys import load_key_file

CONSTRAINT_TYPES: tuple[str, ...] = CHECKOUT_TYPES + PAYMENT_TYPES
"""Constraint types ``--require-constraint`` accepts."""

AT_FORMS = (
    "Unix seconds (e.g. 1777343400), an RFC 3339 date-time with a time zone "
    "(e.g. 2026-04-28T02:30:00Z or 2026-04-28T11:30:00+09:00), or a date 2026-04-28 "
    "(midnight UTC)"
)

_MINOR = re.compile(r"-?[0-9]{1,18}")
BATCH_ONLY_ONE = ("expect_checkout_id", "expect_total", "prior_total", "prior_uses")
"""Options that describe one transaction and are therefore refused in a batch run."""


def parse_at(value: str | None) -> int | None:
    """``--at`` through :func:`constraints.parse_instant`.

    Raises:
        InputError: Listing the accepted forms.
    """
    if value is None:
        return None
    ts = parse_instant(value)
    if ts is None:
        shown = value if len(value) <= 40 else value[:40] + "..."
        raise InputError(f"--at {shown!r} is not a valid time; give {AT_FORMS}")
    return ts


def parse_amount(pair: list[str], flag: str, *, allow_negative: bool = False) -> dict[str, Any]:
    """Parse ``MINOR_UNITS CURRENCY`` (``12500 USD`` is USD 125.00) into an AP2 Amount.

    Raises:
        InputError: For decimals, non-integers, negative amounts or unknown currency codes.
    """
    raw_amount, raw_cur = pair[0].strip(), pair[1].strip()
    cur = raw_cur.upper()
    if not currency.is_currency_code(cur):
        raise InputError(
            f"{flag}: {raw_cur[:20]!r} is not an ISO 4217 currency code; give it as "
            f"{flag} MINOR_UNITS CURRENCY, e.g. {flag} 12500 USD for USD 125.00"
        )
    if not _MINOR.fullmatch(raw_amount):
        hint = ""
        if re.fullmatch(r"-?[0-9]+[.,][0-9]+", raw_amount):
            exp, _known = currency.exponent(cur)
            whole, _, frac = raw_amount.replace(",", ".").partition(".")
            if len(frac) <= exp:
                minor = int(whole + frac.ljust(exp, "0")) if exp else int(whole)
                hint = f" ({cur} {raw_amount} is {minor})"
        raise InputError(
            f"{flag}: {raw_amount[:20]!r} is not a whole number of minor units{hint}; give "
            f"{flag} MINOR_UNITS CURRENCY, e.g. {flag} 12500 USD for USD 125.00"
        )
    amount = int(raw_amount)
    if amount < 0 and not allow_negative:
        raise InputError(f"{flag}: the amount must not be negative")
    return {"amount": amount, "currency": cur}


def parse_constraint_types(values: list[str] | None) -> list[str]:
    """Validate ``--require-constraint`` values, suggesting the closest known type.

    Raises:
        InputError: For an unknown constraint type.
    """
    out: list[str] = []
    for v in values or []:
        t = v.strip()
        if t not in CONSTRAINT_TYPES:
            close = difflib.get_close_matches(t.lower(), CONSTRAINT_TYPES, n=1, cutoff=0.6)
            hint = f"; did you mean {close[0]!r}?" if close else ""
            shown = t if len(t) <= 60 else t[:60] + "..."
            raise InputError(
                f"--require-constraint {shown!r} is not a known constraint type{hint} Known: "
                + ", ".join(CONSTRAINT_TYPES)
            )
        if t not in out:
            out.append(t)
    return out


def load_agent_key(path: str) -> dict[str, Any]:
    """Read the one public key given with ``--expect-agent-key`` (JWK, JWKS or PEM).

    Raises:
        InputError: For private keys, unsupported keys, or a file with several keys.
    """
    items = load_key_file(path, "--expect-agent-key")
    if len(items) != 1:
        raise InputError(
            f"--expect-agent-key {path}: the file holds {len(items)} keys; give exactly the "
            "agent's one public key"
        )
    return dict(items[0].jwk)


def verifier_options(args: argparse.Namespace) -> dict[str, Any]:
    """Collect ``expected`` (aud/nonce and relying-party members), ``history``, ``require_pinned``.

    Returns:
        Keyword arguments for :func:`~ap2_evidence.verify.verify_bundle` (only those given).

    Raises:
        InputError: If any value is invalid.
    """
    expected: dict[str, Any] = {}
    for kind in ("checkout", "payment"):
        for claim in ("aud", "nonce"):
            value = getattr(args, f"expect_{kind}_{claim}", None)
            if value is not None:
                expected.setdefault(kind, {})[claim] = value
    if getattr(args, "expect_agent_key", None):
        expected["agent_key"] = load_agent_key(args.expect_agent_key)
    for name in ("checkout_id", "merchant_id"):
        value = getattr(args, f"expect_{name}", None)
        if value is not None:
            if not value.strip():
                raise InputError(f"--expect-{name.replace('_', '-')} must not be empty")
            expected[name] = value
    if getattr(args, "expect_total", None):
        expected["total"] = parse_amount(args.expect_total, "--expect-total")
    req = parse_constraint_types(getattr(args, "require_constraint", None))
    if req:
        expected["require_constraints"] = req
    history: dict[str, Any] = {}
    if getattr(args, "prior_total", None):
        history["prior_total"] = parse_amount(args.prior_total, "--prior-total")
    if getattr(args, "prior_uses", None) is not None:
        if args.prior_uses < 0:
            raise InputError("--prior-uses must not be negative")
        history["prior_uses"] = args.prior_uses
    out: dict[str, Any] = {}
    if expected:
        out["expected"] = expected
    if history:
        out["history"] = history
    if getattr(args, "require_pinned", False):
        out["require_pinned"] = True
    return out


def add_arguments(p: argparse.ArgumentParser) -> None:
    """Add the verifier-side assertion options to the ``verify`` parser."""
    g = p.add_argument_group(
        "what you assert as the verifier",
        "Values you, the person running the verifier, assert from your own records. They are "
        "not read from the bundle and not stored by 'pack'. Amounts are in minor units "
        "followed by the currency code: 12500 USD is USD 125.00, 500 JPY is JPY 500.",
    )
    g.add_argument(
        "--require-pinned",
        action="store_true",
        help="do not accept signatures that verify only under keys supplied inside the bundle: "
        "such a check becomes a required SKIP, so the verdict is at best INCOMPLETE",
    )
    g.add_argument(
        "--expect-agent-key",
        metavar="FILE",
        help="public key of the agent the closed mandates must be bound to (JWK, JWKS with one "
        "key, PEM public key or certificate)",
    )
    g.add_argument(
        "--expect-checkout-id", metavar="ID", help="the checkout id the checkout must carry"
    )
    g.add_argument(
        "--expect-merchant-id", metavar="ID", help="the merchant id the checkout must name"
    )
    g.add_argument(
        "--expect-total",
        nargs=2,
        metavar=("MINOR_UNITS", "CURRENCY"),
        help="the checkout total and payment amount you expect, e.g. 9998 USD for USD 99.98",
    )
    g.add_argument(
        "--require-constraint",
        action="append",
        metavar="TYPE",
        help="a constraint type the open mandates must carry (repeatable), e.g. "
        "payment.amount_range; one of: " + ", ".join(CONSTRAINT_TYPES),
    )
    g.add_argument(
        "--prior-total",
        nargs=2,
        metavar=("MINOR_UNITS", "CURRENCY"),
        help="what you assert was already paid under the open payment mandate before this "
        "payment (for payment.budget), e.g. 12500 USD for USD 125.00",
    )
    g.add_argument(
        "--prior-uses",
        type=int,
        metavar="N",
        help="how many payments you assert were already made under the open payment mandate "
        "(for payment.agent_recurrence)",
    )
