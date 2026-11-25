"""Evaluation of AP2 v0.2 mandate constraints.

Semantics follow the upstream SDK (``code/sdk/python/ap2/sdk/constraints.py``,
``max_flow_helper.py``) unless docs/spec-notes.md says otherwise. Inputs are
already disclosure-resolved; arrays that were selectively disclosable arrive as
:class:`~ap2_evidence.sdjwt.ResolvedList` so that undisclosed entries can be
told apart from entries the issuer never wrote.

Every value taken from a token is untrusted: labels pass it through :func:`u`,
which collapses whitespace and caps the length, so a crafted name cannot lay
out fake report lines.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, TypeGuard

from . import currency

CHECKOUT_TYPES = ("checkout.allowed_merchants", "checkout.line_items")
"""Constraint types defined for open checkout mandates."""

PAYMENT_TYPES = (
    "payment.agent_recurrence",
    "payment.allowed_payees",
    "payment.allowed_payment_instruments",
    "payment.allowed_pisps",
    "payment.amount_range",
    "payment.budget",
    "payment.execution_date",
    "payment.reference",
)
"""Constraint types defined for open payment mandates."""

FREQUENCIES = ("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY")
"""Allowed ``payment.agent_recurrence.frequency`` values."""

MAX_LINES = 1000
"""Upper bound on checkout lines / requirements of one ``checkout.line_items`` evaluation."""

MAX_PAIRS = 250_000
"""Upper bound on checkout lines x requirements of one ``checkout.line_items`` evaluation."""

MAX_LINE_ITEM_CONSTRAINTS = 32
"""Upper bound on ``checkout.line_items`` constraints evaluated for one open mandate."""

MAX_WORK = 2_000_000
"""Work budget (graph edges built plus edges scanned) for all line-item matching of a bundle."""

MAX_LABEL = 120
"""Maximum length of one untrusted value inside report text."""

_WS = re.compile(r"\s+")


def u(value: Any, limit: int = MAX_LABEL) -> str:
    """Render an untrusted value for report text: one line, collapsed whitespace, capped."""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = repr(value)
    text = _WS.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def q(value: Any, limit: int = MAX_LABEL) -> str:
    """Like :func:`u`, in single quotes (for identifiers and names inside sentences)."""
    return "'" + u(value, limit) + "'"


def error_text(p: dict[str, Any]) -> str:
    """'reports an error: 'x' (description 'y')' for a receipt payload, never quoting null.

    A missing or empty ``error`` / ``error_description`` is said in words, not printed
    as ``'null'``.
    """
    code, desc = p.get("error"), p.get("error_description")
    has_code, has_desc = code not in (None, ""), desc not in (None, "")
    if has_code and has_desc:
        return f"reports an error: {q(code, 60)} (description {q(desc, 200)})"
    if has_code:
        return f"reports an error: {q(code, 60)} (no description given)"
    if has_desc:
        return f"reports an error without an error code (description {q(desc, 200)})"
    return "reports an error without an error code or description"


@dataclass
class Outcome:
    """Result of evaluating one constraint (or a group of constraints of one type)."""

    status: str
    detail: str
    expected: str | None = None
    actual: str | None = None
    reason: str | None = None


def is_int(value: Any) -> TypeGuard[int]:
    """True for JSON integers (``bool`` excluded)."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value: Any) -> TypeGuard[int | float]:
    """True for JSON numbers (``bool`` excluded)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def ctype(c: Any) -> str | None:
    """The constraint's ``type`` if it is a string, else None."""
    t = c.get("type") if isinstance(c, dict) else None
    return t if isinstance(t, str) else None


def revealed(entries: Any) -> tuple[list[Any], int]:
    """Return ``(revealed entries, number of undisclosed placeholders)`` of an SD array."""
    if not isinstance(entries, list):
        return [], 0
    return list(entries), int(getattr(entries, "hidden", 0))


def merchant_matches(candidate: Any, target: Any) -> bool:
    """Upstream merchant matching: by ``id`` when both have one, else ``name`` + ``website``."""
    if not isinstance(candidate, dict) or not isinstance(target, dict):
        return False
    cid, tid = candidate.get("id"), target.get("id")
    if isinstance(cid, str) and cid and isinstance(tid, str) and tid:
        return cid == tid
    name, website = candidate.get("name"), candidate.get("website")
    return (
        isinstance(name, str)
        and bool(name)
        and isinstance(website, str)
        and bool(website)
        and name == target.get("name")
        and website == target.get("website")
    )


def merchant_details_differ(a: Any, b: Any) -> bool:
    """True if two merchant objects disagree on ``name`` or ``website``.

    Used when they matched by ``id``: upstream treats the id as authoritative, but a payee
    that carries the merchant's id under another name or website is worth a warning.
    A member absent on both sides is not a difference.
    """
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    return any(a.get(k) != b.get(k) for k in ("name", "website"))


def merchant_label(m: Any) -> str:
    """Human-readable merchant description."""
    if not isinstance(m, dict):
        return u(m)
    parts = [u(m.get("name", "(no name)"))]
    extra = [u(m[k], 80) for k in ("id", "website") if m.get(k) is not None]
    if extra:
        parts.append("(" + ", ".join(extra) + ")")
    return " ".join(parts)


def instrument_label(i: Any) -> str:
    """Human-readable payment instrument description."""
    if not isinstance(i, dict):
        return u(i)
    desc = i.get("description")
    base = f"{u(i.get('type', '?'), 40)} {q(desc, 80)}" if desc is not None else u(i.get("type"))
    return f"{base} (id {u(i.get('id'), 80)})"


def pisp_label(p: Any) -> str:
    """Human-readable PISP description."""
    if not isinstance(p, dict):
        return u(p)
    brand, legal = u(p.get("brand_name"), 60), u(p.get("legal_name"), 80)
    return f"{brand} / {legal} ({u(p.get('domain_name'), 80)})"


def amount_label(a: Any) -> str:
    """Format an Amount object (minor units) in major units."""
    if isinstance(a, dict) and is_int(a.get("amount")) and isinstance(a.get("currency"), str):
        return u(currency.format_minor(a["amount"], a["currency"]))
    return u(a)


def _hidden_note(hidden: int) -> str:
    if not hidden:
        return ""
    return (
        f" ({hidden} further entr{'y' if hidden == 1 else 'ies'} not shown in this bundle: "
        "withheld, a decoy, or replaced by an entry that was not issued; an entry that is not "
        "shown never counts as allowing anything, so it can only narrow what is allowed)"
    )


def eval_allowed_list(constraint: dict[str, Any], value: Any, what: str) -> Outcome:
    """Evaluate ``checkout.allowed_merchants`` / ``payment.allowed_payees`` (merchant lists)."""
    allowed_raw = constraint.get("allowed")
    if not isinstance(allowed_raw, list):
        return Outcome(
            "FAIL",
            f"constraint is malformed: 'allowed' is not an array ({what})",
            reason="malformed_constraint",
        )
    entries, hidden = revealed(allowed_raw)
    shown = [merchant_label(e) for e in entries]
    expected = "; ".join(shown) if shown else "(none revealed)"
    if not entries:
        return Outcome(
            "FAIL",
            f"no entries of 'allowed' are revealed{_hidden_note(hidden)}, so the {what} cannot be "
            "shown to be allowed (an empty revealed list never satisfies this constraint)",
            expected,
            merchant_label(value),
            reason="none_revealed",
        )
    matches = [e for e in entries if merchant_matches(e, value)]
    if matches and all(merchant_details_differ(e, value) for e in matches):
        # The checkout merchant (CM34, reason merchant_details_differ) and the payee (PM33,
        # payee_details_differ) get the same warning: a renamed party under an allowed id.
        return Outcome(
            "WARN",
            f"{what} {merchant_label(value)} matches the allowed entry "
            f"{merchant_label(matches[0])} by id only, which satisfies the upstream SDK; its "
            f"name or website differ from what the user's mandate allowed{_hidden_note(hidden)}",
            merchant_label(matches[0]),
            merchant_label(value),
            reason=f"{what}_details_differ",
        )
    if matches:
        return Outcome(
            "PASS",
            f"{what} {merchant_label(value)} is among the revealed allowed entries: "
            f"{expected}{_hidden_note(hidden)}",
        )
    return Outcome(
        "FAIL",
        f"{what} {merchant_label(value)} is not among the revealed allowed entries "
        f"({expected}){_hidden_note(hidden)}",
        expected,
        merchant_label(value),
        reason=f"{what}_not_allowed",
    )


class WorkBudget:
    """A shared allowance of matching work, so one bundle cannot make verification hang.

    Every ``checkout.line_items`` evaluation of a bundle draws from the same budget; once it
    is used up, the remaining evaluations report ``too_large`` instead of running.
    """

    def __init__(self, limit: int = MAX_WORK) -> None:
        """Create a budget of ``limit`` work units (graph edges built or scanned)."""
        self.left = limit

    def take(self, units: int) -> bool:
        """Spend ``units``; return False (and spend nothing) if fewer are left."""
        if units > self.left:
            return False
        self.left -= units
        return True


class _OutOfWork(Exception):
    pass


def _max_flow(
    n: int, edges: list[tuple[int, int, int]], source: int, sink: int, budget: WorkBudget
) -> int:
    """Maximum flow by Dinic's algorithm (blocking flows on BFS level graphs).

    Raises:
        _OutOfWork: When the scans needed exceed what is left of ``budget``.
    """
    head: list[list[int]] = [[] for _ in range(n)]
    to: list[int] = []
    cap: list[int] = []
    for u, v, c in edges:
        head[u].append(len(to))
        to.append(v)
        cap.append(c)
        head[v].append(len(to))
        to.append(u)
        cap.append(0)
    allowance = budget.left
    steps = 0
    flow = 0
    while True:
        level = [-1] * n
        level[source] = 0
        queue: deque[int] = deque([source])
        while queue:
            node = queue.popleft()
            for e in head[node]:
                if cap[e] > 0 and level[to[e]] < 0:
                    level[to[e]] = level[node] + 1
                    queue.append(to[e])
        steps += len(to)
        if steps > allowance:
            raise _OutOfWork
        if level[sink] < 0:
            budget.left -= steps
            return flow
        nxt = [0] * n
        while True:
            path: list[int] = []
            node = source
            while node != sink:
                adj = head[node]
                i = nxt[node]
                while i < len(adj):
                    e = adj[i]
                    if cap[e] > 0 and level[to[e]] == level[node] + 1:
                        break
                    i += 1
                steps += i - nxt[node] + 1
                nxt[node] = i
                if i < len(adj):
                    path.append(adj[i])
                    node = to[adj[i]]
                    continue
                if node == source:
                    break
                level[node] = -1  # dead end in this phase
                e = path.pop()
                node = to[e ^ 1]
                nxt[node] += 1
            if steps > allowance:
                raise _OutOfWork
            if node != sink:
                break
            push = min(cap[e] for e in path)
            for e in path:
                cap[e] -= push
                cap[e ^ 1] += push
            flow += push


def _assignable(
    cart: dict[str, int],
    req_sets: list[set[str] | None],
    req_qty: list[int],
    budget: WorkBudget,
) -> int | None:
    """How many checkout units can be assigned to requirements (None: out of work budget)."""
    total_cart = sum(cart.values())
    groups: dict[frozenset[str] | None, int] = {}
    for s, qty in zip(req_sets, req_qty, strict=True):
        key = None if s is None else frozenset(s)
        groups[key] = groups.get(key, 0) + qty
    if list(groups) == [None]:  # only wildcard requirements: no matching needed
        return min(total_cart, groups[None])
    cost = sum(len(k) if k is not None else len(cart) for k in groups) + len(cart) + len(groups)
    if not budget.take(cost):
        return None
    sku_node = {sku: 1 + i for i, sku in enumerate(cart)}
    sink = 1 + len(cart) + len(groups)
    edges: list[tuple[int, int, int]] = [(0, sku_node[sku], qty) for sku, qty in cart.items()]
    for j, (key, qty) in enumerate(groups.items()):
        g = 1 + len(cart) + j
        members = cart if key is None else [x for x in key if x in sku_node]
        edges.extend((sku_node[sku], g, total_cart) for sku in members)
        edges.append((g, sink, qty))
    try:
        return _max_flow(sink + 1, edges, 0, sink, budget)
    except _OutOfWork:
        budget.left = 0
        return None


MAX_LISTED = 50
"""Most entries one line-items result sentence lists before summarising the rest."""


def _some(parts: Iterable[str], sep: str = ", ", limit: int = MAX_LISTED) -> str:
    """Join at most ``limit`` parts, then say how many more there are (bounded report text)."""
    shown: list[str] = []
    more = 0
    for p in parts:
        if len(shown) < limit:
            shown.append(p)
        else:
            more += 1
    return sep.join(shown) + (f"{sep}(+{more} more)" if more else "")


def _over_capacity(
    cart: dict[str, int], req_sets: list[set[str] | None], req_qty: list[int]
) -> str | None:
    """A linear-time reason why no assignment can exist, or None if none is found.

    Both tests are necessary conditions for a full assignment: the checkout cannot hold
    more units than all requirements together allow, nor more units of one item than the
    requirements accepting that item allow. Cost: one pass over the requirements' sets.
    """
    total_cart, total_cap = sum(cart.values()), sum(req_qty)
    if total_cart > total_cap:
        return (
            f"the checkout has {total_cart} unit(s), but all requirements together allow at "
            f"most {total_cap}"
        )
    wild = sum(q for s, q in zip(req_sets, req_qty, strict=True) if s is None)
    cap: dict[str, int] = {}
    for s, q in zip(req_sets, req_qty, strict=True):
        if s is not None:
            for sku in s:
                if sku in cart:
                    cap[sku] = cap.get(sku, 0) + q
    over = [(sku, n, wild + cap.get(sku, 0)) for sku, n in cart.items()]
    over = [x for x in over if x[1] > x[2]]
    if not over:
        return None
    return _some(
        (
            f"the checkout has {n} unit(s) of {u(sku, 60)}, but the requirements accepting it "
            f"allow at most {c}"
            for sku, n, c in over
        ),
        sep="; ",
        limit=5,
    )


def _too_large(what: str) -> Outcome:
    return Outcome(
        "SKIP",
        f"the constraint was not evaluated: {what}, beyond what this tool evaluates (so that a "
        "crafted bundle cannot make verification hang); check the line items by hand",
        reason="too_large",
    )


def eval_line_items(
    constraint: dict[str, Any], line_items: Any, budget: WorkBudget | None = None
) -> Outcome:
    """Evaluate ``checkout.line_items`` with the upstream max-flow semantics.

    Every unit in the checkout must be assigned to a requirement whose revealed
    ``acceptable_items`` contain the item's id, without exceeding any
    requirement's ``quantity``. A literally empty ``acceptable_items`` array is
    a wildcard (upstream SDK); an array whose entries are all undisclosed
    matches nothing. If a requirement is not fully used the result is WARN,
    because the prose spec (but not the SDK) requires that.

    Requirements with the same acceptable set are merged (which leaves the maximum
    flow unchanged) and the flow is computed with Dinic's algorithm. Inputs beyond
    :data:`MAX_LINES`, :data:`MAX_PAIRS` or the work ``budget`` (default: a fresh
    :data:`MAX_WORK`) give a SKIP with reason ``too_large``, never a PASS, and never hide
    a FAIL that a linear pass establishes: malformed requirements or lines, an item that no
    requirement accepts, and more units (in total or of one item) than the requirements
    accepting them allow are reported whatever the size.
    """
    if budget is None:
        budget = WorkBudget()
    reqs = constraint.get("items")
    if not isinstance(reqs, list) or not reqs:
        return Outcome(
            "FAIL",
            "constraint is malformed: 'items' must be a non-empty array",
            reason="malformed_constraint",
        )
    if not isinstance(line_items, list):
        return Outcome("FAIL", "the checkout has no line_items array", reason="malformed_checkout")
    if not line_items:
        return Outcome(
            "FAIL",
            "the checkout has no line items: an empty cart does not satisfy a line_items "
            "constraint (the upstream SDK rejects it the same way)",
            "items from: at least one checkout line",
            "checkout items: (none)",
            reason="empty_checkout",
        )
    # Everything up to the size limits below is one linear pass over the input, so it runs
    # whatever the size: a limit may only withhold a PASS, never a FAIL these passes establish.
    req_ids: list[str] = []
    req_sets: list[set[str] | None] = []  # None = wildcard
    req_qty: list[int] = []
    for n, req in enumerate(reqs, start=1):
        if not isinstance(req, dict):
            return Outcome(
                "FAIL", f"requirement #{n} is not an object", reason="malformed_constraint"
            )
        qty = req.get("quantity")
        if not is_int(qty) or qty <= 0:
            return Outcome(
                "FAIL",
                f"requirement #{n} has no positive integer quantity",
                reason="malformed_constraint",
            )
        acc = req.get("acceptable_items")
        if not isinstance(acc, list):
            return Outcome(
                "FAIL",
                f"requirement #{n} has no acceptable_items array",
                reason="malformed_constraint",
            )
        entries, hidden = revealed(acc)
        if not entries and not hidden:
            req_sets.append(None)
        else:
            req_sets.append(
                {e["id"] for e in entries if isinstance(e, dict) and isinstance(e.get("id"), str)}
            )
        req_ids.append(u(req.get("id", f"#{n}"), 60))
        req_qty.append(qty)
    cart: dict[str, int] = {}
    for n, li in enumerate(line_items, start=1):
        item = li.get("item") if isinstance(li, dict) else None
        sku = item.get("id") if isinstance(item, dict) else None
        qty = li.get("quantity") if isinstance(li, dict) else None
        if not isinstance(sku, str) or not is_int(qty) or qty < 1:
            return Outcome(
                "FAIL",
                f"checkout line #{n} has no item.id string or positive quantity",
                reason="malformed_checkout",
            )
        cart[sku] = cart.get(sku, 0) + qty

    def show(s: set[str] | None) -> str:
        return "any item" if s is None else _some(u(x, 60) for x in sorted(s)) or "(none)"

    wildcard = any(s is None for s in req_sets)
    accepted: set[str] = set()
    if not wildcard:
        for s in req_sets:
            assert s is not None
            accepted |= s
    unmatched = [] if wildcard else [s for s in cart if s not in accepted]
    summary = _some(f"{u(k, 60)} x{v}" for k, v in cart.items())
    if unmatched:
        return Outcome(
            "FAIL",
            "checkout item(s) not in any requirement's revealed acceptable_items: "
            + _some(u(s, 60) for s in unmatched),
            "items from: "
            + _some(
                (f"{rid}: {show(s)}" for rid, s in zip(req_ids, req_sets, strict=True)), sep="; "
            ),
            "checkout items: " + summary,
            reason="item_not_acceptable",
        )
    total_cart = sum(cart.values())
    limits = _some(
        (f"{rid} up to {qn}" for rid, qn in zip(req_ids, req_qty, strict=True)), sep=", "
    )

    def too_large(what: str) -> Outcome:
        """``too_large``, unless a linear capacity test already shows the checkout fails."""
        over = _over_capacity(cart, req_sets, req_qty)
        if over is None:
            return _too_large(what)
        return Outcome(
            "FAIL",
            f"{over}, so the checkout ({summary}) exceeds the allowed quantities ({limits}); "
            "this follows from the totals alone, without the full matching",
            limits,
            summary,
            reason="quantity_exceeded",
        )

    if len(reqs) > MAX_LINES or len(line_items) > MAX_LINES:
        return too_large(
            f"it has {len(reqs)} requirement(s) and the checkout {len(line_items)} line(s), "
            f"more than {MAX_LINES}"
        )
    if len(reqs) * len(line_items) > MAX_PAIRS:
        return too_large(
            f"{len(reqs)} requirement(s) x {len(line_items)} checkout line(s) is more than "
            f"{MAX_PAIRS} combinations"
        )
    size = len(line_items) + sum(len(r["acceptable_items"]) for r in reqs)
    if not budget.take(size):
        return too_large("the line items of this bundle need too much work in total")
    flow = _assignable(cart, req_sets, req_qty, budget)
    if flow is None:
        return too_large("matching the checkout lines to the requirements needs too much work")
    if flow < total_cart:
        return Outcome(
            "FAIL",
            f"only {flow} of {total_cart} checkout unit(s) can be assigned to the requirements "
            f"({limits}); the checkout ({summary}) exceeds the allowed quantities",
            limits,
            summary,
            reason="quantity_exceeded",
        )
    wild = [rid for rid, s in zip(req_ids, req_sets, strict=True) if s is None]
    note = (
        f"; requirement(s) {', '.join(wild)} have an empty acceptable_items array, treated as "
        "'any item' like the upstream SDK"
        if wild
        else ""
    )
    if flow < sum(req_qty):
        return Outcome(
            "WARN",
            f"all {total_cart} checkout unit(s) ({summary}) fit the requirements ({limits}), which "
            "satisfies the upstream SDK; the prose spec additionally requires every requirement "
            f"to be filled completely, and only {flow} of {sum(req_qty)} required unit(s) are "
            f"present{note}",
            reason="requirement_unfilled",
        )
    return Outcome(
        "PASS",
        f"all {total_cart} checkout unit(s) ({summary}) are assigned to requirements "
        f"({limits}){note}",
    )


def eval_amount_range(constraint: dict[str, Any], amount: dict[str, Any]) -> Outcome:
    """Evaluate ``payment.amount_range`` (min/max in minor units, currency must match)."""
    cur, mx, mn = constraint.get("currency"), constraint.get("max"), constraint.get("min")
    if not isinstance(cur, str) or not is_int(mx) or (mn is not None and not is_int(mn)):
        return Outcome(
            "FAIL",
            "constraint is malformed: needs string currency, integer max and optional integer "
            "min (minor units)",
            actual=u({k: constraint.get(k) for k in ("currency", "min", "max")}),
            reason="malformed_constraint",
        )
    lo = currency.format_minor(mn, cur) if mn is not None else "no minimum"
    expected = u(f"{lo} .. {currency.format_minor(mx, cur)}")
    actual = amount_label(amount)
    problems: list[tuple[str, str]] = []
    if amount["currency"] != cur:
        problems.append(
            (
                "currency_mismatch",
                f"currency {u(amount['currency'])} differs from the constraint currency {u(cur)}",
            )
        )
    if amount["amount"] > mx:
        problems.append(
            (
                "amount_above_max",
                f"amount {actual} exceeds the maximum {u(currency.format_minor(mx, cur))}",
            )
        )
    if mn is not None and amount["amount"] < mn:
        problems.append(
            (
                "amount_below_min",
                f"amount {actual} is below the minimum {u(currency.format_minor(mn, cur))}",
            )
        )
    if problems:
        return Outcome(
            "FAIL", "; ".join(p[1] for p in problems), expected, actual, reason=problems[0][0]
        )
    return Outcome("PASS", f"amount {actual} is within {expected}")


def eval_allowed_instruments(constraint: dict[str, Any], instrument: Any) -> Outcome:
    """Evaluate ``payment.allowed_payment_instruments`` (match by ``id``, as upstream)."""
    allowed_raw = constraint.get("allowed")
    if not isinstance(allowed_raw, list):
        return Outcome(
            "FAIL",
            "constraint is malformed: 'allowed' is not an array",
            reason="malformed_constraint",
        )
    entries, hidden = revealed(allowed_raw)
    expected = "; ".join(instrument_label(e) for e in entries) or "(none revealed)"
    if not isinstance(instrument, dict) or not isinstance(instrument.get("id"), str):
        return Outcome(
            "FAIL",
            "the closed payment mandate has no payment_instrument.id",
            reason="no_instrument",
        )
    if any(isinstance(e, dict) and e.get("id") == instrument["id"] for e in entries):
        return Outcome(
            "PASS",
            f"instrument {instrument_label(instrument)} is allowed{_hidden_note(hidden)}",
        )
    return Outcome(
        "FAIL",
        f"instrument {instrument_label(instrument)} is not among the revealed allowed "
        f"instruments ({expected}){_hidden_note(hidden)}",
        expected,
        instrument_label(instrument),
        reason="instrument_not_allowed",
    )


def eval_allowed_pisps(constraint: dict[str, Any], pisp: Any) -> Outcome:
    """Evaluate ``payment.allowed_pisps`` (all three PISP fields must match, as upstream)."""
    allowed_raw = constraint.get("allowed")
    if not isinstance(allowed_raw, list):
        return Outcome(
            "FAIL",
            "constraint is malformed: 'allowed' is not an array",
            reason="malformed_constraint",
        )
    entries, hidden = revealed(allowed_raw)
    expected = "; ".join(pisp_label(e) for e in entries) or "(none revealed)"
    if not isinstance(pisp, dict):
        return Outcome(
            "FAIL",
            "the closed payment mandate names no pisp, so it cannot match the allowed PISPs",
            expected,
            "(no pisp)",
            reason="no_pisp",
        )
    keys = ("legal_name", "brand_name", "domain_name")
    if any(isinstance(e, dict) and all(e.get(k) == pisp.get(k) for k in keys) for e in entries):
        return Outcome("PASS", f"PISP {pisp_label(pisp)} is allowed{_hidden_note(hidden)}")
    return Outcome(
        "FAIL",
        f"PISP {pisp_label(pisp)} is not among the allowed PISPs ({expected})",
        expected,
        pisp_label(pisp),
        reason="pisp_not_allowed",
    )


_RFC3339 = re.compile(
    r"(?P<y>[0-9]{4})-(?P<mo>[0-9]{2})-(?P<d>[0-9]{2})"
    r"(?:[Tt](?P<h>[0-9]{2}):(?P<mi>[0-9]{2}):(?P<s>[0-9]{2})(?:\.(?P<f>[0-9]+))?"
    r"(?P<tz>[Zz]|(?P<sign>[+-])(?P<oh>[0-9]{2}):(?P<om>[0-9]{2})))?",
    re.ASCII,
)
_UNIX_TS = re.compile(r"[0-9]{1,12}", re.ASCII)


def parse_when(value: str) -> _dt.datetime | None:
    """Parse the RFC 3339 profile accepted for dates and instants, or return None.

    Accepted: a full date ``YYYY-MM-DD`` (midnight UTC), or a date-time
    ``YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)``. Fractions beyond microseconds
    are truncated; leap second 60, a date-time without an offset, surrounding whitespace
    and every other ISO 8601 form are not accepted. The result is the same on every
    supported Python version (it does not depend on :meth:`datetime.fromisoformat`).
    """
    if not isinstance(value, str):
        return None
    m = _RFC3339.fullmatch(value)
    if m is None:
        return None
    try:
        if m["h"] is None:
            return _dt.datetime(int(m["y"]), int(m["mo"]), int(m["d"]), tzinfo=_dt.timezone.utc)
        if m["tz"] in ("Z", "z"):
            tz = _dt.timezone.utc
        else:
            oh, om = int(m["oh"]), int(m["om"])
            if oh > 23 or om > 59:
                return None
            off = _dt.timedelta(hours=oh, minutes=om)
            tz = _dt.timezone(-off if m["sign"] == "-" else off)
        micro = int((m["f"] or "0")[:6].ljust(6, "0"))
        when = _dt.datetime(
            int(m["y"]),
            int(m["mo"]),
            int(m["d"]),
            int(m["h"]),
            int(m["mi"]),
            int(m["s"]),
            micro,
            tzinfo=tz,
        )
        return when.astimezone(_dt.timezone.utc)
    except (ValueError, OverflowError):  # out-of-range field (month 13, second 60, year 0)
        return None


def parse_instant(value: str) -> int | None:
    """Parse a ``--at`` value: Unix seconds (1-12 digits) or :func:`parse_when`'s profile.

    Surrounding whitespace is ignored. Returns whole Unix seconds (fractions truncated
    towards the past), or None if the value is neither form or out of range.
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if _UNIX_TS.fullmatch(v):
        return int(v)
    when = parse_when(v)
    if when is None:
        return None
    try:
        return int(when.timestamp() // 1)
    except (OverflowError, OSError, ValueError):  # platform-dependent range limits
        return None


def eval_execution_date(constraint: dict[str, Any], execution_date: Any) -> Outcome:
    """Evaluate ``payment.execution_date`` (``not_before`` <= execution_date <= ``not_after``)."""
    nb, na = constraint.get("not_before"), constraint.get("not_after")
    if (nb is not None and not isinstance(nb, str)) or (na is not None and not isinstance(na, str)):
        return Outcome(
            "FAIL",
            "constraint is malformed: not_before / not_after must be strings",
            reason="malformed_constraint",
        )
    window = f"{u(nb or '(open)', 40)} .. {u(na or '(open)', 40)}"
    if execution_date is None:
        return Outcome(
            "PASS",
            f"no execution_date in the closed mandate (absent means immediate execution); the "
            f"upstream SDK treats this as satisfying the window {window}",
        )
    if not isinstance(execution_date, str):
        return Outcome("FAIL", "execution_date is not a string", reason="malformed_mandate")
    ex = parse_when(execution_date)
    bounds = [parse_when(b) if b else None for b in (nb, na)]
    parsed = ex is not None and all(
        b is not None for b, raw in zip(bounds, (nb, na), strict=True) if raw
    )
    shown = u(execution_date, 40)
    problems: list[tuple[str, str]] = []
    if parsed:
        assert ex is not None
        if nb and bounds[0] is not None and ex < bounds[0]:
            problems.append(
                (
                    "execution_date_before_window",
                    f"execution_date {shown} is before not_before {u(nb, 40)}",
                )
            )
        if na and bounds[1] is not None and ex > bounds[1]:
            problems.append(
                (
                    "execution_date_after_window",
                    f"execution_date {shown} is after not_after {u(na, 40)}",
                )
            )
        how = "compared as RFC 3339 instants"
    else:
        if nb and execution_date < nb:
            problems.append(
                (
                    "execution_date_before_window",
                    f"execution_date {shown} sorts before not_before {u(nb, 40)}",
                )
            )
        if na and execution_date > na:
            problems.append(
                (
                    "execution_date_after_window",
                    f"execution_date {shown} sorts after not_after {u(na, 40)}",
                )
            )
        how = (
            "not all values are RFC 3339 dates or date-times, so compared as plain strings like "
            "the upstream SDK"
        )
    if problems:
        return Outcome(
            "FAIL",
            "; ".join(p[1] for p in problems) + f" ({how})",
            window,
            shown,
            reason=problems[0][0],
        )
    return Outcome("PASS", f"execution_date {shown} is within {window} ({how})")


def eval_budget(constraint: dict[str, Any], amount: dict[str, Any]) -> Outcome:
    """Evaluate ``payment.budget`` for this payment alone (``max`` read in major units)."""
    mx, cur = constraint.get("max"), constraint.get("currency")
    if not is_number(mx) or not isinstance(cur, str):
        return Outcome(
            "FAIL",
            "constraint is malformed: needs numeric max and string currency",
            reason="malformed_constraint",
        )
    if amount["currency"] != cur:
        return Outcome(
            "FAIL",
            f"payment currency {u(amount['currency'])} differs from the budget currency {u(cur)}",
            u(cur),
            u(amount["currency"]),
            reason="currency_mismatch",
        )
    try:
        limit = currency.major_to_minor(mx, cur)
    except ArithmeticError:
        return Outcome(
            "FAIL",
            "constraint is malformed: max is not a finite number",
            reason="malformed_constraint",
        )
    _, known = currency.exponent(cur)
    assumed = "" if known else f" (exponent of {u(cur)} assumed to be 2)"
    label = budget_label(mx, cur, limit) + assumed
    if amount["amount"] > limit:
        return Outcome(
            "FAIL",
            f"this payment alone ({amount_label(amount)}) exceeds the whole budget {label}",
            label,
            amount_label(amount),
            reason="budget_exceeded",
        )
    return Outcome(
        "PASS",
        f"this payment ({amount_label(amount)}) does not exceed the budget {label} on its own; "
        "cumulative spend is not verifiable from one bundle (see PM39)",
    )


_OPERATOR = "supplied by whoever ran the verifier, not proven by this bundle"


def budget_label(mx: Any, cur: str, limit: Any) -> str:
    """``payment.budget.max`` (major units) as ``"USD 150.00"``; ``limit`` is in minor units."""
    try:
        if limit == limit.to_integral_value():
            return u(currency.format_minor(int(limit), cur))
    except (AttributeError, ArithmeticError, ValueError):
        pass
    return f"{u(cur)} {u(mx)}"


def _budget_text(mx: Any, cur: str) -> str:
    try:
        return budget_label(mx, cur, currency.major_to_minor(mx, cur))
    except (ArithmeticError, ValueError):
        return f"{u(cur)} {u(mx)}"


def eval_cumulative_budget(
    constraint: dict[str, Any], amount: dict[str, Any], prior_total: dict[str, Any] | None
) -> Outcome:
    """Evaluate ``payment.budget`` cumulatively: earlier spend plus this payment.

    ``prior_total`` (minor units) is the operator-supplied spend under the same open mandate
    before this payment; without it the result is a SKIP with reason ``history_needed``.
    """
    mx, cur = constraint.get("max"), constraint.get("currency")
    if not is_number(mx) or not isinstance(cur, str):
        return Outcome("FAIL", "budget constraint is malformed", reason="malformed_constraint")
    if prior_total is None:
        return Outcome(
            "SKIP",
            f"the budget {_budget_text(mx, cur)} limits the total of all payments under this "
            "mandate; "
            "what was already spent before this payment is not in the bundle, so whether this "
            "payment stays within the budget cannot be shown (re-run with --prior-total "
            "MINOR_UNITS CURRENCY; API: history.prior_total)",
            reason="history_needed",
        )
    try:
        limit = currency.major_to_minor(mx, cur)
    except ArithmeticError:
        return Outcome("FAIL", "budget max is not a finite number", reason="malformed_constraint")
    if amount["currency"] != cur:
        # The agent's payment itself is in another currency: a violation shown by the bundle.
        return Outcome(
            "FAIL",
            f"this payment ({amount_label(amount)}) is not in the budget currency {u(cur)}",
            u(cur),
            u(amount["currency"]),
            reason="currency_mismatch",
        )
    if prior_total["currency"] != cur:
        # Only the operator's figure is in another currency: nothing the agent did is shown
        # to be wrong, and the two amounts cannot be added up.
        return Outcome(
            "SKIP",
            f"the earlier spend you supplied ({amount_label(prior_total)}, {_OPERATOR}) is in "
            f"{u(prior_total['currency'])}, but the budget {_budget_text(mx, cur)} is in "
            f"{u(cur)}, so the two cannot be added up and whether this payment stays within the "
            f"budget was not checked; supply the earlier total in {u(cur)} (--prior-total "
            f"MINOR_UNITS {u(cur)}; API: history.prior_total)",
            u(cur),
            u(prior_total["currency"]),
            reason="history_currency_mismatch",
        )
    total = prior_total["amount"] + amount["amount"]
    spent = {"amount": total, "currency": cur}
    label = budget_label(mx, cur, limit)
    text = (
        f"earlier spend {amount_label(prior_total)} ({_OPERATOR}) plus this payment "
        f"{amount_label(amount)} is {amount_label(spent)}"
    )
    if total > limit:
        return Outcome(
            "FAIL",
            f"{text}, which exceeds the budget {label}",
            label,
            amount_label(spent),
            reason="budget_exceeded",
        )
    return Outcome("PASS", f"{text}, within the budget {label}")


def eval_cumulative_recurrence(constraint: dict[str, Any], prior_uses: int | None) -> Outcome:
    """Evaluate ``payment.agent_recurrence.max_occurrences`` including this payment.

    Upstream rejects a payment when the uses before it already reach ``max_occurrences``.
    ``prior_uses`` is operator-supplied; without it the result is a SKIP ``history_needed``.
    """
    mx = constraint.get("max_occurrences")
    if mx is None:
        return Outcome(
            "PASS",
            "the recurrence sets no max_occurrences, so there is no occurrence count to exceed "
            "(the per-period frequency itself is not verifiable from one bundle)",
        )
    if not is_int(mx) or mx < 1:
        return Outcome("FAIL", "max_occurrences is malformed", reason="recurrence_malformed")
    if prior_uses is None:
        return Outcome(
            "SKIP",
            f"the recurrence allows at most {mx} payment(s) under this mandate; how many were "
            "already made before this one is not in the bundle, so it cannot be shown that this "
            "payment is within the limit (re-run with --prior-uses N; API: history.prior_uses)",
            reason="history_needed",
        )
    text = f"{prior_uses} earlier use(s) ({_OPERATOR}) plus this payment is {prior_uses + 1}"
    if prior_uses >= mx:
        return Outcome(
            "FAIL",
            f"{text}, more than max_occurrences {mx}",
            f"at most {mx}",
            str(prior_uses + 1),
            reason="occurrences_exceeded",
        )
    return Outcome("PASS", f"{text}, within max_occurrences {mx}")


def eval_recurrence(constraint: dict[str, Any], all_constraints: list[Any]) -> Outcome:
    """Evaluate the parts of ``payment.agent_recurrence`` checkable from one payment."""
    freq, mx = constraint.get("frequency"), constraint.get("max_occurrences")
    problems: list[tuple[str, str]] = []
    if not isinstance(freq, str) or freq not in FREQUENCIES:
        problems.append(
            (
                "recurrence_malformed",
                f"frequency {u(freq, 40)} is not one of {', '.join(FREQUENCIES)}",
            )
        )
    if mx is not None and (not is_int(mx) or mx < 1):
        problems.append(("recurrence_malformed", "max_occurrences is not a positive integer"))
    types = {ctype(c) for c in all_constraints}
    for needed in ("payment.amount_range", "payment.budget"):
        if needed not in types:
            problems.append(
                (
                    "recurrence_missing_companion",
                    f"recurrence requires a {needed} constraint (upstream SDK rule)",
                )
            )
    if problems:
        return Outcome("FAIL", "; ".join(p[1] for p in problems), reason=problems[0][0])
    occ = f", at most {mx} time(s)" if mx is not None else ""
    return Outcome(
        "PASS",
        f"recurrence {freq}{occ} is well-formed and accompanied by amount_range and budget; "
        "the occurrence count itself is not verifiable from one bundle (see PM39)",
    )


def field_problems(c: Any, n: int) -> list[str]:
    """Type problems of a known constraint's fields (per the upstream schemas)."""
    if not isinstance(c, dict):
        return [f"constraint #{n} is not an object"]
    t = c.get("type")
    if not isinstance(t, str):
        return [f"constraint #{n} has no string type"]
    out: list[str] = []
    label = f"constraint #{n} ({u(t, 60)})"

    def need(key: str, ok: bool, what: str, required: bool = True) -> None:
        if key not in c:
            if required:
                out.append(f"{label}: {key} is missing")
        elif not ok:
            out.append(f"{label}: {key} is not {what}")

    if t in ("checkout.allowed_merchants", "payment.allowed_payees",
             "payment.allowed_payment_instruments", "payment.allowed_pisps"):  # fmt: skip
        allowed = c.get("allowed")
        need("allowed", isinstance(allowed, list), "an array")
        if isinstance(allowed, list) and not all(isinstance(e, dict) for e in allowed):
            out.append(f"{label}: allowed entries must be objects")
    elif t == "checkout.line_items":
        items = c.get("items")
        need("items", isinstance(items, list) and bool(items), "a non-empty array")
        if isinstance(items, list):
            for i, req in enumerate(items):
                if not isinstance(req, dict):
                    out.append(f"{label}: items[{i}] is not an object")
                    continue
                if not isinstance(req.get("id"), str):
                    out.append(f"{label}: items[{i}].id is missing or not a string")
                if not isinstance(req.get("acceptable_items"), list):
                    out.append(f"{label}: items[{i}].acceptable_items is not an array")
                qn = req.get("quantity")
                if not is_int(qn) or qn < 1:
                    out.append(f"{label}: items[{i}].quantity is not a positive integer")
    elif t == "payment.amount_range":
        need("currency", isinstance(c.get("currency"), str), "a string")
        need("max", is_int(c.get("max")), "an integer (minor units)")
        need("min", is_int(c.get("min")), "an integer (minor units)", required=False)
    elif t == "payment.budget":
        need("currency", isinstance(c.get("currency"), str), "a string")
        need("max", is_number(c.get("max")), "a number")
    elif t == "payment.reference":
        need(
            "conditional_transaction_id",
            isinstance(c.get("conditional_transaction_id"), str),
            "a string",
        )
    elif t == "payment.agent_recurrence":
        need("frequency", isinstance(c.get("frequency"), str), "a string")
        need("max_occurrences", is_int(c.get("max_occurrences")), "an integer", required=False)
    elif t == "payment.execution_date":
        need("not_before", isinstance(c.get("not_before"), str), "a string", required=False)
        need("not_after", isinstance(c.get("not_after"), str), "a string", required=False)
    return out


def describe(constraint: Any) -> str:
    """Describe a constraint in plain words for the evidence section (never raises)."""
    try:
        return _describe(constraint)
    except Exception:  # noqa: BLE001 - evidence text must never break the report
        return f"malformed constraint {u(constraint, 80)}"


def _describe(constraint: Any) -> str:
    if not isinstance(constraint, dict):
        return f"malformed constraint {u(constraint, 80)}"
    t = ctype(constraint)
    if t in ("checkout.allowed_merchants", "payment.allowed_payees"):
        entries, hidden = revealed(constraint.get("allowed"))
        who = "merchant" if t.startswith("checkout") else "payee"
        names = "; ".join(merchant_label(e) for e in entries) or "(none revealed)"
        return f"{who} must be one of: {names}{_hidden_note(hidden)}"
    if t == "checkout.line_items":
        parts = []
        items = constraint.get("items")
        for req in items if isinstance(items, list) else []:
            if not isinstance(req, dict):
                continue
            entries, hidden = revealed(req.get("acceptable_items"))
            names = ", ".join(
                f"{u(e.get('title'), 60)} (id {u(e.get('id'), 60)})"
                for e in entries
                if isinstance(e, dict)
            )
            if not entries and not hidden:
                names = "any item"
            parts.append(
                f"line {u(req.get('id'), 40)}: up to {u(req.get('quantity'), 20)} of "
                f"{names or '(none revealed)'}{_hidden_note(hidden)}"
            )
        return "items: " + ("; ".join(parts) if parts else "(malformed or empty)")
    if t == "payment.amount_range":
        cur = constraint.get("currency")
        if isinstance(cur, str) and is_int(constraint.get("max")):
            mn = constraint.get("min")
            lo = currency.format_minor(mn, cur) if is_int(mn) else "no minimum"
            return u(
                f"amount between {lo} and {currency.format_minor(constraint['max'], cur)}", 200
            )
        return "amount range (malformed)"
    if t == "payment.allowed_payment_instruments":
        entries, hidden = revealed(constraint.get("allowed"))
        names = "; ".join(instrument_label(e) for e in entries) or "(none revealed)"
        return f"payment instrument must be one of: {names}{_hidden_note(hidden)}"
    if t == "payment.allowed_pisps":
        entries, _ = revealed(constraint.get("allowed"))
        return "PISP must be one of: " + ("; ".join(pisp_label(e) for e in entries) or "(none)")
    if t == "payment.reference":
        return (
            "payment tied to the open checkout mandate with hash "
            f"{u(constraint.get('conditional_transaction_id'), 80)}"
        )
    if t == "payment.execution_date":
        return (
            f"execution between {u(constraint.get('not_before') or '(open)', 40)} and "
            f"{u(constraint.get('not_after') or '(open)', 40)}"
        )
    if t == "payment.budget":
        return (
            f"total budget {u(constraint.get('currency'), 10)} {u(constraint.get('max'), 30)} "
            "(major units)"
        )
    if t == "payment.agent_recurrence":
        mx = constraint.get("max_occurrences")
        return f"recurring use {u(constraint.get('frequency'), 30)}" + (
            f", at most {u(mx, 20)} time(s)" if mx is not None else ""
        )
    return f"constraint of type {u(constraint.get('type'), 60)} (unknown: treated as failing)"
