"""Plain-language evidence chain and conclusion for the report.

Everything here is descriptive: values are taken from the artifacts as they
are (passed through :func:`~ap2_evidence.constraints.u`, so they are one line
and length-capped), and the wording states how far the checks proved them.
Every function is defensive about types: malformed input yields placeholder
text, never an exception.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from . import constraints as C
from . import currency
from .checks import HISTORY_OPTIONS, warn_phrase
from .constraints import error_text, q, u
from .report import (
    ARTIFACT_PARTIES,
    FAIL,
    FAILED,
    INCOMPLETE,
    NOTHING_MORE,
    PASS,
    SIGNATURE_ROLES,
    SKIP,
    VERIFIED,
    WARN,
    Report,
    group_not_verified,
    plain_text,
    short_thumbprint,
    side_effects_sentence,
    undermines,
)
from .report import derive_next_steps as _next_steps

if TYPE_CHECKING:
    from .verify import _Chain, _Receipt, _Verifier

_WORD = {PASS: "verified", FAIL: "INVALID", WARN: "verified with a warning", SKIP: "not checked"}


def _word(v: _Verifier, cid: str) -> str:
    r = v.results.get(cid)
    return _WORD.get(r.status, "?") if r is not None else "?"


def _utc(ts: Any) -> str:
    from .verify import _utc as fmt

    return fmt(ts)


def _s(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _kid_text(kid: Any) -> str:
    """'key id 'x'' or 'no key id' (never a Python None or an empty quote)."""
    if isinstance(kid, str) and kid.strip():
        return f"key id {q(kid, 60)}"
    return "no key id"


def _delegation(v: _Verifier, ch: _Chain) -> dict[str, Any] | None:
    if ch.unavailable == "B02":
        return None
    if not ch.segments:
        return {"summary": f"unreadable ({ch.prefix}01 failed)", "structure": "unreadable"}
    root = ch.segments[0].jws
    kid = root.header.get("kid")
    iss = root.payload.get("iss")
    issuer = f"issuer {q(iss, 80)}, " if isinstance(iss, str) else ""
    sig = _word(v, f"{ch.prefix}03")
    signer = v.signers.get(f"{ch.prefix}03")
    signer_txt = f", key {short_thumbprint(signer.key.thumbprint)}" if signer else ""
    out: dict[str, Any] = {
        "issuer_kid": u(kid, 80) if isinstance(kid, str) else None,
        "issuer_iss": u(iss, 120) if isinstance(iss, str) else None,
        "issuer_signature": sig,
        "issuer_key_thumbprint": signer.key.thumbprint if signer else None,
    }
    if ch.n == 2:
        thumb = ch.agent_key.thumbprint if ch.agent_key else None
        out.update(
            structure="open+closed",
            agent_key_thumbprint=thumb,
            key_binding=_word(v, f"{ch.prefix}08"),
        )
        out["summary"] = (
            f"open mandate signed by the mandate issuer ({issuer}{_kid_text(kid)}"
            f"{signer_txt}; signature {sig}), delegating to agent key "
            f"{short_thumbprint(thumb) if thumb else '(none valid)'}; closed mandate signed by "
            f"that agent key: {out['key_binding']}"
        )
    elif ch.n == 1:
        out.update(structure="direct", agent_key_thumbprint=None, key_binding=None)
        out["summary"] = (
            f"directly signed closed mandate (human present; {issuer}{_kid_text(kid)}"
            f"{signer_txt}; signature {sig}); no agent delegation"
        )
    else:
        out.update(structure=f"{ch.n} segments", agent_key_thumbprint=None, key_binding=None)
        out["summary"] = f"{ch.n}-segment delegation chain (not verified: outside AP2 v0.2)"
    return out


def _authorised(ch: _Chain) -> list[str] | None:
    o = ch.open
    if o is None:
        return None
    out: list[str] = []
    cons = o.get("constraints")
    if isinstance(cons, list):
        out.extend(C.describe(c) for c in cons)
    elif cons is not None:
        out.append(f"malformed constraints member {u(cons, 80)}")
    if ch.hidden_constraints:
        out.append(
            f"{ch.hidden_constraints} constraint(s) withheld (not disclosed; see {ch.prefix}22)"
        )
    if ch.withheld_open:
        out.append(
            f"possibly withheld claims: {'; '.join(ch.withheld_open[:3])} (see {ch.prefix}22)"
        )
    for k in o:
        if k in ("vct", "constraints", "cnf", "iat", "exp"):
            continue
        val = o[k]
        if k == "payee":
            text = C.merchant_label(val)
        elif k == "payment_amount":
            text = C.amount_label(val)
        elif k == "payment_instrument":
            text = C.instrument_label(val)
        else:
            text = u(val, 120)
        out.append(f"pre-set {u(k, 40)}: {text}")
    return out


def checkout_total(p: dict[str, Any]) -> dict[str, Any] | None:
    """The checkout's ``totals[type=total]`` as an Amount, if readable."""
    cur = p.get("currency")
    totals = p.get("totals")
    if not currency.is_currency_code(cur) or not isinstance(totals, list):
        return None
    entries = [t for t in totals if isinstance(t, dict) and t.get("type") == "total"]
    if len(entries) != 1 or not C.is_int(entries[0].get("amount")):
        return None
    return {"amount": entries[0]["amount"], "currency": cur}


def _purchase(v: _Verifier) -> dict[str, Any] | None:
    p = v.checkout_payload
    if p is None:
        return None
    merchant = p.get("merchant")
    out: dict[str, Any] = {
        "merchant": C.merchant_label(merchant) if isinstance(merchant, dict) else None,
        "checkout_id": u(p["id"], 80) if isinstance(p.get("id"), str) else None,
        "status": u(p["status"], 40) if isinstance(p.get("status"), str) else None,
        "items": [],
        "total": None,
        "total_minor": None,
        "merchant_signature": _word(v, "CM32"),
    }
    cur = p.get("currency")
    lines = p.get("line_items")
    if isinstance(lines, list):
        for li in lines[:50]:
            if not isinstance(li, dict):
                continue
            raw_item = li.get("item")
            item: dict[str, Any] = raw_item if isinstance(raw_item, dict) else {}
            price = item.get("price")
            price_txt = (
                f" at {u(currency.format_minor(price, cur))} each"
                if C.is_int(price) and isinstance(cur, str)
                else ""
            )
            qty = u(li["quantity"], 20) if li.get("quantity") is not None else "(no quantity)"
            title = u(item["title"], 80) if item.get("title") is not None else "(no title)"
            ident = f"id {u(item['id'], 80)}" if item.get("id") is not None else "no id"
            out["items"].append(f"{qty} x {title} ({ident}){price_txt}")
    total = checkout_total(p)
    if total is not None:
        out["total"] = C.amount_label(total)
        out["total_minor"] = total
    if not v.ucp:
        out["note"] = "not a UCP Checkout; contents shown as far as they could be read"
    return out


def _payment(v: _Verifier) -> dict[str, Any] | None:
    c = v.pm.closed
    if c is None:
        return None
    amt = c.get("payment_amount")
    return {
        "amount": C.amount_label(amt) if amt is not None else None,
        "amount_minor": amt if isinstance(amt, dict) else None,
        "payee": C.merchant_label(c["payee"]) if c.get("payee") is not None else None,
        "instrument": (
            C.instrument_label(c["payment_instrument"])
            if c.get("payment_instrument") is not None
            else None
        ),
        "pisp": C.pisp_label(c["pisp"]) if c.get("pisp") is not None else None,
        "execution_date": u(c["execution_date"], 40) if _s(c.get("execution_date")) else None,
        "transaction_id": u(c["transaction_id"], 80) if _s(c.get("transaction_id")) else None,
    }


def _receipt(v: _Verifier, rec: _Receipt) -> dict[str, Any] | None:
    if rec.jws is None:
        if rec.unavailable == "B02":
            return None
        return {"summary": f"unreadable ({rec.prefix}01 failed)", "status": None}
    p = rec.jws.payload
    status = p.get("status") if p.get("status") is not None else p.get("result")
    ids = (
        ("order_id",)
        if rec.kind == "checkout"
        else ("payment_id", "psp_confirmation_id", "network_confirmation_id")
    )
    out: dict[str, Any] = {
        "status": u(status, 20) if isinstance(status, str) else None,
        "iss": u(p["iss"], 120) if isinstance(p.get("iss"), str) else None,
        "iat": _utc(p["iat"]) if C.is_int(p.get("iat")) else None,
        "signature": _word(v, f"{rec.prefix}02"),
        "bound_to_mandate": _word(v, f"{rec.prefix}04"),
    }
    for k in ids:
        out[k] = u(p[k], 80) if isinstance(p.get(k), str) else None
    if status in ("Error", "error"):
        out["error"] = u(p["error"], 80) if p.get("error") not in (None, "") else None
        out["error_description"] = (
            u(p["error_description"], 200) if p.get("error_description") not in (None, "") else None
        )
    id_txt = ", ".join(f"{k} {out[k]}" for k in ids if out[k] is not None)
    when = f"at {out['iat']}" if out["iat"] else "with no issue time"
    issued = (
        f"issued by {q(out['iss'])} {when}" if out["iss"] else f"issued {when} (issuer not named)"
    )
    out["summary"] = (
        f"{out['status'] or 'no recognisable outcome'}"
        + (f", {id_txt}" if id_txt else "")
        + f"; {issued}; signature "
        f"{out['signature']}; bound to the closed mandate: {out['bound_to_mandate']}"
    )
    if "error" in out:
        out["summary"] += "; " + error_text(p).replace("reports an error", "error", 1)
    return out


def _timeline(v: _Verifier) -> list[dict[str, Any]]:
    events: list[tuple[int, str]] = []

    def add(ts: Any, what: str) -> None:
        if C.is_int(ts):
            events.append((ts, what))

    for ch in (v.cm, v.pm):
        if not ch.segments:
            continue
        for i, seg in enumerate(ch.segments):
            mand = ch.mandates[i] if i < len(ch.mandates) else None
            state = "open" if (ch.n == 2 and i == 0) else "closed"
            label = f"{state} {ch.kind} mandate"
            pl = seg.jws.payload
            if state == "closed" and ch.n == 2:
                add(pl.get("iat"), f"{label} signed by the agent")
            else:
                add(pl.get("iat"), f"{label} signed")
            add(pl.get("exp"), f"{label}: signature expires")
            if isinstance(mand, dict):
                add(mand.get("iat"), f"{label}: issued")
                add(mand.get("exp"), f"{label}: expires")
    if isinstance(v.checkout_payload, dict):
        add(v.checkout_payload.get("iat"), "merchant's checkout signed")
        add(v.checkout_payload.get("exp"), "merchant's checkout expires")
    for rec in (v.cr, v.pr):
        if rec.jws is not None:
            add(rec.jws.payload.get("iat"), f"{rec.kind.capitalize()} Receipt issued")
    events.sort(key=lambda e: e[0])
    return [{"time": _utc(ts), "unix": ts, "event": what} for ts, what in events]


def _safe(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001 - one broken part must not hide the rest
        return None


_PROV_WORDS = {
    "trusted": "pinned by the person running the tool",
    "bundle": "taken from inside the file",
    "mandate": "the agent key named in the user's open mandate",
}


def _keys(v: _Verifier) -> list[dict[str, Any]]:
    """Every key that verified a signature, once each, with what it verified."""
    keys: dict[str, dict[str, Any]] = {}

    def add(thumb: str, role: str, what: str, prov: str | None, ok: bool = True) -> None:
        k = keys.setdefault(
            thumb,
            {
                "role": role,
                "thumbprint": thumb,
                "used_for": [],
                "failed_for": [],
                "provenance": None,
            },
        )
        member = "used_for" if ok else "failed_for"
        if what not in k[member]:
            k[member].append(what)
        if prov and k["provenance"] is None:
            k["provenance"] = _PROV_WORDS.get(prov, prov)

    for ch in (v.cm, v.pm):
        e = v.signers.get(f"{ch.prefix}03")
        if e is not None and v.status(f"{ch.prefix}03") == PASS:
            add(e.key.thumbprint, "mandate issuer", f"the open {ch.kind} mandate", e.provenance)
        if ch.agent_key is not None and ch.n == 2:
            st = v.status(f"{ch.prefix}08")
            if st in (PASS, FAIL):
                add(
                    ch.agent_key.thumbprint,
                    "agent",
                    f"the closed {ch.kind} mandate",
                    "mandate",
                    ok=st == PASS,
                )
    for cid, what in (
        ("CM32", "the checkout JWT"),
        ("CR02", "the Checkout Receipt"),
        ("PR02", "the Payment Receipt"),
    ):
        e = v.signers.get(cid)
        if e is not None and v.status(cid) == PASS:
            add(e.key.thumbprint, SIGNATURE_ROLES[cid], what, e.provenance)
    return list(keys.values())


def _bundle_note(v: _Verifier) -> bool:
    b = v.bundle
    return isinstance(b, dict) and isinstance(b.get("note"), str) and bool(b["note"].strip())


def build_evidence(v: _Verifier) -> dict[str, Any]:
    """Build the structured evidence chain from a finished verification."""
    return {
        "delegation": {
            "checkout": _safe(_delegation, v, v.cm),
            "payment": _safe(_delegation, v, v.pm),
        },
        "keys": _safe(_keys, v) or [],
        **({"note": u(v.bundle["note"], 2000)} if _bundle_note(v) else {}),
        "authorised": {"checkout": _safe(_authorised, v.cm), "payment": _safe(_authorised, v.pm)},
        "purchase": _safe(_purchase, v),
        "payment": _safe(_payment, v),
        "receipts": {"checkout": _safe(_receipt, v, v.cr), "payment": _safe(_receipt, v, v.pr)},
        "timeline": _safe(_timeline, v) or [],
    }


_PROVEN: list[tuple[tuple[str, ...], tuple[str, ...], str]] = [
    (("CM03", "PM03"), (), "the mandate issuer signed the user's instructions"),
    (
        ("CM08", "PM08"),
        (),
        "both approvals were signed by the agent key the user's instructions name",
    ),
    (("CM09", "PM09"), (), "each approval belongs to the user's instructions shown"),
    (("CM31",), (), "the agent's approval covers exactly the merchant's checkout shown"),
    (("CM32",), (), "the merchant signed the checkout"),
    (("PM30",), (), "the payment is for this checkout"),
    (("PM31",), (), "the payment authorisation is tied to the checkout authorisation"),
    (
        ("XC01", "XC02"),
        ("XC02", "PM33", "CM34"),
        "the amount and payee match the checkout total and merchant",
    ),
    (("CR02", "CR04"), ("CR07",), "the merchant signed a Checkout Receipt for this mandate"),
    (
        ("PR02", "PR04"),
        ("PR07",),
        "the payment processor signed a Payment Receipt for this mandate",
    ),
]
"""(checks that must PASS, checks whose WARN contradicts it, what it shows)."""


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _short_name(m: Any) -> str | None:
    """A merchant's name (else website, else id), one line and capped."""
    if not isinstance(m, dict):
        return None
    for k in ("name", "website", "id"):
        val = m.get(k)
        if isinstance(val, str) and val.strip():
            return u(val, 80)
    return None


def _differs(payee: dict[str, Any], merchant: dict[str, Any]) -> bool:
    """True if a member present in both (id, name, website) has different values."""
    return any(
        k in payee and k in merchant and payee.get(k) != merchant.get(k)
        for k in ("id", "name", "website")
    )


def _payee_phrase(v: _Verifier) -> tuple[str | None, str | None]:
    """(who was paid, an extra sentence if the agent-named payee differs from the merchant).

    The merchant-signed checkout is preferred over the payee in the agent-signed payment
    mandate; a difference between them is stated explicitly, never hidden.
    """
    merchant = (v.checkout_payload or {}).get("merchant")
    closed = v.pm.closed or {}
    payee = closed.get("payee")
    m_name = _short_name(merchant)
    p_name = _short_name(payee)
    signed = "signed checkout" if v.status("CM32") == PASS else "checkout"
    if m_name is None:
        if p_name is None:
            return None, None
        return f"{q(p_name, 80)} (as named by the agent's payment mandate)", None
    extra = None
    if isinstance(payee, dict) and isinstance(merchant, dict) and _differs(payee, merchant):
        extra = (
            "Note that the agent's payment mandate describes the payee as "
            f"{C.merchant_label(payee)}, which differs from the merchant in the merchant's own "
            f"{signed} ({C.merchant_label(merchant)})."
        )
    return m_name, extra


NOT_PROCESSED = "nothing in this bundle shows it was processed"


def _payment_sentence(v: _Verifier, report: Report) -> tuple[str | None, str | None]:
    """('The agent paid USD 199.00 to Demo Merchant for checkout ...', payee-difference note).

    "paid" is used only when an authentic Success Payment Receipt for this payment exists;
    otherwise the sentence says the agent approved the payment and that nothing shows it
    was processed.
    """
    pay = _safe(_payment, v) or {}
    pur = _safe(_purchase, v) or {}
    amount = pay.get("amount")
    if not amount:
        return None, None
    who, extra = _payee_phrase(v)
    target = ""
    if who:
        target += f" to {who}"
    if pur.get("checkout_id"):
        target += f" for checkout {q(pur['checkout_id'], 60)}"
        if v.cm.n == 2 and v.status("CM08") == FAIL:
            # The checkout approval is not the agent's: never imply that it is.
            cm08 = next((c.reason for c in report.checks if c.id == "CM08"), None)
            target += (
                " (that checkout was approved with a key that is not the agent key the user "
                "authorised)"
                if cm08 == "signature_invalid"
                else " (that checkout's approval is not shown to come from the agent key the "
                "user authorised)"
            )
    if v.pm.n == 2 and v.status("PM08") != PASS:
        # The agent's approval is not established: say what the documents claim, without
        # attributing the payment to the agent.
        reason = next((c.reason for c in report.checks if c.id == "PM08"), None)
        if v.status("PM08") == FAIL and reason == "signature_invalid":
            how = "approved with a key that is not the agent key the user authorised"
        elif v.status("PM08") == FAIL:
            how = "whose approval is not shown to come from the agent key the user authorised"
        else:
            how = "whose approval by the agent key the user authorised could not be checked"
        return f"{CONCERNED}{amount}{target}, {how}.", extra
    subject = "the agent" if v.pm.n == 2 else "the directly signed payment mandate"
    processed = report.receipt_says("payment") == "success"
    verb = "paid" if processed else "approved a payment of"
    text = f"{subject} {verb} {amount}{target}"
    # only a Payment Receipt that counts shows that the payment was processed
    if not processed and report.outcome not in ("declined", "conflicting"):
        text += f"; {NOT_PROCESSED}"
    return _cap(text) + ".", extra


CONCERNED = "The payment concerned: "


def _constraint(ch: Any, ctype: str) -> dict[str, Any]:
    o = ch.open
    cons = o.get("constraints") if isinstance(o, dict) else None
    if isinstance(cons, list):
        for c in cons:
            if isinstance(c, dict) and c.get("type") == ctype:
                return c
    return {}


def _amount_clauses(v: _Verifier, report: Report, prim: list[str]) -> tuple[list[str], set[str]]:
    """Plain clauses for amount-related primary failures, and the check IDs they cover."""
    clauses: list[str] = []
    used: set[str] = set()
    if "PM32" in prim:
        reason = report.check("PM32").reason
        rng = _constraint(v.pm, "payment.amount_range")
        cur = rng.get("currency")
        clause = None
        if isinstance(cur, str):
            if reason == "amount_above_max" and C.is_int(rng.get("max")):
                limit = C.amount_label({"amount": rng["max"], "currency": cur})
                clause = f"the user's mandate allowed at most {limit}"
            elif reason == "amount_below_min" and C.is_int(rng.get("min")):
                limit = C.amount_label({"amount": rng["min"], "currency": cur})
                clause = f"the user's mandate required at least {limit}"
            elif reason == "currency_mismatch":
                clause = f"the user's mandate allowed only payments in {u(cur, 10)}"
        if clause:
            clauses.append(clause)
            used.add("PM32")
    if "XC01" in prim and report.check("XC01").reason == "amount_mismatch":
        total = (_safe(_purchase, v) or {}).get("total")
        if total:
            signed = "signed checkout" if v.status("CM32") == PASS else "checkout"
            clauses.append(f"the merchant's {signed} was for {total}")
            used.add("XC01")
    return clauses, used


# --------------------------------------------------------------------------- receipts


def _receipt_outcome_text(v: _Verifier, report: Report) -> str | None:
    """The finding sentence for a declined or conflicting outcome, naming each receipt."""
    outcome = report.outcome
    if outcome == "declined":
        return (
            "The Payment Receipt is authentic and says the payment was DECLINED; nothing here "
            "shows money moved."
        )
    if outcome != "conflicting":
        return None
    pay = report.receipt_says("payment")
    rec = (report.evidence.get("receipts") or {}).get("payment") or {}
    conf = any(rec.get(k) for k in ("psp_confirmation_id", "network_confirmation_id"))
    conf_txt = " (confirmation id present)" if conf else ""
    if pay == "success":
        return (
            f"The Payment Receipt says the payment SUCCEEDED{conf_txt}; the Checkout Receipt "
            "says the order FAILED. Money may have moved without an order."
        )
    return (
        "The Payment Receipt says the payment was DECLINED; the Checkout Receipt says the order "
        "SUCCEEDED. The order may have been placed without payment."
    )


NO_RECEIPT = "no receipt in this bundle can be relied on to say what happened to it"


def _unknown_receipts_clause(report: Report) -> str:
    """For outcome ``unknown``: what the receipts that count say, never 'no receipt' if one does."""
    pay = report.receipt_says("payment")
    chk = report.receipt_says("checkout")
    if pay == "success":
        return (
            "and the payment processor signed a receipt saying it succeeded, but the Checkout "
            "Receipt in this bundle cannot be relied on to say what happened to the order"
        )
    if pay is None and chk is not None:
        said = "the order succeeded" if chk == "success" else "the order failed"
        return (
            f"and the merchant signed a receipt saying {said}, but no Payment Receipt in this "
            "bundle can be relied on to say what happened to the payment"
        )
    return "but " + NO_RECEIPT


def _unknown_receipts_meaning(report: Report) -> str:
    """The 'What this means' counterpart of :func:`_unknown_receipts_clause`."""
    pay = report.receipt_says("payment")
    chk = report.receipt_says("checkout")
    if pay == "success":
        return (
            "the payment processor confirmed the payment, but the Checkout Receipt cannot be "
            "relied on to say what happened to the order"
        )
    if pay is None and chk is not None:
        said = "confirmed the order" if chk == "success" else "says the order failed"
        return (
            f"the merchant's Checkout Receipt {said}, but no Payment Receipt in this bundle can "
            "be relied on to say what happened to the payment"
        )
    return "no receipt in this bundle can be relied on to say what happened to the payment"


def _receipt_steps(report: Report) -> list[str]:
    if report.outcome != "conflicting":
        return []
    if report.receipt_says("payment") == "success":
        return [
            "Ask the merchant what happened to the order and whether a refund was issued for "
            "the payment the Payment Receipt confirms."
        ]
    return [
        "Ask the merchant whether the order was delivered without payment, and the payment "
        "processor whether a later payment attempt succeeded."
    ]


# --------------------------------------------------------------------------- warnings


def _warnings(report: Report) -> list[Any]:
    return [c for c in report.checks if c.status == WARN]


def _listed_warnings(report: Report) -> list[Any]:
    """The warnings to list for the reader.

    A decline (PR05 / CR05 ``declined``) of a receipt that counts is the headline of the
    finding already, so it is not listed again as a warning to review.
    """
    return [c for c in _warnings(report) if not _headline_decline(report, c)]


def _headline_decline(report: Report, c: Any) -> bool:
    if c.id not in ("PR05", "CR05") or c.reason not in ("declined", "rejected"):
        return False
    return report.receipt_counts("payment" if c.id == "PR05" else "checkout")


def _warning_clause(report: Report) -> str:
    warns = _listed_warnings(report)
    if not warns:
        return ""
    phrases: list[str] = []
    for c in warns:
        phrase = warn_phrase(c.id, c.reason)
        if phrase not in phrases:
            phrases.append(phrase)
    more = f"; and {len(phrases) - 3} more" if len(phrases) > 3 else ""
    return f", with {_plural(len(phrases), 'warning')} to review: " + "; ".join(phrases[:3]) + more


# --------------------------------------------------------------------------- history


def _history(v: _Verifier) -> dict[str, Any]:
    h = getattr(v, "history", None)
    return h if isinstance(h, dict) else {}


def _pm39_overrides(v: _Verifier, report: Report) -> None:
    """Concrete wording for PM39 (cumulative budget / use limit), set on the report."""
    try:
        c = report.check("PM39")
    except KeyError:
        return
    h = _history(v)
    closed = v.pm.closed or {}
    amt = closed.get("payment_amount")
    budget = _constraint(v.pm, "payment.budget")
    rec = _constraint(v.pm, "payment.agent_recurrence")
    need = []
    if budget:
        need.append("prior_total")
    if rec.get("max_occurrences") is not None:
        need.append("prior_uses")
    if c.status == FAIL and c.reason == "budget_exceeded" and "prior_total" in h:
        prior = C.amount_label(h["prior_total"])
        this = C.amount_label(amt)
        limit = c.expected or "whole"  # the budget as "USD 150.00" (see constraints.budget_label)
        report.plain_overrides["PM39"] = (
            f"Together with the {prior} you said was already spent, this payment of {this} "
            f"exceeds the user's {limit} budget."
        )
        report.action_overrides["PM39"] = (
            f"Confirm the earlier spend of {prior} with the mandate issuer's or payment "
            "processor's records; if it is right, ask the agent provider why its agent approved "
            "a payment that takes the total over the user's budget."
        )
    elif c.status == FAIL and c.reason == "occurrences_exceeded" and "prior_uses" in h:
        mx = rec.get("max_occurrences")
        n = h["prior_uses"]
        report.plain_overrides["PM39"] = (
            f"Together with the {n} earlier payment(s) you said were made under this mandate, "
            f"this payment exceeds the {mx} payment(s) the user allowed."
        )
        report.action_overrides["PM39"] = (
            f"Confirm the {n} earlier payment(s) with the mandate issuer's or payment "
            "processor's records; if that is right, ask the agent provider why its agent made "
            "one payment too many."
        )
    elif c.reason == "history_currency_mismatch":
        cur = budget.get("currency")
        given = (h.get("prior_total") or {}).get("currency")
        if isinstance(cur, str) and isinstance(given, str):
            report.plain_overrides["PM39"] = (
                f"The earlier total you supplied is in {u(given, 10)}, but the user's budget is "
                f"in {u(cur, 10)}, so the two cannot be added up."
            )
            report.action_overrides["PM39"] = (
                f"Supply the earlier total in {u(cur, 10)} with --prior-total MINOR_UNITS "
                f"{u(cur, 10)} and check again."
            )
    missing = [k for k in need if k not in h]
    given = [k for k in need if k in h]
    hints = []
    if given:
        hints.append(
            "this result rests on "
            + " and ".join(HISTORY_OPTIONS[k].split()[0] for k in given)
            + " as given by whoever ran the verifier; check the figure(s) against the mandate "
            "issuer's or payment processor's records"
        )
    if missing:
        hints.append(
            "run the verifier again with " + " and ".join(HISTORY_OPTIONS[k] for k in missing)
        )
        if c.reason == "history_needed":
            what = {
                "prior_total": "what was already spent",
                "prior_uses": "how many payments were already made",
            }
            report.action_overrides["PM39"] = (
                "Get "
                + " and ".join(what[k] for k in missing)
                + " under this mandate from the mandate issuer's or payment processor's records, "
                "and check again with " + " and ".join(HISTORY_OPTIONS[k] for k in missing) + "."
            )
    if hints and c.status != PASS:
        report.hint_overrides["PM39"] = "; ".join(hints)


def _history_note(v: _Verifier, report: Report) -> str | None:
    """A note when history figures were given but the mandate has no limit that needs them."""
    h = _history(v)
    if not h:
        return None
    budget = _constraint(v.pm, "payment.budget")
    rec = _constraint(v.pm, "payment.agent_recurrence")
    unused = []
    if "prior_total" in h and not budget:
        unused.append("--prior-total")
    if "prior_uses" in h and rec.get("max_occurrences") is None:
        unused.append("--prior-uses")
    if not unused:
        return None
    return (
        f"Note: the figure(s) given with {' and '.join(unused)} were not needed, because the "
        "user's mandate sets no budget or use limit that they apply to."
    )


# --------------------------------------------------------------------------- disclosure


_ALTERED_LIST = {
    "CM34": "the list of allowed merchants",
    "CM35": "the list of allowed items",
    "PM32": "the allowed amount range",
    "PM33": "the list of allowed payees",
    "PM34": "the list of allowed cards or accounts",
}


def _altered_overrides(report: Report) -> None:
    """Name which part of the instructions was changed, where a consequence makes it clear."""
    for primary in ("CM04", "PM04"):
        try:
            c = report.check(primary)
        except KeyError:
            continue
        if c.status != FAIL or c.reason not in ("unreferenced_disclosure", "duplicate_disclosure"):
            continue
        parts = [
            _ALTERED_LIST[d.id] for d in report.consequences_of(primary) if d.id in _ALTERED_LIST
        ]
        words = "shopping" if primary == "CM04" else "payment"
        if parts:
            report.plain_overrides[primary] = (
                f"Part of the user's {words} instructions ({_and(parts)}) was changed after they "
                "were signed."
            )


# --------------------------------------------------------------------------- finding


def _finding(v: _Verifier, report: Report) -> str:
    verdict = report.verdict
    pay, extra = _payment_sentence(v, report)
    receipts = _receipt_outcome_text(v, report)
    parts: list[str] = []
    if verdict == VERIFIED:
        if receipts:
            parts.append(receipts)
            if pay:
                parts.append(pay)
            wc = _warning_clause(report)
            if wc:
                parts.append("Every required check passed" + wc + ".")
        elif report.outcome == "success":
            if pay:
                parts.append(pay)
            parts.append(
                "Every required check passed: the payment is within the limits the user set, "
                "matches the merchant's checkout, and both the merchant and the payment "
                "processor signed receipts saying it succeeded" + _warning_clause(report) + "."
            )
        else:
            if pay:
                parts.append(pay)
            parts.append(
                "Every required check passed: the payment is within the limits the user set and "
                "matches the merchant's checkout, "
                + _unknown_receipts_clause(report)
                + _warning_clause(report)
                + "."
            )
    elif verdict == INCOMPLETE:
        if pay and pay.startswith(CONCERNED):
            parts.append(pay)
        elif pay:
            parts.append("According to the bundle, " + pay[0].lower() + pay[1:])
        if receipts:
            parts.append(receipts)
        n = len(report.not_verified())
        parts.append(
            f"{_plural(n, 'required check')} could not be done, so it is not yet established "
            "that this payment was authorised."
        )
    else:
        prim = [c.id for c in report.primary_failures()]
        clauses, used = _amount_clauses(v, report, prim)
        rest = [report.check(cid) for cid in prim if cid not in used]
        if clauses:
            if pay:
                parts.append(pay)
            parts.append(_cap(", and ".join(clauses)) + ".")
            shown = rest[:1]
        else:
            shown = rest[:2]
        parts.extend(plain_text(c, report) for c in shown)
        side = side_effects_sentence(report)
        if side:
            parts.append(side)
        if not clauses and pay:
            parts.append(pay if pay.startswith(CONCERNED) else CONCERNED + pay[0].lower() + pay[1:])
        left = len(rest) - len(shown)
        if left > 0:
            parts.append(
                f"{_plural(left, 'further independent problem')} "
                f"{'is' if left == 1 else 'are'} listed under Broken links."
            )
        if receipts:
            parts.append(receipts)
    if extra:
        parts.append(extra)
    return " ".join(parts)


def _gaps(report: Report) -> list[str]:
    """What could not be checked, in plain words (from the root required SKIPs)."""
    roots, _groups = group_not_verified(report, report.not_verified())
    gaps: list[str] = []
    signers: list[str] = []
    for n in roots:
        c = report.check(n["id"])
        if c.id == "B02" and c.reason == "missing_artifact":
            names = [
                name for m, (name, _p) in ARTIFACT_PARTIES.items() if report.inputs.get(m) is None
            ]
            if names:
                gaps.append(f"{_and(names)} {'is' if len(names) == 1 else 'are'} missing")
                continue
        if c.reason in _KEY_REASONS and c.id in SIGNATURE_ROLES:
            role = SIGNATURE_ROLES[c.id]
            if role not in signers:
                signers.append(role)
            continue
        text = plain_text(c, report)
        gaps.append(text[:1].lower() + text[1:].rstrip("."))
    if signers:
        whose = _and([f"the {s}'s" for s in signers])
        plural = "s" if len(signers) > 1 else ""
        gaps.append(f"{whose} signature{plural} could not be checked with a key")
    return gaps


_KEY_REASONS = ("no_key", "x5c_unsupported", "key_not_pinned")

CONTRADICTING_SKIPS = frozenset({"reference_unverifiable_withheld"})
"""Required-SKIP reasons that are themselves a mismatch: 'nothing contradicts' must not be said."""


def _proven(v: _Verifier, report: Report) -> list[str]:
    warned = {c.id for c in _warnings(report)}
    return [
        t
        for ids, contra, t in _PROVEN
        if all(v.status(i) == PASS for i in ids) and not (warned & set(contra))
    ]


def _meaning(v: _Verifier, report: Report) -> str:
    verdict = report.verdict
    if verdict == FAILED:
        text = "This bundle cannot be used to show that the payment was authorised."
        und = undermines(report)
        if und:
            text += " " + und
    elif verdict == INCOMPLETE:
        gaps = _gaps(report)
        contra = any(
            c.status == SKIP and c.required and c.reason in CONTRADICTING_SKIPS
            for c in report.checks
        )
        if contra:
            text = (
                "The bundle does not show that this payment was authorised, and one link points "
                "the wrong way: "
                + "; ".join(gaps)
                + ". Only the checkout instructions exactly as issued, with all of their parts, "
                "can settle which it is."
            )
        else:
            text = (
                "Nothing in the bundle contradicts the claim that this payment was authorised, "
                "but the bundle does not establish it yet"
                + (": " + "; ".join(gaps) + "." if gaps else ".")
            )
        proven = _proven(v, report)
        if proven:
            text += " Already shown: " + "; ".join(proven) + "."
    else:
        who = (
            "the agent the user authorised"
            if (v.pm.agent_key or v.cm.agent_key) is not None
            else "the user's directly signed mandate"
        )
        kt = report.key_trust
        if report.outcome == "declined":
            confirmed = (
                "the Payment Receipt is authentic and says the payment was DECLINED, so nothing "
                "here shows money moved"
            )
        elif report.outcome == "conflicting":
            confirmed = "the two receipts disagree about what happened (see the finding)"
        elif report.outcome == "success":
            confirmed = "the merchant and the payment processor confirmed them"
        else:
            confirmed = _unknown_receipts_meaning(report)
        if kt == "pinned":
            lead = "Checked with the keys you pinned, the bundle shows"
        elif kt == "none":
            lead = "Without any key of the mandate issuer, merchant or processor, the bundle shows"
        elif kt == "mixed":
            lead = (
                "Checked with keys of which only some were pinned by you, the documents are "
                "consistent: they show"
            )
        else:
            lead = (
                "Checked with keys that came inside the file (none of them pinned by you), the "
                "documents are consistent: they show"
            )
        text = (
            f"{lead} that {who} approved exactly this checkout and this payment, within every "
            f"limit the user set, and that {confirmed}. It does not show who the signing keys "
            "belong to, whether the goods were delivered, or what other payments were made "
            "under the same mandate."
        )
        said: list[str] = []
        for c in _listed_warnings(report):
            sentence = plain_text(c, report)
            if sentence not in said:
                said.append(sentence)
                text += " Warning: " + sentence
    if v.status("XC04") == WARN and verdict != VERIFIED:
        text += (
            " Note: the checkout and payment mandates were signed by different mandate-issuer "
            "keys (see XC04)."
        )
    if v.status("CM33") == WARN and verdict not in (FAILED, VERIFIED):
        text += (
            " The checkout payload is not a full UCP Checkout; only its well-typed members were "
            "used."
        )
    return text


_UNDISCLOSED = re.compile(r"presented with (\d+) undisclosed digest")


def _pm31_override(report: Report) -> None:
    """Narrowed presentation: state the count of undisclosed digests, never 'withheld' as fact."""
    try:
        c = report.check("PM31")
    except KeyError:
        return
    if c.reason != "reference_unverifiable_withheld":
        return
    m = _UNDISCLOSED.search(c.detail)
    count = f"{_plural(int(m.group(1)), 'undisclosed digest')}" if m else "undisclosed digests"
    report.plain_overrides["PM31"] = (
        "The user's payment authorisation does not match the checkout instructions as they "
        f"appear in this bundle, which have {count} (parts left out of this copy, or decoys "
        "the issuer added). That is what checkout instructions shown with some parts left out "
        "look like, and also what a payment authorisation for a different checkout looks like; "
        "this bundle cannot tell the two apart."
    )
    # Reader-facing "What you can do": plain names only (the technical locator is in the
    # check's technical detail and in the JSON hint).
    report.hint_overrides["PM31"] = (
        "ask the agent provider for the checkout instructions exactly as issued, with all of "
        "their parts, and check again: the user's payment authorisation refers to the checkout "
        "instructions as issued, so it cannot be checked against a copy with parts left out"
    )


def build_conclusion(v: _Verifier, report: Report) -> str:
    """Fill in the report's finding, meaning, next steps and notes; return the conclusion.

    The returned string (``Report.conclusion``) is the verdict followed by the finding,
    what it means and the key-trust caveat, never truncated.
    """
    notes = []
    for name, guess in v.unknown_members[:3]:
        notes.append(
            f"Note: unknown bundle member {q(name, 60)} was ignored"
            + (f" - did you mean {guess!r}?" if guess else ".")
        )
    hist = _history_note(v, report)
    if hist:
        notes.append(hist)
    _pm39_overrides(v, report)
    _pm31_override(report)
    _altered_overrides(report)
    finding = _finding(v, report)
    meaning = _meaning(v, report)
    steps = _next_steps(report)
    extra_steps = _receipt_steps(report)
    if extra_steps:
        steps = extra_steps + [s for s in steps if s not in extra_steps]
    if len(steps) > 1:
        steps = [s for s in steps if s != NOTHING_MORE]
    report.finding = finding
    report.meaning = meaning
    report.next_steps = steps
    report.notes = notes
    prefix = "".join(n + " " for n in notes)
    return f"{prefix}{report.verdict_label}. {finding} {meaning} {report.key_trust_sentence()}"


def fallback_conclusion(report: Report) -> str:
    """Minimal conclusion used if :func:`build_conclusion` itself fails."""
    s = report.summary()
    return (
        f"{report.verdict}. {s['fail']} check(s) failed and {s['skip']} were skipped; see the "
        "list of checks below (the conclusion text could not be generated for this input)."
    )
