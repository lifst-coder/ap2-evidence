"""The verification engine: turns an evidence bundle into a :class:`~ap2_evidence.report.Report`.

Each check in :data:`~ap2_evidence.checks.REGISTRY` produces exactly one
result. Checks run inside a guard so that an unexpected exception becomes a
FAIL ("could not be evaluated") instead of a crash. Every non-PASS result
carries a short machine-readable ``reason`` code.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import constraints as C
from . import currency, strictjson
from .bundle import (
    ARTIFACTS,
    BUNDLE,
    BUNDLE_VERSION,
    DOCS_URL,
    KNOWN_MEMBERS,
    MANDATE,
    ROLES,
    TRUSTED,
    InputError,
    KeyEntry,
    KeyStore,
    suggest_member,
)
from .checks import REGISTRY
from .constraints import error_text, q, u
from .jose import (
    HASH_ALGS,
    CompactJws,
    JoseError,
    PublicKey,
    hash_b64,
    load_public_jwk,
    parse_compact,
    sha256_hex,
    verify_es256,
)
from .report import FAIL, PASS, SKIP, WARN, CheckResult, Report
from .sdjwt import (
    Resolution,
    SdJwtError,
    Segment,
    fmt_path,
    mandate_items,
    mandate_root,
    parse_chain,
    resolve,
)

MAX_CHAIN_CHARS = 4 * 1024 * 1024
"""Upper bound on one chain string."""

FORMAT_URL = f"{DOCS_URL}/bundle-format.md"

_PROV_TEXT = {
    TRUSTED: "key pinned by the verifier with --trusted-keys",
    BUNDLE: "key supplied inside the bundle (self-asserted by whoever assembled it)",
    MANDATE: "key taken from the open mandate's cnf.jwk",
}

_UCP_REQUIRED = ("id", "line_items", "status", "currency", "totals", "links")
_UCP_STATUS = (
    "incomplete",
    "requires_escalation",
    "ready_for_complete",
    "complete_in_progress",
    "completed",
    "canceled",
)
_SIGNABLE_STATUS = ("incomplete", "ready_for_complete", "complete_in_progress", "completed")
"""Checkout statuses the agent may legitimately sign: upstream samples sign 'incomplete'."""
_DISC_RE = re.compile(r"disclosure #(\d+)")
_WS = re.compile(r"\s+")
_ALLOW_LIST_TYPES = (
    "checkout.allowed_merchants",
    "payment.allowed_payees",
    "payment.allowed_payment_instruments",
    "payment.allowed_pisps",
)
_RECEIPTS = ("checkout_receipt", "payment_receipt")
_ARTIFACT_FLAG = {
    "checkout_mandate": "--checkout-mandate",
    "payment_mandate": "--payment-mandate",
    "checkout_receipt": "--checkout-receipt",
    "payment_receipt": "--payment-receipt",
}


def _utc(ts: Any) -> str:
    if not C.is_number(ts):
        return f"invalid timestamp {u(ts, 40)}"
    try:
        when = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"invalid timestamp {u(ts, 40)}"
    return when.isoformat().replace("+00:00", "Z")


def _add_hint(member: str) -> str:
    return f"add {member} to the bundle (or pass {_ARTIFACT_FLAG[member]} FILE)"


def _kid_text(kid: Any) -> str:
    """How a JWS header's key id is shown: quoted, or 'no kid' when the header has none."""
    return f"kid {q(kid, 60)}" if isinstance(kid, str) and kid else "no kid"


@dataclass
class _Chain:
    kind: str
    prefix: str
    member: str
    raw: str | None = None
    unavailable: str | None = None
    segments: list[Segment] = field(default_factory=list)
    res: list[Resolution] = field(default_factory=list)
    mandates: list[dict[str, Any] | None] = field(default_factory=list)
    pick_problem: list[tuple[str, str]] = field(default_factory=list)
    agent_key: PublicKey | None = None
    closed_ok: bool = False  # closed mandate fields usable (X13 passed)
    hidden_constraints: int = 0
    withheld_open: list[str] = field(default_factory=list)
    withheld_closed: list[str] = field(default_factory=list)
    narrowing: int = 0

    @property
    def open_vct(self) -> str:
        return f"mandate.{self.kind}.open.1"

    @property
    def closed_vct(self) -> str:
        return f"mandate.{self.kind}.1"

    @property
    def other_kind(self) -> str:
        return "payment" if self.kind == "checkout" else "checkout"

    @property
    def n(self) -> int:
        return len(self.segments)

    @property
    def usable(self) -> bool:
        return self.unavailable is None and 1 <= self.n <= 2

    @property
    def open(self) -> dict[str, Any] | None:
        return self.mandates[0] if self.usable and self.n == 2 else None

    @property
    def closed(self) -> dict[str, Any] | None:
        return self.mandates[-1] if self.usable else None

    @property
    def closed_seg(self) -> Segment | None:
        return self.segments[-1] if self.usable else None

    @property
    def withholds(self) -> bool:
        """True if constraints or claims of the open mandate may be withheld."""
        return bool(self.hidden_constraints or self.withheld_open)

    def closed_iat(self) -> Any:
        """The closed mandate's signing time: KB-SD-JWT iat, or the direct mandate's iat."""
        seg = self.closed_seg
        if seg is None:
            return None
        if self.n == 2:
            return seg.jws.payload.get("iat")
        closed = self.closed or {}
        return closed.get("iat", seg.jws.payload.get("iat"))


@dataclass
class _Receipt:
    kind: str
    prefix: str
    member: str
    role: str
    raw: str | dict[str, Any] | None = None
    unavailable: str | None = None
    jws: CompactJws | None = None


def _pick(res: Resolution) -> tuple[dict[str, Any] | None, tuple[str, str] | None]:
    """The single mandate object of a segment, or the reason there is none."""
    if res.payload is None:
        return None, ("unresolvable", "the payload could not be resolved")
    items = mandate_items(res.payload)
    if not items:
        return None, (
            "no_mandate_object",
            "delegate_payload resolves to no mandate object (the mandate disclosure is missing, "
            "undisclosed or delegate_payload is not an array)",
        )
    if len(items) > 1:
        return None, (
            "multiple_mandate_objects",
            f"delegate_payload resolves to {len(items)} items; exactly one mandate object per "
            "token is required (the upstream SDK uses delegate_payload[0] and rejects several in "
            "non-terminal tokens), so this tool does not pick one",
        )
    if not isinstance(items[0], dict):
        return None, ("no_mandate_object", "delegate_payload[0] is not a mandate object")
    return items[0], None


def _in_narrowing(rel: tuple[str | int, ...], kind: str, mandate: Any) -> bool:
    """Whether an undisclosed digest can only narrow what the mandate allows.

    Only a whole hidden entry of the allow-list itself narrows: ``constraints[i].allowed``
    of an allow-list constraint type, or ``constraints[i].items[j].acceptable_items`` of a
    ``checkout.line_items`` constraint. A hidden property inside a revealed entry does not
    (dropping a merchant's ``id``, for example, switches matching from the id to name and
    website, which widens the match), and neither does an array of the same name elsewhere.
    """
    if kind != "elem" or not isinstance(mandate, dict) or len(rel) < 3:
        return False
    cons = mandate.get("constraints")
    i = rel[1]
    if rel[0] != "constraints" or not isinstance(cons, list) or not isinstance(i, int):
        return False
    if not 0 <= i < len(cons):
        return False
    t = C.ctype(cons[i])
    if rel[2:] == ("allowed",):
        return t in _ALLOW_LIST_TYPES
    return (
        len(rel) == 5
        and rel[2] == "items"
        and isinstance(rel[3], int)
        and rel[4] == "acceptable_items"
        and t == "checkout.line_items"
    )


def _at(node: Any, path: tuple[str | int, ...]) -> Any:
    for p in path:
        if isinstance(p, int) and isinstance(node, list) and 0 <= p < len(node):
            node = node[p]
        elif isinstance(p, str) and isinstance(node, dict):
            node = node.get(p)
        else:
            return None
    return node


def _classify(res: Resolution, cjwt_allowance: int = 0) -> tuple[int, list[str], int]:
    """Split undisclosed digests into (hidden constraints, withheld claims, narrowing ones)."""
    if res.payload is None:
        return 0, [], 0
    root = mandate_root(res.payload)
    mandate = _at(res.payload, root)
    hidden_cons, withheld, narrow = 0, [], 0
    for path, kind, n in res.hidden:
        if root and path == ("delegate_payload",):
            if kind == "elem":
                withheld.append(
                    f"{n} undisclosed item(s) in delegate_payload (a further mandate object may "
                    "be withheld)"
                )
            continue
        if path[: len(root)] != root:
            what = "claim" if kind == "sd" else "array element"
            withheld.append(
                f"{n} undisclosed {what}(s) at {fmt_path(path)}, outside the mandate object"
            )
            continue
        rel = path[len(root) :]
        if _in_narrowing(rel, kind, mandate):
            narrow += n
            continue
        if kind == "elem" and rel == ("constraints",):
            hidden_cons += n
            continue
        if kind == "sd" and rel == () and cjwt_allowance:
            used = min(n, cjwt_allowance)
            n -= used
            cjwt_allowance -= used
            if not n:
                continue
        what = "claim" if kind == "sd" else "array element"
        withheld.append(f"{n} undisclosed {what}(s) at {fmt_path(path)}")
    return hidden_cons, withheld, narrow


class _Verifier:
    def __init__(
        self,
        bundle: Any,
        trusted: KeyStore | None,
        skew: int,
        at: int | None,
        expected: dict[str, dict[str, str]] | None,
        require_pinned: bool = False,
    ) -> None:
        self.bundle = bundle
        self.skew = skew
        self.at = at
        self.require_pinned = require_pinned
        self.work = C.WorkBudget()
        self.results: dict[str, CheckResult] = {}
        self.keys = KeyStore()
        if trusted is not None:
            self.keys.entries.extend(trusted.entries)
        self.signers: dict[str, KeyEntry] = {}
        self.member_error: dict[str, str] = {}
        self.unknown_members: list[tuple[str, str | None]] = []
        self.expected: dict[str, dict[str, tuple[str, str]]] = {"checkout": {}, "payment": {}}
        for kind, vals in (expected or {}).items():
            for claim, value in vals.items():
                self.expected.setdefault(kind, {})[claim] = (value, "pinned")
        self.cm = _Chain("checkout", "CM", "checkout_mandate")
        self.pm = _Chain("payment", "PM", "payment_mandate")
        self.cr = _Receipt("checkout", "CR", "checkout_receipt", "merchant")
        self.pr = _Receipt("payment", "PR", "payment_receipt", "payment_processor")
        self.checkout_payload: dict[str, Any] | None = None
        self.checkout_jws: CompactJws | None = None
        self.ucp = False
        self.receipt_outcome: dict[str, str] = {}
        """Per receipt kind, ``success`` or ``declined`` once CR05 / PR05 established it."""
        self.history: dict[str, Any] = {}
        self.rp: dict[str, Any] = {}

    # ------------------------------------------------------------------ plumbing

    def put(
        self,
        cid: str,
        status: str,
        detail: str,
        *,
        reason: str | None = None,
        hint: str | None = None,
        expected: Any = None,
        actual: Any = None,
        required: bool | None = None,
        blocked_by: str | None = None,
        prov: str | None = None,
    ) -> None:
        d = REGISTRY[cid]
        if status != PASS and reason is None:
            if blocked_by == "B02":
                reason = "missing_artifact"
            elif blocked_by:
                reason = "blocked"
            elif status == SKIP:
                reason = "not_applicable"
            else:  # pragma: no cover - every FAIL/WARN site names its reason
                reason = "unspecified"
        self.results[cid] = CheckResult(
            id=cid,
            group=d.group,
            title=d.title,
            status=status,
            required=d.required if required is None else required,
            detail=_WS.sub(" ", detail).strip(),
            hint=_WS.sub(" ", hint).strip() if hint else None,
            expected=None if expected is None else u(expected, 600),
            actual=None if actual is None else u(actual, 600),
            spec_ref=d.spec_ref,
            blocked_by=blocked_by,
            key_provenance=prov,
            reason=None if status == PASS else reason,
        )

    def status(self, cid: str) -> str | None:
        r = self.results.get(cid)
        return r.status if r is not None else None

    def blocked(
        self, cid: str, by: str, why: str, *, required: bool = True, reason: str | None = None
    ) -> None:
        b = self.results.get(by)
        hint = b.hint if b is not None else None
        self.put(cid, SKIP, why, blocked_by=by, required=required, hint=hint, reason=reason)

    def na(self, cid: str, why: str, hint: str, reason: str = "not_applicable") -> None:
        self.put(cid, SKIP, why, required=False, hint=hint, reason=reason)

    def run(self, cid: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every check is isolated by design
            self.put(
                cid,
                FAIL,
                f"could not be evaluated: {type(exc).__name__}: {u(str(exc), 200)}",
                reason="internal_error",
                hint="the input is probably malformed in an unexpected way; if it looks valid, "
                "please report this as a bug in ap2-evidence",
            )
        if cid not in self.results:  # pragma: no cover - defensive
            self.put(cid, FAIL, "internal error: no result", reason="internal_error", hint="bug")

    def signature(self, cid: str, jws: CompactJws, role: str, where: str) -> None:
        kid = jws.header.get("kid")
        cands, note = self.keys.candidates(role, kid)
        if not cands:
            detail = f"no {role} public key was supplied"
            if isinstance(kid, str):
                detail += f" (the header names kid {q(kid, 60)})"
            detail += "; the signature was not checked."
            reason = "no_key"
            if "x5c" in jws.header:
                reason = "x5c_unsupported"
                detail += (
                    " The header carries an x5c certificate chain; x5c chain validation is not "
                    "supported in 0.1."
                )
            self.put(
                cid,
                SKIP,
                detail,
                reason=reason,
                hint=f"supply the {role} public key under keys.{role} in the bundle, or pin it "
                "with --trusted-keys",
            )
            return
        for e in cands:
            if verify_es256(jws, e.key):
                if self.require_pinned and e.provenance == BUNDLE:
                    self.put(
                        cid,
                        SKIP,
                        f"the signature verifies only under {e.label} ({_kid_text(e.key.kid)}, "
                        f"JWK thumbprint {e.key.thumbprint}), a key supplied inside the bundle; "
                        "pinned keys are required for this run, and a key chosen by whoever "
                        f"assembled the bundle does not show who signed. {note}",
                        reason="key_not_pinned",
                        required=True,
                        hint=f"pin the {role} public key with --trusted-keys (obtained from a "
                        "source you trust)",
                        prov=e.provenance,
                    )
                    return
                self.signers[cid] = e
                self.put(
                    cid,
                    PASS,
                    f"signature verifies under {e.label} ({_kid_text(e.key.kid)}, JWK "
                    f"thumbprint {e.key.thumbprint}); {_PROV_TEXT[e.provenance]}. {note}",
                    prov=e.provenance,
                )
                return
        provs = sorted({e.provenance for e in cands})
        kid_txt = (
            f"; header kid {q(kid, 60)} matches none of them"
            if isinstance(kid, str) and not any(e.key.kid == kid for e in cands)
            else ""
        )
        self.put(
            cid,
            FAIL,
            f"signature does not verify under any supplied {role} key{kid_txt} "
            f"({len(cands)} tried: {', '.join(e.label for e in cands)}): the token was altered "
            f"after signing or was signed by a different key. {note}",
            reason="signature_invalid",
            hint=f"{where}; compare the signer with the {role} key you expect",
            prov="/".join(provs),
        )

    # ------------------------------------------------------------------ main

    def verify(self) -> None:
        self.run("B01", self.check_b01)
        self.run("B03", self.check_b03)
        self.run("B02", self.check_b02)
        for chain in (self.cm, self.pm):
            self.chain_checks(chain)
        self.checkout_checks()
        self.payment_checks()
        self.cross_checks()
        for rec, chain in ((self.cr, self.cm), (self.pr, self.pm)):
            self.receipt_checks(rec, chain)
        for cid, fn in (
            ("EX01", self.ex01),
            ("EX02", self.ex02),
            ("EX03", self.ex03),
            ("EX04", self.ex04),
            ("EX05", self.ex05),
        ):
            self.run(cid, fn)

    # ------------------------------------------------------------------ expectations

    def _not_expected(self, cid: str, member: str) -> bool:
        if member in self.rp:
            return False
        self.na(
            cid,
            f"no expected {member} was given, so this was not compared",
            hint=f"pass expected={{'{member}': ...}} to verify_bundle to check it",
            reason="not_expected",
        )
        return True

    def _compare(
        self,
        cid: str,
        what: str,
        want: str,
        seen: list[tuple[str, str]],
        missing_by: str | None,
        reason: str,
    ) -> None:
        """PASS/FAIL an expectation against the values ``seen`` as (source, value)."""
        if not seen:
            self.blocked(
                cid,
                missing_by or "B02",
                f"the expected {what} cannot be compared: the artifact that states it is missing "
                "or unreadable",
            )
            return
        bad = [(src, val) for src, val in seen if val != want]
        if bad:
            self.put(
                cid,
                FAIL,
                f"expected {what} {q(want, 80)}, but "
                + "; ".join(f"{src} says {q(val, 80)}" for src, val in bad),
                reason=reason,
                expected=want,
                actual=bad[0][1],
                hint="the expectation was supplied by whoever ran the verifier",
                required=True,
            )
        else:
            self.put(
                cid,
                PASS,
                f"{what} {q(want, 80)} as expected (" + ", ".join(src for src, _ in seen) + ")",
                required=True,
            )

    def ex01(self) -> None:
        if self._not_expected("EX01", "agent_key"):
            return
        want: PublicKey = self.rp["agent_key"]
        seen = [
            (f"the open {ch.kind} mandate's cnf.jwk", ch.agent_key.thumbprint)
            for ch in (self.cm, self.pm)
            if ch.agent_key is not None
        ]
        by = next(
            (
                ch.unavailable or f"{ch.prefix}06"
                for ch in (self.cm, self.pm)
                if ch.agent_key is None and ch.n != 1
            ),
            None,
        )
        if not seen and by is None:
            self.put(
                "EX01",
                SKIP,
                "both mandates are directly signed (one segment), so no agent key is bound",
                reason="not_applicable",
                required=True,
            )
            return
        self._compare(
            "EX01", "agent key (RFC 7638 thumbprint)", want.thumbprint, seen, by,
            "agent_key_mismatch",
        )  # fmt: skip

    def ex02(self) -> None:
        if self._not_expected("EX02", "checkout_id"):
            return
        p = self.checkout_payload
        seen = [("the merchant-signed checkout", u(p["id"]))] if p and "id" in p else []
        self._compare(
            "EX02", "checkout id", self.rp["checkout_id"], seen, self._checkout_root(),
            "checkout_id_mismatch",
        )  # fmt: skip

    def _checkout_root(self) -> str:
        cm30 = self.results.get("CM30")
        if cm30 is not None and cm30.status == SKIP and cm30.blocked_by:
            return cm30.blocked_by
        return "CM30"

    def ex03(self) -> None:
        if self._not_expected("EX03", "merchant_id"):
            return
        seen: list[tuple[str, str]] = []
        m = (self.checkout_payload or {}).get("merchant")
        if isinstance(m, dict) and isinstance(m.get("id"), str):
            seen.append(("the merchant-signed checkout's merchant.id", m["id"]))
        c = self.pm.closed if self.pm.usable and self.pm.closed_ok else None
        if c is not None and isinstance(c["payee"].get("id"), str):
            seen.append(("the closed payment mandate's payee.id", c["payee"]["id"]))
        self._compare(
            "EX03", "merchant id", self.rp["merchant_id"], seen, self._checkout_root(),
            "merchant_id_mismatch",
        )  # fmt: skip

    def ex04(self) -> None:
        if self._not_expected("EX04", "total"):
            return
        want = C.amount_label(self.rp["total"])
        seen: list[tuple[str, str]] = []
        p = self.checkout_payload or {}
        totals = p.get("totals")
        entries = (
            [t for t in totals if isinstance(t, dict) and t.get("type") == "total"]
            if isinstance(totals, list)
            else []
        )
        if (
            len(entries) == 1
            and C.is_int(entries[0].get("amount"))
            and currency.is_currency_code(p.get("currency"))
        ):
            seen.append(
                (
                    "the merchant-signed checkout total",
                    C.amount_label({"amount": entries[0]["amount"], "currency": p["currency"]}),
                )
            )
        c = self.pm.closed if self.pm.usable and self.pm.closed_ok else None
        if c is not None:
            seen.append(
                ("the closed payment mandate's payment_amount", C.amount_label(c["payment_amount"]))
            )
        by = "PM13" if self.pm.usable else (self.pm.unavailable or "PM20")
        self._compare("EX04", "total", want, seen, by, "total_mismatch")

    def ex05(self) -> None:
        if self._not_expected("EX05", "require_constraints"):
            return
        missing: list[str] = []
        unknown: list[tuple[str, str]] = []
        for t in self.rp["require_constraints"]:
            ch = self.cm if t.startswith("checkout.") else self.pm
            if ch.usable and ch.n == 1:
                missing.append(t)  # a directly signed mandate has no open mandate constraints
                continue
            o = ch.open if ch.usable else None
            if o is None:
                why = ch.unavailable or (f"{ch.prefix}04" if ch.n == 2 else f"{ch.prefix}20")
                unknown.append((t, why))
                continue
            cons = o.get("constraints")
            if any(C.ctype(c) == t for c in (cons if isinstance(cons, list) else [])):
                continue
            if ch.withholds:
                unknown.append((t, f"{ch.prefix}22"))
            else:
                missing.append(t)
        if missing:
            self.put(
                "EX05",
                FAIL,
                "the open mandate(s) do not carry the required constraint type(s) "
                + ", ".join(missing),
                reason="constraint_missing",
                expected=", ".join(self.rp["require_constraints"]),
                actual="missing: " + ", ".join(missing),
                hint="segment 1 of the mandate chains; the requirement was supplied by whoever "
                "ran the verifier",
                required=True,
            )
        elif unknown:
            self.blocked(
                "EX05",
                unknown[0][1],
                "it cannot be shown that the open mandate carries "
                + ", ".join(t for t, _ in unknown)
                + " (the open mandate is missing, has no open segment or withholds constraints)",
            )
        else:
            self.put(
                "EX05",
                PASS,
                "the open mandate(s) carry every required constraint type: "
                + ", ".join(self.rp["require_constraints"]),
                required=True,
            )

    # ------------------------------------------------------------------ bundle

    def check_b01(self) -> None:
        b = self.bundle
        if not isinstance(b, dict):
            self.put(
                "B01",
                FAIL,
                f"the bundle is a JSON {type(b).__name__}, expected an object",
                reason="not_object",
                hint=f"see {FORMAT_URL}",
            )
            for m in ARTIFACTS:
                self.member_error[m] = "bundle is not an object"
            return
        problems: list[tuple[str, str]] = []
        warnings: list[str] = []
        ver = b.get("bundle_version")
        if ver is None:
            problems.append(
                ("bad_version", f"bundle_version is missing (expected {BUNDLE_VERSION!r})")
            )
        elif ver != BUNDLE_VERSION:
            problems.append(
                ("bad_version", f"bundle_version is {q(ver, 40)}, expected {BUNDLE_VERSION!r}")
            )
        for m in ARTIFACTS:
            if m in _RECEIPTS and isinstance(b.get(m), dict):
                continue  # an unsigned receipt object: reported by CR01 / PR01
            if m in b and b[m] is not None and not isinstance(b[m], str):
                problems.append(
                    ("bad_member_type", f"{m} must be a string, got {type(b[m]).__name__}")
                )
                self.member_error[m] = f"{m} is not a string"
            elif isinstance(b.get(m), str) and len(b[m]) > MAX_CHAIN_CHARS:
                problems.append(("too_long", f"{m} is longer than {MAX_CHAIN_CHARS} characters"))
                self.member_error[m] = f"{m} is too long"
        exp = b.get("expected")
        if exp is not None:
            if not isinstance(exp, dict):
                problems.append(("bad_member_type", "expected must be an object"))
            else:
                for kind, val in exp.items():
                    if kind not in ("checkout", "payment"):
                        warnings.append(
                            f"expected.{u(kind, 40)} is not a known member and was ignored"
                        )
                        continue
                    if not isinstance(val, dict):
                        problems.append(("bad_member_type", f"expected.{kind} must be an object"))
                        continue
                    for k, v in val.items():
                        if k not in ("aud", "nonce"):
                            warnings.append(
                                f"expected.{kind}.{u(k, 40)} is not a known member, ignored"
                            )
                        elif not isinstance(v, str):
                            problems.append(
                                ("bad_member_type", f"expected.{kind}.{k} must be a string")
                            )
                        elif k not in self.expected[kind]:
                            self.expected[kind][k] = (v, "bundle")
        if "note" in b and not isinstance(b["note"], str):
            problems.append(("bad_member_type", "note must be a string"))
        for name in sorted(set(b) - KNOWN_MEMBERS):
            guess = suggest_member(name)
            self.unknown_members.append((name, guess))
            warnings.append(
                f"unknown member {q(name, 60)} ignored"
                + (f" (did you mean {guess!r}?)" if guess else "")
            )
        if problems:
            self.put(
                "B01",
                FAIL,
                "the bundle is not well-formed: "
                + "; ".join(p[1] for p in problems)
                + ("; " + "; ".join(warnings) if warnings else ""),
                reason=problems[0][0],
                hint=f"see {FORMAT_URL} and schemas/bundle.schema.json",
            )
        elif warnings:
            self.put(
                "B01",
                WARN,
                "the bundle is readable; " + "; ".join(warnings),
                reason="unknown_member",
                hint=f"remove or correct the member(s); see {FORMAT_URL}",
            )
        else:
            self.put("B01", PASS, f"JSON object with bundle_version {BUNDLE_VERSION!r}")

    def check_b03(self) -> None:
        b = self.bundle
        keys = b.get("keys") if isinstance(b, dict) else None
        before = len(self.keys.entries)
        if keys is not None:
            self.keys.add_role_map(keys, BUNDLE, "keys")
        added = len(self.keys.entries) - before
        trusted = sum(1 for e in self.keys.entries if e.provenance == TRUSTED)
        if self.keys.problems:
            self.put(
                "B03",
                FAIL,
                "invalid key material: " + "; ".join(u(p, 200) for p in self.keys.problems),
                reason="invalid_key",
                hint="keys must be EC P-256 public JWKs grouped by role; private keys ('d') must "
                "never be put in a bundle",
            )
        elif keys is None and not trusted:
            self.na(
                "B03",
                "no keys in the bundle and no --trusted-keys: signatures by the mandate issuer, "
                "merchant and payment processor cannot be checked",
                hint="add keys.mandate_issuer / keys.merchant / keys.payment_processor, or pass "
                "--trusted-keys",
                reason="no_keys",
            )
        elif self.keys.warnings:
            self.put(
                "B03",
                WARN,
                f"{added} bundle key(s) and {trusted} pinned key(s) loaded; "
                + "; ".join(u(w, 200) for w in self.keys.warnings),
                reason="unknown_role",
                hint=f"key roles are {', '.join(ROLES)}",
            )
        else:
            self.put("B03", PASS, f"{added} bundle key(s) and {trusted} pinned key(s) loaded")

    def check_b02(self) -> None:
        b = self.bundle if isinstance(self.bundle, dict) else {}
        missing = [m for m in ARTIFACTS if b.get(m) is None and m not in self.member_error]
        for chain in (self.cm, self.pm):
            if chain.member in self.member_error:
                chain.unavailable = "B01"
            elif b.get(chain.member) is None:
                chain.unavailable = "B02"
            else:
                chain.raw = b[chain.member]
        for rec in (self.cr, self.pr):
            if rec.member in self.member_error:
                rec.unavailable = "B01"
            elif b.get(rec.member) is None:
                rec.unavailable = "B02"
            else:
                rec.raw = b[rec.member]
        present = [
            m
            for m in ARTIFACTS
            if isinstance(b.get(m), str) or (m in _RECEIPTS and isinstance(b.get(m), dict))
        ]
        if not missing:
            self.put("B02", PASS, "all four artifacts are present")
        elif not present:
            self.put(
                "B02",
                FAIL,
                "the bundle contains no artifact at all: there is nothing to verify",
                reason="no_artifacts",
                hint="add checkout_mandate, payment_mandate, checkout_receipt and payment_receipt "
                "to the bundle (or pass them with --checkout-mandate FILE etc.)",
            )
        else:
            self.put(
                "B02",
                SKIP,
                f"missing: {', '.join(missing)}; present: {', '.join(present)}",
                reason="missing_artifact",
                hint="; ".join(_add_hint(m) for m in missing),
            )

    # ------------------------------------------------------------------ chains

    def chain_checks(self, ch: _Chain) -> None:
        p = ch.prefix
        ids = [f"{p}{i:02d}" for i in range(1, 23)]
        self.run(f"{p}01", lambda: self.x01(ch))
        if ch.unavailable is not None:
            why = {
                "B02": f"{ch.member} is not in the bundle",
                "B01": f"{ch.member} could not be read (see B01)",
            }.get(ch.unavailable, f"{ch.member} could not be parsed (see {p}01)")
            for cid in ids[1:]:
                self.blocked(cid, ch.unavailable, why, required=REGISTRY[cid].required)
            return
        self.run(f"{p}20", lambda: self.x20(ch))
        self.run(f"{p}02", lambda: self.x02(ch))
        self.run(f"{p}03", lambda: self.x03(ch))
        self.run(f"{p}04", lambda: self.x04(ch))
        if not ch.usable:
            for i in (5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22):
                cid = f"{p}{i:02d}"
                self.blocked(
                    cid,
                    f"{p}20",
                    f"chains of {ch.n} segments (agent-to-agent delegation) are not verified",
                    required=REGISTRY[cid].required,
                )
            return
        order: list[tuple[str, Callable[[], None]]] = [
            ("05", lambda: self.x05(ch)),
            ("06", lambda: self.x06(ch)),
            ("07", lambda: self.x07(ch)),
            ("08", lambda: self.x08(ch)),
            ("09", lambda: self.x09(ch)),
            ("10", lambda: self.x10(ch)),
            ("11", lambda: self.x11(ch)),
            ("12", lambda: self.x12(ch)),
            ("13", lambda: self.x13(ch)),
            ("14", lambda: self.x14_15(ch, "aud", f"{p}14")),
            ("15", lambda: self.x14_15(ch, "nonce", f"{p}15")),
            ("16", lambda: self.x16(ch)),
            ("21", lambda: self.x21(ch)),
            ("22", lambda: self.x22(ch)),
            ("17", lambda: self.x17(ch)),
            ("18", lambda: self.x18(ch)),
            ("19", lambda: self.x19(ch)),
        ]
        for suffix, fn in order:
            self.run(f"{p}{suffix}", fn)

    def x01(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}01"
        if ch.unavailable == "B01":
            self.blocked(cid, "B01", f"{ch.member} is not a string")
            return
        if ch.unavailable == "B02":
            self.blocked(cid, "B02", f"{ch.member} is not in the bundle")
            return
        assert ch.raw is not None
        try:
            ch.segments = parse_chain(ch.raw)
        except SdJwtError as exc:
            ch.unavailable = cid
            self.put(
                cid,
                FAIL,
                f"{exc.where}: {u(str(exc), 300)}",
                reason="parse_error",
                hint=f"{exc.where} of {ch.member}",
            )
            return
        ch.res = [resolve(seg) for seg in ch.segments]
        counts = ", ".join(str(len(s.disclosures)) for s in ch.segments)
        self.put(cid, PASS, f"{ch.n} segment(s); disclosures per segment: {counts}")
        for res in ch.res:
            mandate, problem = _pick(res)
            ch.mandates.append(mandate)
            ch.pick_problem.append(problem or ("", ""))
        if 1 <= ch.n <= 2:
            closed = ch.mandates[-1]
            allowance = (
                1
                if ch.kind == "checkout"
                and isinstance(closed, dict)
                and "checkout_jwt" not in closed
                else 0
            )
            _, ch.withheld_closed, n_closed = _classify(ch.res[-1], allowance)
            ch.narrowing = n_closed
            if ch.n == 2:
                ch.hidden_constraints, ch.withheld_open, n_open = _classify(ch.res[0])
                ch.narrowing += n_open

    def x20(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}20"
        if ch.n == 2:
            self.put(
                cid,
                PASS,
                "two segments: open mandate (issuer-signed) and closed mandate (agent-signed)",
            )
        elif ch.n == 1:
            self.put(
                cid,
                PASS,
                "one segment: a directly signed closed mandate (human present); there is no open "
                "mandate and no key-binding hop",
            )
        else:
            self.put(
                cid,
                SKIP,
                f"{ch.n} segments: agent-to-agent delegation is outside AP2 v0.2 "
                '(specification.md "Agent-to-Agent Delegation"); the intermediate hops are not '
                "verified and the chain cannot be relied on",
                reason="delegation_unsupported",
                hint=f"{ch.member} has {ch.n - 2} intermediate hop(s)",
            )

    def x02(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}02"
        alg = ch.segments[0].jws.alg
        if alg == "ES256":
            self.put(cid, PASS, "root token alg is ES256")
            return
        why = ""
        if alg == "none":
            why = "'none' means the token is unsigned"
        elif alg == "EdDSA":
            why = "EdDSA is deterministic and this version supports ES256 only"
        elif isinstance(alg, str) and alg.startswith("HS"):
            why = "HMAC uses a shared secret, so it cannot prove who signed"
        self.put(
            cid,
            FAIL,
            f"root token alg is {q(alg, 40)}, only ES256 is accepted"
            + (f" ({why})" if why else ""),
            reason="alg_not_allowed",
            expected="ES256",
            actual=alg,
            hint=f"segment 1 header of {ch.member}",
        )

    def x03(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}03"
        if self.status(f"{ch.prefix}02") != PASS:
            self.blocked(
                cid, f"{ch.prefix}02", "the root algorithm is not ES256, so no signature check"
            )
            return
        self.signature(cid, ch.segments[0].jws, "mandate_issuer", f"segment 1 of {ch.member}")

    def _resolution_result(self, cid: str, ch: _Chain, i: int) -> None:
        res = ch.res[i]
        seg = ch.segments[i]
        if res.errors:
            m = _DISC_RE.search(res.errors[0])
            where = f"segment {i + 1} of {ch.member}" + (f", disclosure #{m.group(1)}" if m else "")
            shown = "; ".join(res.errors[:4]) + (
                f" (+{len(res.errors) - 4} more)" if len(res.errors) > 4 else ""
            )
            self.put(cid, FAIL, shown, reason=res.codes[0], hint=where)
            return
        mandate = ch.mandates[i]
        if mandate is None:
            code, text = ch.pick_problem[i]
            self.put(cid, FAIL, text, reason=code, hint=f"segment {i + 1} of {ch.member}")
            return
        where = (
            "delegate_payload resolves to exactly one mandate object"
            if res.payload is not None and "delegate_payload" in res.payload
            else "the resolved payload has no delegate_payload (absent or not disclosed), so the "
            "mandate object was taken from the top level of the token payload"
        )
        self.put(
            cid,
            PASS,
            f"{len(seg.disclosures)} disclosure(s), each referenced exactly once (_sd_alg "
            f"{res.sd_alg}); {where}, "
            + (f"vct {q(mandate['vct'], 60)}" if mandate.get("vct") is not None else "no vct"),
        )

    def x04(self, ch: _Chain) -> None:
        self._resolution_result(f"{ch.prefix}04", ch, 0)

    def _need_open(self, cid: str, ch: _Chain) -> dict[str, Any] | None:
        if ch.n == 1:
            self.na(
                cid,
                "directly signed closed mandate: there is no open mandate",
                hint=f"{ch.member} has one segment; open-mandate checks do not apply",
            )
            return None
        if ch.open is None:
            self.blocked(cid, f"{ch.prefix}04", "the open mandate object could not be resolved")
            return None
        return ch.open

    def _need_closed(self, cid: str, ch: _Chain) -> dict[str, Any] | None:
        if ch.closed is None:
            src = f"{ch.prefix}10" if ch.n == 2 else f"{ch.prefix}04"
            self.blocked(cid, src, "the closed mandate object could not be resolved")
            return None
        return ch.closed

    def _need_kb(self, cid: str, ch: _Chain) -> bool:
        if ch.n == 1:
            self.na(
                cid,
                "directly signed closed mandate (one segment): there is no key-binding hop, so "
                "this check does not apply",
                hint=f"{ch.member} has one segment",
            )
            return False
        return True

    def _vct_hint(self, ch: _Chain, vct: Any, seg: int) -> str:
        hint = f"segment {seg} of {ch.member}, mandate disclosure"
        if isinstance(vct, str) and vct.startswith(f"mandate.{ch.other_kind}."):
            hint += (
                f"; this looks like a {ch.other_kind} mandate: were the checkout and payment "
                "files swapped?"
            )
        return hint

    def x05(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}05"
        o = self._need_open(cid, ch)
        if o is None:
            return
        vct = o.get("vct")
        if vct == ch.open_vct:
            self.put(cid, PASS, f"vct is {ch.open_vct!r}")
        else:
            self.put(
                cid,
                FAIL,
                f"open mandate vct is {q(vct, 60)}, expected exactly {ch.open_vct!r}",
                reason="wrong_vct",
                expected=ch.open_vct,
                actual=vct,
                hint=self._vct_hint(ch, vct, 1),
            )

    def x06(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}06"
        o = self._need_open(cid, ch)
        if o is None:
            return
        cnf = o.get("cnf")
        if not isinstance(cnf, dict) or "jwk" not in cnf:
            self.put(
                cid,
                FAIL,
                "the open mandate has no cnf.jwk: it does not name the agent key allowed to "
                "close it",
                reason="no_cnf_jwk",
                hint=f"segment 1 of {ch.member}, mandate disclosure, member cnf",
            )
            return
        try:
            ch.agent_key = load_public_jwk(cnf["jwk"])
        except JoseError as exc:
            self.put(
                cid,
                FAIL,
                f"cnf.jwk is not a valid key: {u(str(exc), 200)}",
                reason="invalid_cnf_jwk",
                hint=f"segment 1 of {ch.member}, cnf.jwk",
            )
            return
        self.put(cid, PASS, f"agent key bound: P-256, JWK thumbprint {ch.agent_key.thumbprint}")

    def x07(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}07"
        if not self._need_kb(cid, ch):
            return
        typ = ch.segments[-1].jws.header.get("typ")
        where = f"segment {ch.n} header of {ch.member}"
        if typ == "kb+sd-jwt":
            self.put(cid, PASS, "typ is 'kb+sd-jwt'")
        elif typ == "kb-sd-jwt":
            self.put(
                cid,
                WARN,
                "typ is 'kb-sd-jwt' (hyphen); the registered spelling is 'kb+sd-jwt'. Accepted, as "
                "the upstream SDK accepts both",
                reason="typ_variant",
                hint=where,
            )
        elif typ in ("kb+sd-jwt+kb", "kb-sd-jwt+kb"):
            self.put(
                cid,
                FAIL,
                f"typ is {q(typ)}, an intermediate delegation hop, but it is the last segment: the "
                "chain does not end in a closed mandate",
                reason="intermediate_typ",
                expected="kb+sd-jwt",
                actual=typ,
                hint=where,
            )
        else:
            self.put(
                cid,
                FAIL,
                f"typ is {q(typ, 60)}, expected 'kb+sd-jwt'",
                reason="wrong_typ",
                expected="kb+sd-jwt",
                actual=typ,
                hint=where,
            )

    def x08(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}08"
        if not self._need_kb(cid, ch):
            return
        if ch.agent_key is None:
            self.blocked(cid, f"{ch.prefix}06", "no valid agent key (cnf.jwk) to check against")
            return
        jws = ch.segments[-1].jws
        if jws.alg != "ES256":
            self.put(
                cid,
                FAIL,
                f"closed token alg is {q(jws.alg, 40)}; only ES256 is accepted",
                reason="alg_not_allowed",
                expected="ES256",
                actual=jws.alg,
                hint=f"segment {ch.n} header of {ch.member}",
            )
            return
        if verify_es256(jws, ch.agent_key):
            self.put(
                cid,
                PASS,
                f"the closed mandate's signature verifies under the agent key bound in the open "
                f"mandate (thumbprint {ch.agent_key.thumbprint})",
                prov=MANDATE,
            )
        else:
            self.put(
                cid,
                FAIL,
                "the closed mandate is NOT signed by the agent key named in the open mandate's "
                f"cnf.jwk (thumbprint {ch.agent_key.thumbprint}): either another key signed it or "
                "it was altered after signing",
                reason="signature_invalid",
                hint=f"segment {ch.n} of {ch.member}; compare its signer with segment 1 cnf.jwk",
                prov=MANDATE,
            )

    def x09(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}09"
        if not self._need_kb(cid, ch):
            return
        payload = ch.segments[-1].jws.payload
        prev = ch.segments[0]
        has_sd, has_ij = "sd_hash" in payload, "issuer_jwt_hash" in payload
        where = f"segment {ch.n} payload of {ch.member} vs. segment 1 as presented"
        if has_sd == has_ij:
            self.put(
                cid,
                FAIL,
                "the closed token must carry exactly one of sd_hash and issuer_jwt_hash, it "
                f"carries {'both' if has_sd else 'neither'}",
                reason="binding_claim_count",
                hint=where,
            )
            return
        alg = prev.sd_alg
        if alg not in HASH_ALGS:
            self.put(
                cid,
                FAIL,
                f"open token _sd_alg {q(alg, 40)} is unsupported",
                reason="unsupported_sd_alg",
                hint=where,
            )
            return
        if has_sd:
            claim, expected, form = "sd_hash", prev.sd_hash_form(alg), "<jwt>~<disclosures>~"
        else:
            claim, expected, form = "issuer_jwt_hash", prev.issuer_jwt_hash(alg), "issuer JWT"
        actual = payload[claim]
        if actual == expected:
            note = (
                " (issuer_jwt_hash binds only the issuer-signed JWT, so the open mandate's "
                "disclosures could have been changed without breaking this link)"
                if claim == "issuer_jwt_hash"
                else ""
            )
            self.put(cid, PASS, f"{claim} equals {alg} of the open segment's {form}{note}")
        else:
            self.put(
                cid,
                FAIL,
                f"{claim} does not match the open segment as presented: the closed mandate was "
                "made for a different open mandate, or the open segment was altered, re-encoded "
                "or its disclosures changed or reordered",
                reason="binding_mismatch",
                expected=expected,
                actual=actual,
                hint=where,
            )

    def x10(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}10"
        if not self._need_kb(cid, ch):
            return
        self._resolution_result(cid, ch, ch.n - 1)

    def x11(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}11"
        c = self._need_closed(cid, ch)
        if c is None:
            return
        vct = c.get("vct")
        if vct == ch.closed_vct:
            self.put(cid, PASS, f"vct is {ch.closed_vct!r}")
            return
        extra = ""
        if isinstance(vct, str) and vct.lower().startswith(("intentmandate", "cartmandate")):
            extra = " (looks like an AP2 v0.1 mandate, which is not supported)"
        self.put(
            cid,
            FAIL,
            f"closed mandate vct is {q(vct, 60)}, expected exactly {ch.closed_vct!r}{extra}",
            reason="wrong_vct",
            expected=ch.closed_vct,
            actual=vct,
            hint=self._vct_hint(ch, vct, ch.n),
        )

    def x12(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}12"
        c = self._need_closed(cid, ch)
        if c is None:
            return
        if ch.n == 1:
            # Upstream forbids cnf only on a terminal key-binding hop (kb_sd_jwt.py); a directly
            # signed one-segment mandate is a root SD-JWT, which may carry cnf
            # (agent_authorization.md shows cnf in mandate.checkout.1).
            self.put(
                cid,
                PASS,
                "directly signed closed mandate (one segment, no key-binding hop): "
                + (
                    "it carries cnf, which upstream allows for a root token"
                    if "cnf" in c
                    else "no cnf"
                ),
            )
        elif "cnf" in c:
            self.put(
                cid,
                FAIL,
                "the closed mandate carries a cnf claim: a terminal (closed) mandate must not "
                "delegate to a further key",
                reason="cnf_in_closed",
                hint=f"segment {ch.n} of {ch.member}, mandate disclosure, member cnf",
            )
        else:
            self.put(cid, PASS, "no cnf in the closed mandate")

    def x13(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}13"
        c = self._need_closed(cid, ch)
        if c is None:
            return
        problems: list[str] = []
        if ch.kind == "checkout":
            if "checkout_jwt" not in c:
                problems.append("checkout_jwt is missing (not disclosed)")
            elif not isinstance(c["checkout_jwt"], str):
                problems.append("checkout_jwt is not a string")
            if not isinstance(c.get("checkout_hash"), str):
                problems.append(
                    "checkout_hash is missing"
                    if "checkout_hash" not in c
                    else "checkout_hash is not a string"
                )
        else:
            if not isinstance(c.get("transaction_id"), str):
                problems.append(
                    "transaction_id is missing"
                    if "transaction_id" not in c
                    else "transaction_id is not a string"
                )
            problems += _merchant_problems(c.get("payee"), "payee", required=True)
            problems += _amount_problems(c.get("payment_amount"), "payment_amount", required=True)
            problems += _instrument_problems(
                c.get("payment_instrument"), "payment_instrument", True
            )
            problems += _pisp_problems(c.get("pisp"), "pisp", required=False)
            if "execution_date" in c and not isinstance(c["execution_date"], str):
                problems.append("execution_date is not a string")
            if "risk_data" in c and not isinstance(c["risk_data"], dict):
                problems.append("risk_data is not an object")
        for k in ("iat", "exp"):
            if k in c and not C.is_int(c[k]):
                problems.append(f"{k} is not an integer")
        if problems:
            missing = any(" is missing" in p for p in problems)
            self.put(
                cid,
                FAIL,
                "the closed mandate does not match its schema: " + "; ".join(problems),
                reason="missing_field" if missing else "wrong_type",
                hint=f"segment {ch.n} of {ch.member}, mandate disclosure",
            )
        else:
            ch.closed_ok = True
            self.put(cid, PASS, f"all required {ch.closed_vct} fields are present with valid types")

    def x14_15(self, ch: _Chain, claim: str, cid: str) -> None:
        if not self._need_kb(cid, ch):
            return
        want_src = self.expected[ch.kind].get(claim)
        payload = ch.segments[-1].jws.payload
        got = payload.get(claim)
        flag = f"--expect-{ch.kind}-{claim}"
        # RFC 9901 section 4.3: a KB-JWT must carry aud and nonce; RFC 7519 allows aud to be
        # an array of strings.
        aud_list = (
            claim == "aud"
            and isinstance(got, list)
            and bool(got)
            and all(isinstance(x, str) and x for x in got)
        )
        if not (isinstance(got, str) and got) and not aud_list:
            what = "missing" if claim not in payload else f"not a non-empty string ({q(got, 40)})"
            if claim == "aud" and claim in payload:
                what = f"not a non-empty string or array of strings ({q(got, 40)})"
            self.put(
                cid,
                FAIL,
                f"the closed token's {claim} is {what}; RFC 9901 requires a key-binding token to "
                f"carry {claim}, and every token the upstream SDK creates has it, so without it "
                "the presentation is not tied to "
                + ("a recipient" if claim == "aud" else "one verifier session (replay)"),
                reason=f"{claim}_missing",
                hint=f"segment {ch.n} payload of {ch.member}",
            )
            return
        if want_src is None:
            why = f"no expected {claim} supplied; the token says {q(got, 80)}"
            self.na(
                cid,
                why,
                hint=f"pass {flag} VALUE (or add expected.{ch.kind}.{claim} to the bundle) to "
                "check it",
                reason="no_expected_value",
            )
            return
        want, src = want_src
        source = (
            f"pinned with {flag}"
            if src == "pinned"
            else f"taken from expected.{ch.kind}.{claim} inside the bundle (self-asserted by "
            f"whoever assembled it; pin it with {flag})"
        )
        if got == want:
            self.put(cid, PASS, f"{claim} equals the expected value {q(want, 80)}, {source}")
        elif aud_list and want in got:
            self.put(
                cid,
                PASS,
                f"aud is an array that contains the expected value {q(want, 80)} (RFC 7519 "
                f"allows an array of recipients), {source}",
            )
        else:
            self.put(
                cid,
                FAIL,
                f"{claim} is {q(got, 80)}, but the expected value is {q(want, 80)} ({source})",
                reason=f"{claim}_mismatch",
                expected=want,
                actual=got,
                hint=f"segment {ch.n} payload of {ch.member}",
            )

    def x16(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}16"
        if not self._need_kb(cid, ch):
            return
        o = self._need_open(cid, ch)
        if o is None:
            return
        kb_iat = ch.segments[-1].jws.payload.get("iat")
        where = f"segment {ch.n} payload (iat) and segment 1 mandate (iat/exp) of {ch.member}"
        if not C.is_int(kb_iat):
            self.put(
                cid,
                FAIL,
                f"the closed token has no integer iat ({u(kb_iat, 40)}); key-binding tokens must "
                "carry iat",
                reason="no_kb_iat",
                hint=where,
            )
            return
        o_iat, o_exp = o.get("iat"), o.get("exp")
        bad = [k for k, v in (("iat", o_iat), ("exp", o_exp)) if v is not None and not C.is_int(v)]
        if bad:
            self.put(
                cid,
                FAIL,
                "; ".join(f"open mandate {k} is not an integer" for k in bad),
                reason="iat_not_integer",
                hint=where,
            )
            return
        sk = self.skew
        problems: list[tuple[str, str]] = []
        if o_iat is not None and o_exp is not None and o_iat > o_exp:
            problems.append(
                (
                    "open_iat_after_exp",
                    f"the open mandate's iat {_utc(o_iat)} is after its exp {_utc(o_exp)}",
                )
            )
        if o_iat is not None and kb_iat < o_iat - sk:
            problems.append(
                (
                    "signed_before_open",
                    f"the closed mandate was signed at {_utc(kb_iat)}, {o_iat - kb_iat} s BEFORE "
                    f"the open mandate was issued ({_utc(o_iat)})",
                )
            )
        if o_exp is not None and kb_iat > o_exp + sk:
            problems.append(
                (
                    "signed_after_expiry",
                    f"the closed mandate was signed at {_utc(kb_iat)}, {kb_iat - o_exp} s AFTER "
                    f"the open mandate expired ({_utc(o_exp)})",
                )
            )
        c = ch.closed or {}
        if C.is_int(c.get("exp")) and kb_iat > c["exp"] + sk:
            problems.append(
                (
                    "after_closed_exp",
                    f"the closed token iat is after the closed mandate's own exp {_utc(c['exp'])}",
                )
            )
        window = f"{_utc(o_iat) if o_iat is not None else '(no iat)'} .. " + (
            _utc(o_exp) if o_exp is not None else "(no exp)"
        )
        if problems:
            self.put(
                cid,
                FAIL,
                "; ".join(p[1] for p in problems) + f" (skew {sk} s)",
                reason=problems[0][0],
                expected=window,
                actual=_utc(kb_iat),
                hint=where,
            )
        elif o_iat is None and o_exp is None:
            self.put(
                cid,
                PASS,
                f"closed mandate signed at {_utc(kb_iat)}; the open mandate has no iat/exp, so "
                "there is no window to compare with",
            )
        else:
            self.put(
                cid,
                PASS,
                f"closed mandate signed at {_utc(kb_iat)}, within the open mandate's window "
                f"{window} (skew {sk} s)",
            )

    def x17(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}17"
        o = self._need_open(cid, ch)
        if o is None:
            return
        cons = o.get("constraints")
        withheld = (
            f"; {ch.hidden_constraints} further constraint(s) are withheld and cannot be "
            f"evaluated (see {ch.prefix}22)"
            if ch.hidden_constraints
            else ""
        )
        if cons is None:
            self.put(
                cid,
                PASS,
                "the open mandate discloses no constraints, so none are unknown"
                + (
                    f" (constraints may be withheld, see {ch.prefix}22)" if ch.withheld_open else ""
                ),
            )
            return
        if not isinstance(cons, list):
            self.blocked(
                cid, f"{ch.prefix}21", "constraints is not an array", reason="malformed_constraint"
            )
            return
        known = C.CHECKOUT_TYPES if ch.kind == "checkout" else C.PAYMENT_TYPES
        other = C.PAYMENT_TYPES if ch.kind == "checkout" else C.CHECKOUT_TYPES
        unknown: list[str] = []
        foreign = False
        for n, c in enumerate(cons, start=1):
            t = C.ctype(c)
            if t not in known:
                unknown.append(f"#{n} {q(t, 60) if t is not None else '(no string type)'}")
                foreign = foreign or t in other
        if unknown:
            extra = (
                f" (a constraint of the other mandate type is not valid in an open {ch.kind} "
                "mandate)"
                if foreign
                else ""
            )
            self.put(
                cid,
                FAIL,
                "unknown constraint type(s) " + ", ".join(unknown) + "; AP2 requires unknown "
                f"constraints to be treated as failing{extra}",
                reason="unknown_constraint_type",
                hint=f"segment 1 of {ch.member}, mandate constraints",
            )
        elif withheld:
            self.put(
                cid, PASS, f"the {len(cons)} disclosed constraint(s) are of known types{withheld}"
            )
        else:
            self.put(cid, PASS, f"{len(cons)} constraint(s), all of known types")

    def x18(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}18"
        o = self._need_open(cid, ch)
        if o is None:
            return
        c = self._need_closed(cid, ch)
        if c is None:
            return
        preset = [k for k in o if k not in ("vct", "constraints", "cnf", "iat", "exp")]
        changed = [k for k in preset if not _json_equal(c.get(k), o[k])]
        if changed:
            k = changed[0]
            self.put(
                cid,
                FAIL,
                "pre-set claim(s) changed in the closed mandate: "
                + ", ".join(u(x, 40) for x in changed),
                reason="preset_claim_changed",
                expected=o[k],
                actual=c.get(k, "(absent)"),
                hint=f"compare segment 1 and segment {ch.n} of {ch.member}, claim {u(k, 40)}",
            )
        elif ch.withheld_open:
            self.put(
                cid,
                SKIP,
                "claims of the open mandate may be withheld (see "
                f"{ch.prefix}22), so it cannot be shown that no pre-set claim was changed"
                + (f"; the disclosed ones are unchanged: {', '.join(preset)}" if preset else ""),
                reason="withheld_claim",
                blocked_by=f"{ch.prefix}22",
                hint=f"supply segment 1 of {ch.member} with all disclosures as issued",
            )
        elif not preset:
            self.put(cid, PASS, "the open mandate pre-sets no claims")
        else:
            self.put(
                cid, PASS, f"pre-set claim(s) unchanged: {', '.join(u(x, 40) for x in preset)}"
            )

    def x19(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}19"
        if self.at is None:
            self.na(
                cid,
                "no --at instant given; wall-clock validity is deliberately not checked because "
                "dispute evidence is always expired by now",
                hint="pass --at UNIX_TS or --at ISO8601 to check validity at a given time",
                reason="no_at",
            )
            return
        at = self.at
        windows: list[tuple[str, Any, Any]] = []
        if ch.n == 2 and ch.open is not None:
            windows.append(("open mandate", ch.open.get("iat"), ch.open.get("exp")))
        if ch.closed is not None:
            windows.append(("closed mandate", ch.closed.get("iat"), ch.closed.get("exp")))
        for seg in ch.segments:
            pl = seg.jws.payload
            if "exp" in pl or "iat" in pl:
                # upstream chain.py rejects iat > now + skew and now > exp + skew per token
                windows.append((f"segment {seg.index} JWT", pl.get("iat"), pl.get("exp")))
        problems = []
        for label, iat, exp in windows:
            if C.is_int(iat) and at < iat - self.skew:
                problems.append(f"{label} was issued later ({_utc(iat)})")
            if C.is_int(exp) and at > exp + self.skew:
                problems.append(f"{label} had expired ({_utc(exp)})")
        if problems:
            self.put(
                cid,
                FAIL,
                f"at {_utc(at)}: " + "; ".join(problems),
                reason="not_valid_at",
                hint="the --at instant is outside the validity window",
            )
        elif not windows:
            self.put(cid, PASS, f"at {_utc(at)}: no iat/exp to compare with")
        else:
            self.put(cid, PASS, f"valid at {_utc(at)} (skew {self.skew} s)")

    def x21(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}21"
        o = self._need_open(cid, ch)
        if o is None:
            return
        problems: list[str] = []
        warnings: list[tuple[str, str]] = []
        cons = o.get("constraints")
        if cons is None:
            warnings.append(
                (
                    "no_constraints",
                    "the open mandate discloses no constraints array: either the agent was not "
                    "limited or the constraints were withheld (see "
                    f"{ch.prefix}22); the schema requires one",
                )
            )
        elif not isinstance(cons, list):
            problems.append("constraints is not an array")
        else:
            for n, c in enumerate(cons, start=1):
                problems += C.field_problems(c, n)
            types = {C.ctype(c) for c in cons}
            need = "checkout.line_items" if ch.kind == "checkout" else "payment.reference"
            if need not in types:
                warnings.append(
                    (
                        "missing_required_constraint",
                        f"no disclosed {need} constraint, which open_{ch.kind}_mandate.json "
                        "requires (the upstream SDK does not enforce this)",
                    )
                )
        for k in ("iat", "exp"):
            if k in o and not C.is_int(o[k]):
                problems.append(f"{k} is not an integer")
        if ch.kind == "payment":
            problems += _merchant_problems(o.get("payee"), "payee", required=False)
            problems += _amount_problems(o.get("payment_amount"), "payment_amount", required=False)
            problems += _instrument_problems(
                o.get("payment_instrument"), "payment_instrument", False
            )
            problems += _pisp_problems(o.get("pisp"), "pisp", required=False)
            if "execution_date" in o and not isinstance(o["execution_date"], str):
                problems.append("execution_date is not a string")
        where = f"segment 1 of {ch.member}, mandate disclosure"
        if problems:
            shown = "; ".join(problems[:6]) + (
                f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""
            )
            self.put(
                cid,
                FAIL,
                "the open mandate does not match its schema: " + shown,
                reason="malformed_constraint"
                if any("constraint" in p for p in problems)
                else "wrong_type",
                hint=where,
            )
        elif warnings:
            self.put(
                cid, WARN, "; ".join(w[1] for w in warnings), reason=warnings[0][0], hint=where
            )
        else:
            self.put(cid, PASS, f"open mandate fields have valid types ({ch.open_vct})")

    def x22(self, ch: _Chain) -> None:
        cid = f"{ch.prefix}22"
        decoys = (
            "SD-JWT decoy digests cannot be told apart from withheld claims, so a limit the user "
            "set may be hidden here"
        )
        narrow = (
            f"; {ch.narrowing} other undisclosed digest"
            + (" sits" if ch.narrowing == 1 else "s sit")
            + " in allowed / acceptable_items lists (entries withheld from this presentation, "
            "or decoys: the bundle cannot tell which); that is fine for the limits, because an "
            "entry that is not shown never allows anything, so it can only narrow what is "
            "allowed"
            if ch.narrowing
            else ""
        )
        if ch.hidden_constraints:
            self.put(
                cid,
                FAIL,
                f"{ch.hidden_constraints} element(s) of the open mandate's constraints array are "
                "undisclosed (withheld constraints, or decoys: the bundle cannot tell which): a "
                "constraint the verifier cannot see cannot be evaluated, and AP2 requires such "
                f"constraints to be treated as failing{narrow}",
                reason="hidden_constraint",
                hint=f"segment 1 of {ch.member}: ask for the open mandate with all its "
                "disclosures as issued",
            )
            return
        withheld = [f"open mandate: {w}" for w in ch.withheld_open] + [
            f"closed mandate: {w}" for w in ch.withheld_closed
        ]
        if withheld:
            self.put(
                cid,
                SKIP,
                "digests without a disclosure: " + "; ".join(withheld[:5]) + f". {decoys}; the "
                "mandate must be supplied with all its disclosures as issued" + narrow,
                reason="withheld_claim",
                hint=f"{ch.member}: ask for every segment with all disclosures as issued",
            )
            return
        self.put(
            cid,
            PASS,
            "no constraint entry and no claim of the mandate is undisclosed, so no limit the "
            f"user set is hidden{narrow}",
        )

    # ------------------------------------------------------------------ constraint helpers

    def _constraints_of(self, cid: str, ch: _Chain, ctype: str) -> list[dict[str, Any]] | None:
        """Return the constraints of a type, or None after emitting a SKIP."""
        if not ch.usable:
            self.blocked(cid, ch.unavailable or f"{ch.prefix}20", f"{ch.member} is not usable")
            return None
        if ch.n == 1:
            self.na(
                cid,
                "directly signed closed mandate: no open mandate, so no constraints",
                hint=f"{ch.member} has one segment",
            )
            return None
        o = ch.open
        if o is None:
            self.blocked(cid, f"{ch.prefix}04", "the open mandate object could not be resolved")
            return None
        cons = o.get("constraints")
        found = [c for c in cons if C.ctype(c) == ctype] if isinstance(cons, list) else []
        if not found and ch.withholds:
            self.blocked(
                cid,
                f"{ch.prefix}22",
                f"constraints of the open mandate are withheld, so it cannot be shown that it has "
                f"no {ctype} constraint",
                reason="withheld_claim",
            )
            return None
        if not found:
            self.na(
                cid,
                f"the open mandate has no {ctype} constraint",
                hint=f"nothing to evaluate: no such limit in segment 1 of {ch.member}",
                reason="no_constraint",
            )
            return None
        return found

    def _combine(self, cid: str, outcomes: list[C.Outcome], hint: str) -> None:
        """One result for several constraints of a type: FAIL > SKIP (required) > WARN > PASS."""
        worst = None
        for status in (FAIL, SKIP, WARN):
            worst = next((o for o in outcomes if o.status == status), None)
            if worst is not None:
                break
        if worst is None:
            self.put(cid, PASS, "; ".join(o.detail for o in outcomes))
        else:
            self.put(
                cid,
                worst.status,
                "; ".join(o.detail for o in outcomes if o.status != PASS),
                reason=worst.reason or "constraint_violated",
                expected=worst.expected,
                actual=worst.actual,
                hint=hint,
                required=True if worst.status == SKIP else None,
            )

    # ------------------------------------------------------------------ checkout

    def checkout_checks(self) -> None:
        for cid, fn in (
            ("CM30", self.cm30),
            ("CM31", self.cm31),
            ("CM32", self.cm32),
            ("CM33", self.cm33),
            ("CM34", self.cm34),
            ("CM35", self.cm35),
        ):
            self.run(cid, fn)

    def _unusable(self, cid: str, ch: _Chain) -> None:
        why = (
            f"{ch.member} is not in the bundle"
            if ch.unavailable == "B02"
            else f"{ch.member} is not usable"
        )
        self.blocked(cid, ch.unavailable or f"{ch.prefix}20", why)

    def _cm_closed(self, cid: str) -> dict[str, Any] | None:
        if not self.cm.usable:
            self._unusable(cid, self.cm)
            return None
        return self._need_closed(cid, self.cm)

    def cm30(self) -> None:
        c = self._cm_closed("CM30")
        if c is None:
            return
        where = f"segment {self.cm.n} of checkout_mandate, checkout_jwt disclosure"
        cj = c.get("checkout_jwt")
        if cj is None:
            self.put(
                "CM30",
                FAIL,
                "the closed checkout mandate does not disclose checkout_jwt, so what was bought "
                "cannot be shown",
                reason="checkout_jwt_missing",
                hint=where,
            )
            return
        try:
            jws = parse_compact(cj, require_object_payload=False)
        except JoseError as exc:
            self.put(
                "CM30",
                FAIL,
                f"checkout_jwt is not a compact JWS: {u(str(exc), 200)}",
                reason="not_jws",
                hint=where,
            )
            return
        self.checkout_jws = jws
        if jws.alg != "ES256":
            self.put(
                "CM30",
                FAIL,
                f"checkout_jwt alg is {q(jws.alg, 40)}; it must be a non-deterministic signature "
                "and this version accepts ES256 only",
                reason="alg_not_allowed",
                expected="ES256",
                actual=jws.alg,
                hint=where,
            )
            return
        if not isinstance(jws.payload, dict):
            self.put(
                "CM30",
                FAIL,
                "checkout_jwt payload is not a JSON object",
                reason="payload_not_object",
                hint=where,
            )
            return
        self.checkout_payload = jws.payload
        self.put(
            "CM30",
            PASS,
            f"checkout_jwt is an ES256 compact JWS ({_kid_text(jws.header.get('kid'))})",
        )

    def cm31(self) -> None:
        c = self._cm_closed("CM31")
        if c is None:
            return
        cj = c.get("checkout_jwt")
        if not isinstance(cj, str):
            self.blocked("CM31", "CM30", "no checkout_jwt to hash")
            return
        ch_hash = c.get("checkout_hash")
        where = f"segment {self.cm.n} of checkout_mandate: checkout_hash vs. checkout_jwt"
        if not isinstance(ch_hash, str):
            self.put(
                "CM31",
                FAIL,
                "checkout_hash is missing or not a string",
                reason="checkout_hash_missing",
                hint=where,
            )
            return
        try:
            computed = hash_b64(cj, "sha-256")
        except JoseError as exc:
            self.put(
                "CM31", FAIL, f"cannot hash checkout_jwt: {exc}", reason="not_ascii", hint=where
            )
            return
        if ch_hash == computed:
            self.put("CM31", PASS, "checkout_hash equals base64url(SHA-256(checkout_jwt))")
            return
        alg = self.cm.segments[-1].sd_alg
        if alg != "sha-256" and alg in HASH_ALGS and ch_hash == hash_b64(cj, alg):
            self.put(
                "CM31",
                PASS,
                f"checkout_hash equals {alg} of checkout_jwt (the token's _sd_alg, as the prose "
                "spec says; the upstream SDK always uses SHA-256)",
            )
            return
        self.put(
            "CM31",
            FAIL,
            "checkout_hash does not match the disclosed checkout_jwt: the agent approved a "
            "different checkout than the one in this mandate",
            reason="hash_mismatch",
            expected=computed,
            actual=ch_hash,
            hint=where,
        )

    def _blocked_on_checkout(self, cid: str) -> None:
        """SKIP for want of the checkout payload, naming the root cause like CM30 does."""
        cm30 = self.results.get("CM30")
        if cm30 is not None and cm30.status == SKIP and cm30.blocked_by:
            self.blocked(cid, cm30.blocked_by, cm30.detail)
        else:
            self.blocked(cid, "CM30", "no readable checkout_jwt payload")

    def cm32(self) -> None:
        if self.checkout_jws is None or self.status("CM30") != PASS:
            cm30 = self.results["CM30"]
            if cm30.status == SKIP and cm30.blocked_by:
                self.blocked("CM32", cm30.blocked_by, cm30.detail)
            else:
                self.blocked("CM32", "CM30", "no usable ES256 checkout_jwt")
            return
        self.signature(
            "CM32",
            self.checkout_jws,
            "merchant",
            f"checkout_jwt inside segment {self.cm.n} of checkout_mandate",
        )

    def cm33(self) -> None:
        p = self.checkout_payload
        if p is None:
            self._blocked_on_checkout("CM33")
            return
        missing = [k for k in _UCP_REQUIRED if k not in p]
        problems = []
        if "id" in p and not isinstance(p["id"], str):
            problems.append("id is not a string")
        if "status" in p and p["status"] not in _UCP_STATUS:
            problems.append(f"status {q(p['status'], 40)} is not a UCP checkout status")
        if "currency" in p and not currency.is_currency_code(p["currency"]):
            problems.append(f"currency {q(p['currency'], 20)} is not an ISO 4217 alpha-3 code")
        if "links" in p and not isinstance(p["links"], list):
            problems.append("links is not an array")
        # A line_items shape other than UCP's (e.g. the docs' 'product' shape) is not malformed:
        # AP2 is agnostic to the checkout format (spec-notes R4). CM35 fails on its own if a
        # line_items constraint needs item.id and it is absent.
        shape: list[str] = []
        li = p.get("line_items")
        if "line_items" in p:
            if not isinstance(li, list):
                shape.append("line_items is not an array")
            else:
                for n, line in enumerate(li):
                    item = line.get("item") if isinstance(line, dict) else None
                    if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                        shape.append(f"line_items[{n}].item.id is missing or not a string")
                    elif "price" in item and not C.is_int(item["price"]):
                        shape.append(f"line_items[{n}].item.price is not an integer")
                    qn = line.get("quantity") if isinstance(line, dict) else None
                    if not C.is_int(qn) or qn < 1:
                        shape.append(f"line_items[{n}].quantity is not a positive integer")
                    if len(shape) >= 6:
                        break
        tot = p.get("totals")
        if "totals" in p:
            if not isinstance(tot, list):
                problems.append("totals is not an array")
            else:
                for n, t in enumerate(tot):
                    if (
                        not isinstance(t, dict)
                        or not isinstance(t.get("type"), str)
                        or not C.is_int(t.get("amount"))
                    ):
                        problems.append(f"totals[{n}] needs a string type and an integer amount")
        if "merchant" in p:
            problems += _merchant_problems(p["merchant"], "merchant", required=True)
        where = "checkout_jwt payload (inside the closed checkout mandate)"
        if problems:
            shown = "; ".join(problems[:6]) + (
                f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""
            )
            self.put(
                "CM33",
                FAIL,
                "the checkout payload is malformed: " + shown,
                reason="malformed_checkout",
                hint=where,
            )
            return
        status = p.get("status")
        self.ucp = not missing and not shape
        if status == "canceled":
            self.put(
                "CM33",
                FAIL,
                "the merchant-signed checkout has status 'canceled': the merchant had cancelled "
                "this checkout, so it cannot be the purchase the payment completed",
                reason="checkout_canceled",
                expected=" or ".join(repr(s) for s in _SIGNABLE_STATUS),
                actual=status,
                hint=where + ", member status",
            )
            return
        warnings: list[tuple[str, str]] = []
        if missing:
            used = [k for k in ("merchant", "line_items", "currency", "totals") if k in p]
            warnings.append(
                (
                    "not_ucp",
                    f"the checkout payload is not a UCP Checkout (missing {', '.join(missing)}); "
                    "AP2 is agnostic to the checkout format. "
                    + (
                        f"The members that are present ({', '.join(used)}) are still used"
                        if used
                        else "None of merchant, line_items, currency and totals is present"
                    ),
                )
            )
        if shape:
            warnings.append(
                (
                    "not_ucp",
                    "the line items are not UCP line items ("
                    + "; ".join(shape)
                    + "); AP2 is agnostic to the checkout format, and a line_items constraint "
                    "that needs item ids is evaluated by CM35",
                )
            )
        if status is not None and status not in _SIGNABLE_STATUS:
            warnings.append(
                (
                    "checkout_not_final",
                    f"the checkout has status {q(status, 40)}, which is not a state in which the "
                    f"checkout is ready to be paid ({', '.join(_SIGNABLE_STATUS)}); the merchant "
                    "may have needed further input before completing it",
                )
            )
        if warnings:
            self.put(
                "CM33",
                WARN,
                "; ".join(w[1] for w in warnings),
                reason=warnings[0][0],
                hint=where,
            )
            return
        self.put("CM33", PASS, f"UCP Checkout object with valid member types, status {q(status)}")

    def _checkout_ready(self, cid: str) -> dict[str, Any] | None:
        if self.checkout_payload is None:
            self._blocked_on_checkout(cid)
            return None
        cm33 = self.results.get("CM33")
        if cm33 is not None and cm33.status == FAIL and cm33.reason != "checkout_canceled":
            self.blocked(cid, "CM33", "the checkout payload is malformed")
            return None
        return self.checkout_payload

    def cm34(self) -> None:
        cons = self._constraints_of("CM34", self.cm, "checkout.allowed_merchants")
        if cons is None:
            return
        p = self._checkout_ready("CM34")
        if p is None:
            return
        merchant = p.get("merchant")
        if not isinstance(merchant, dict):
            if self.ucp:
                self.put(
                    "CM34",
                    FAIL,
                    "the checkout names no merchant, so it cannot satisfy allowed_merchants",
                    reason="no_merchant",
                    hint="checkout_jwt payload, member merchant",
                )
            else:
                self.put(
                    "CM34",
                    SKIP,
                    "the checkout payload is not a UCP Checkout and names no merchant; the "
                    "allowed_merchants constraint could not be evaluated",
                    reason="merchant_unreadable",
                    blocked_by="CM33",
                    hint="checkout_jwt payload (see CM33)",
                )
            return
        outs = [C.eval_allowed_list(c, merchant, "merchant") for c in cons]
        self._combine("CM34", outs, "segment 1 of checkout_mandate, allowed_merchants disclosures")

    def cm35(self) -> None:
        cons = self._constraints_of("CM35", self.cm, "checkout.line_items")
        if cons is None:
            return
        p = self._checkout_ready("CM35")
        if p is None:
            return
        if "line_items" in p and not isinstance(p["line_items"], list):
            # Present but not an array: whatever it holds cannot be matched against the
            # requirements, so it cannot satisfy the constraint (absent is different: the goods
            # may be listed in another checkout format, see below).
            self.put(
                "CM35",
                FAIL,
                "the checkout's line_items member is a JSON "
                f"{_json_type(p['line_items'])}, not an array of line items, so the checkout "
                "cannot satisfy the line_items constraint of the open checkout mandate",
                reason="malformed_checkout",
                expected="line_items: an array of line items",
                actual=f"line_items: a JSON {_json_type(p['line_items'])}",
                hint="checkout_jwt payload, member line_items",
            )
            return
        if not isinstance(p.get("line_items"), list):
            self.put(
                "CM35",
                SKIP,
                "the checkout payload has no line_items member (it is not a UCP Checkout, see "
                "CM33), so the line_items constraint of the open checkout mandate was NOT "
                "checked; this is not a pass: compare the goods in the checkout with the "
                "constraint by hand",
                reason="line_items_unreadable",
                blocked_by="CM33",
                hint="checkout_jwt payload (see CM33)",
            )
            return
        if len(cons) > C.MAX_LINE_ITEM_CONSTRAINTS:
            self.put(
                "CM35",
                SKIP,
                f"the open checkout mandate has {len(cons)} checkout.line_items constraints, more "
                f"than the {C.MAX_LINE_ITEM_CONSTRAINTS} this tool evaluates (so that a crafted "
                "bundle cannot make verification hang); none of them was evaluated",
                reason="too_large",
                required=True,
                hint="segment 1 of checkout_mandate: check the line_items constraints by hand",
            )
            return
        outs = [C.eval_line_items(c, p["line_items"], self.work) for c in cons]
        self._combine(
            "CM35",
            outs,
            "segment 1 of checkout_mandate (acceptable_items) vs. checkout_jwt line_items",
        )

    # ------------------------------------------------------------------ payment

    def payment_checks(self) -> None:
        for cid, fn in (
            ("PM30", self.pm30),
            ("PM31", self.pm31),
            ("PM32", lambda: self._pm_amount("PM32", "payment.amount_range", C.eval_amount_range)),
            ("PM33", self.pm33),
            ("PM34", self.pm34),
            ("PM35", self.pm35),
            ("PM36", self.pm36),
            ("PM37", lambda: self._pm_amount("PM37", "payment.budget", C.eval_budget)),
            ("PM38", self.pm38),
            ("PM39", self.pm39),
        ):
            self.run(cid, fn)

    def _pm_closed(self, cid: str, *, need_fields: bool = True) -> dict[str, Any] | None:
        ch = self.pm
        if not ch.usable:
            self._unusable(cid, ch)
            return None
        c = self._need_closed(cid, ch)
        if c is None:
            return None
        if need_fields and not ch.closed_ok:
            self.blocked(cid, "PM13", "the closed payment mandate fields are not valid")
            return None
        return c

    def pm30(self) -> None:
        c = self._pm_closed("PM30")
        if c is None:
            return
        tx = c["transaction_id"]
        cm = self.cm
        if not cm.usable:
            self._unusable("PM30", cm)
            return
        cc = cm.closed
        if cc is None:
            self.blocked(
                "PM30",
                "CM10" if cm.n == 2 else "CM04",
                "the closed checkout mandate could not be resolved",
            )
            return
        ch_hash = cc.get("checkout_hash")
        cj = cc.get("checkout_jwt")
        recomputed = hash_b64(cj, "sha-256") if isinstance(cj, str) and cj.isascii() else None
        alg = cm.segments[-1].sd_alg
        if (
            recomputed is not None
            and isinstance(cj, str)
            and tx != recomputed
            and alg in HASH_ALGS
            and alg != "sha-256"
            and tx == hash_b64(cj, alg)
        ):
            recomputed = tx  # prose variant: hashed with the token's _sd_alg (see CM31)
        where = "transaction_id in the closed payment mandate vs. checkout_hash / checkout_jwt"
        if tx == recomputed and tx == ch_hash:
            self.put(
                "PM30", PASS, "transaction_id equals checkout_hash and SHA-256 of the checkout JWT"
            )
        elif tx == ch_hash and recomputed is None:
            self.put(
                "PM30",
                PASS,
                "transaction_id equals checkout_hash (the checkout JWT is not disclosed, so the "
                "hash could not be recomputed)",
            )
        elif tx == recomputed:
            self.put(
                "PM30",
                FAIL,
                "transaction_id equals SHA-256 of the checkout JWT but not the closed checkout "
                "mandate's checkout_hash (see CM31)",
                reason="checkout_hash_mismatch",
                expected=ch_hash,
                actual=tx,
                hint=where,
            )
        elif tx == ch_hash:
            self.put(
                "PM30",
                FAIL,
                "transaction_id equals checkout_hash, but checkout_hash itself does not match the "
                "disclosed checkout JWT (see CM31)",
                reason="checkout_hash_mismatch",
                expected=recomputed,
                actual=tx,
                hint=where,
            )
        else:
            self.put(
                "PM30",
                FAIL,
                "transaction_id does not match this checkout: the payment was authorised for a "
                "different checkout",
                reason="transaction_id_mismatch",
                expected=recomputed or ch_hash,
                actual=tx,
                hint=where,
            )

    def pm31(self) -> None:
        cons = self._constraints_of("PM31", self.pm, "payment.reference")
        if cons is None:
            return
        cm = self.cm
        if not cm.usable:
            self._unusable("PM31", cm)
            return
        seg = cm.segments[0]
        algs = ["sha-256"]
        pay_alg = self.pm.segments[0].sd_alg
        if pay_alg in HASH_ALGS and pay_alg not in algs:
            algs.append(pay_alg)
        sd_forms = {hash_b64(seg.presented, a): a for a in algs}
        ij_forms = {hash_b64(seg.issuer_jwt, a): a for a in algs}
        # Undisclosed digests only excuse a mismatch when the segment is otherwise intact: a
        # replaced disclosure also leaves its digest without one (CM04 fails then).
        open_withheld = (
            sum(n for _, _, n in cm.res[0].hidden) if cm.res and not cm.res[0].errors else 0
        )
        outs = []
        for c in cons:
            ref = c.get("conditional_transaction_id")
            if not isinstance(ref, str):
                outs.append(
                    C.Outcome(
                        FAIL,
                        "conditional_transaction_id is missing or not a string",
                        reason="malformed_constraint",
                    )
                )
            elif ref in sd_forms:
                outs.append(
                    C.Outcome(
                        PASS,
                        f"conditional_transaction_id equals {sd_forms[ref]} of the open checkout "
                        "mandate as presented (<jwt>~<disclosures>~, the form the upstream "
                        "samples use)",
                    )
                )
            elif ref in ij_forms:
                form = (
                    f"conditional_transaction_id equals {ij_forms[ref]} of the open checkout "
                    "mandate's issuer-signed JWT only; this form does not bind the checkout "
                    "mandate's disclosures"
                )
                if cm.withholds:
                    outs.append(
                        C.Outcome(
                            WARN,
                            form + ", and the open checkout mandate is presented with undisclosed "
                            "constraints or claims, which may be withheld (see CM22)",
                            reason="issuer_jwt_form_with_withheld",
                        )
                    )
                else:
                    outs.append(
                        C.Outcome(
                            PASS,
                            form + "; the open checkout mandate as presented has no undisclosed "
                            "constraint or claim (CM22)",
                        )
                    )
            elif open_withheld:
                # Upstream hashes the open checkout token as issued, with all disclosures. The
                # presented segment may omit some, so the as-issued hash cannot be recomputed.
                # The undisclosed digests cannot be bounded: the SDK's presentation filter
                # (MandateClient.present(claims_to_disclose=...)) drops every array-element
                # disclosure except the mandate object and every claim it is not told to keep,
                # and issuers may add decoys, so no position of an undisclosed digest rules out a
                # legitimate narrowing.
                digests = f"{open_withheld} undisclosed digest" + (
                    "" if open_withheld == 1 else "s"
                )
                outs.append(
                    C.Outcome(
                        SKIP,
                        "conditional_transaction_id does NOT match the open checkout mandate as "
                        f"presented. That segment is presented with {digests} (entries withheld "
                        "from this presentation, or decoys the issuer added; the bundle cannot "
                        "tell which, see CM22). Upstream computes the reference over the token as "
                        "issued, with all its disclosures, so this mismatch is expected if the "
                        "open checkout mandate was presented with fewer disclosures than were "
                        "issued; it is equally what a reference to a different checkout "
                        "authorisation looks like. The reference was not verified either way: the "
                        "open checkout mandate as issued, with all its disclosures, is needed to "
                        "check it (compared: payment.reference in segment 1 of payment_mandate "
                        "vs. segment 1 of checkout_mandate)",
                        expected=next(iter(sd_forms)),
                        actual=ref,
                        reason="reference_unverifiable_withheld",
                    )
                )
            else:
                outs.append(
                    C.Outcome(
                        FAIL,
                        "conditional_transaction_id matches neither the open checkout mandate as "
                        "presented nor its issuer-signed JWT: this payment authorisation belongs "
                        "to a different checkout authorisation, or the open checkout mandate was "
                        "altered after the hash was made (all of its disclosures are presented, "
                        "so nothing was legitimately withheld)",
                        expected=next(iter(sd_forms)),
                        actual=ref,
                        reason="reference_mismatch",
                    )
                )
        self._combine(
            "PM31",
            outs,
            "segment 1 of payment_mandate (payment.reference) vs. segment 1 of checkout_mandate. "
            "Upstream computes this hash over the open checkout token with all disclosures as "
            "issued; if the agent presented fewer disclosures, request the open checkout mandate "
            "as issued",
        )

    def _pm_amount(
        self,
        cid: str,
        ctype: str,
        fn: Callable[[dict[str, Any], dict[str, Any]], C.Outcome],
    ) -> None:
        cons = self._constraints_of(cid, self.pm, ctype)
        if cons is None:
            return
        c = self._pm_closed(cid)
        if c is None:
            return
        outs = [fn(x, c["payment_amount"]) for x in cons]
        self._combine(
            cid,
            outs,
            f"payment_amount in segment {self.pm.n} vs. {ctype} in segment 1 of payment_mandate",
        )

    def pm33(self) -> None:
        cons = self._constraints_of("PM33", self.pm, "payment.allowed_payees")
        if cons is None:
            return
        c = self._pm_closed("PM33")
        if c is None:
            return
        outs = [C.eval_allowed_list(x, c["payee"], "payee") for x in cons]
        self._combine("PM33", outs, "segment 1 of payment_mandate, allowed_payees disclosures")

    def pm34(self) -> None:
        cons = self._constraints_of("PM34", self.pm, "payment.allowed_payment_instruments")
        if cons is None:
            return
        c = self._pm_closed("PM34")
        if c is None:
            return
        outs = [C.eval_allowed_instruments(x, c["payment_instrument"]) for x in cons]
        self._combine(
            "PM34", outs, "segment 1 of payment_mandate, allowed_payment_instruments disclosures"
        )

    def pm35(self) -> None:
        cons = self._constraints_of("PM35", self.pm, "payment.allowed_pisps")
        if cons is None:
            return
        c = self._pm_closed("PM35")
        if c is None:
            return
        outs = [C.eval_allowed_pisps(x, c.get("pisp")) for x in cons]
        self._combine(
            "PM35",
            outs,
            f"pisp in segment {self.pm.n} vs. allowed_pisps in segment 1 of payment_mandate",
        )

    def pm36(self) -> None:
        cons = self._constraints_of("PM36", self.pm, "payment.execution_date")
        if cons is None:
            return
        c = self._pm_closed("PM36")
        if c is None:
            return
        outs = [C.eval_execution_date(x, c.get("execution_date")) for x in cons]
        self._combine("PM36", outs, f"execution_date in segment {self.pm.n} of payment_mandate")

    def pm38(self) -> None:
        cons = self._constraints_of("PM38", self.pm, "payment.agent_recurrence")
        if cons is None:
            return
        all_cons = (self.pm.open or {}).get("constraints") or []
        outs = [C.eval_recurrence(x, all_cons if isinstance(all_cons, list) else []) for x in cons]
        self._combine("PM38", outs, "segment 1 of payment_mandate, constraints")

    def pm39(self) -> None:
        o = self.pm.open if self.pm.usable else None
        cons = o.get("constraints") if isinstance(o, dict) else None
        types = {C.ctype(c) for c in cons} if isinstance(cons, list) else set()
        present = [t for t in ("payment.budget", "payment.agent_recurrence") if t in types]
        if not present:
            self.na(
                "PM39",
                "the open payment mandate has no disclosed budget or recurrence constraint",
                hint="nothing to evaluate: no cumulative limit in segment 1 of payment_mandate",
                reason="no_constraint",
            )
            return
        assert isinstance(cons, list)
        h = self.history
        outs: list[C.Outcome] = []
        budgets = [c for c in cons if C.ctype(c) == "payment.budget"]
        if budgets:
            c = self._pm_closed("PM39")
            if c is None:
                return
            outs += [C.eval_cumulative_budget(x, c["payment_amount"], h.get("prior_total"))
                     for x in budgets]  # fmt: skip
        for x in cons:
            if C.ctype(x) == "payment.agent_recurrence":
                outs.append(C.eval_cumulative_recurrence(x, h.get("prior_uses")))
        self._combine(
            "PM39",
            outs,
            "pass the spend and the number of payments made earlier under this open payment "
            "mandate as history (prior_total, prior_uses), from the issuer's or processor's "
            "records",
        )

    # ------------------------------------------------------------------ cross

    def cross_checks(self) -> None:
        self.run("XC01", self.xc01)
        self.run("XC02", self.xc02)
        self.run("XC03", self.xc03)
        self.run("XC04", self.xc04)

    def _cross_inputs(self, cid: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        c = self._pm_closed(cid)
        if c is None:
            return None
        if not self.cm.usable:
            self._unusable(cid, self.cm)
            return None
        if self.checkout_payload is None:
            self._blocked_on_checkout(cid)
            return None
        return c, self.checkout_payload

    def xc01(self) -> None:
        got = self._cross_inputs("XC01")
        if got is None:
            return
        c, p = got
        cur = p.get("currency")
        totals = p.get("totals")
        where = (
            "payment_amount in the closed payment mandate vs. totals[type=total] in checkout_jwt"
        )
        if not currency.is_currency_code(cur) or not isinstance(totals, list):
            self.put(
                "XC01",
                SKIP,
                "the checkout JWT has no readable currency and totals array, so the paid amount "
                "cannot be compared with what the merchant charged",
                reason="total_unreadable",
                hint="checkout_jwt payload, members currency and totals (see CM33)",
            )
            return
        entries = [t for t in totals if isinstance(t, dict) and t.get("type") == "total"]
        if len(entries) != 1 or not C.is_int(entries[0].get("amount")):
            self.put(
                "XC01",
                FAIL,
                f"the checkout has {len(entries)} totals entries of type 'total' (exactly one with "
                "an integer amount expected)",
                reason="no_single_total",
                hint=where,
            )
            return
        if entries[0]["amount"] < 0:
            self.put(
                "XC01",
                FAIL,
                f"the checkout total is negative ({entries[0]['amount']} minor units)",
                reason="negative_total",
                hint=where,
            )
            return
        paid = c["payment_amount"]
        want = {"amount": entries[0]["amount"], "currency": cur}
        if paid["amount"] == want["amount"] and paid["currency"] == want["currency"]:
            self.put(
                "XC01",
                PASS,
                f"paid {C.amount_label(paid)} equals the checkout total {C.amount_label(want)}",
            )
        else:
            self.put(
                "XC01",
                FAIL,
                f"paid {C.amount_label(paid)} but the checkout total is {C.amount_label(want)}",
                reason="amount_mismatch" if paid["currency"] == cur else "currency_mismatch",
                expected=C.amount_label(want),
                actual=C.amount_label(paid),
                hint=where,
            )

    def xc02(self) -> None:
        got = self._cross_inputs("XC02")
        if got is None:
            return
        c, p = got
        merchant = p.get("merchant")
        if not isinstance(merchant, dict):
            self.put(
                "XC02",
                SKIP,
                "the checkout JWT names no merchant, so the payee cannot be compared with it",
                reason="merchant_unreadable",
                hint="checkout_jwt payload, member merchant",
            )
            return
        payee = c["payee"]
        signed_by_merchant = C.merchant_label(merchant)
        named_by_agent = C.merchant_label(payee)
        if C.merchant_matches(payee, merchant) and C.merchant_details_differ(payee, merchant):
            self.put(
                "XC02",
                WARN,
                f"the payee has the checkout merchant's id {q(merchant.get('id'), 60)}, which "
                "satisfies the upstream SDK, but its name or website differ: the merchant-signed "
                f"checkout names {signed_by_merchant}, while the agent-signed payment mandate "
                f"names {named_by_agent}. Rely on the merchant-signed description",
                reason="payee_details_differ",
                expected=signed_by_merchant,
                actual=named_by_agent,
                hint="payee in the closed payment mandate vs. merchant in checkout_jwt",
            )
        elif C.merchant_matches(payee, merchant):
            self.put(
                "XC02",
                PASS,
                f"payee {named_by_agent} is the checkout merchant",
                expected=signed_by_merchant,
                actual=named_by_agent,
            )
        else:
            self.put(
                "XC02",
                FAIL,
                f"the payment goes to {C.merchant_label(payee)} but the checkout was sold by "
                f"{C.merchant_label(merchant)}",
                reason="payee_mismatch",
                expected=C.merchant_label(merchant),
                actual=C.merchant_label(payee),
                hint="payee in the closed payment mandate vs. merchant in checkout_jwt",
            )

    def xc03(self) -> None:
        a, b = self.cm.agent_key, self.pm.agent_key
        if a is None or b is None:
            self.na(
                "XC03",
                "the agent key of both open mandates is needed (CM06 and PM06)",
                hint="see CM06 and PM06",
            )
            return
        if a.thumbprint == b.thumbprint:
            self.put("XC03", PASS, f"both open mandates bind agent key {a.thumbprint}")
        else:
            self.put(
                "XC03",
                WARN,
                f"the open checkout mandate binds agent key {a.thumbprint} but the open payment "
                f"mandate binds {b.thumbprint}; allowed, but unusual",
                reason="agent_key_differs",
                hint="cnf.jwk in segment 1 of checkout_mandate and payment_mandate",
            )

    def xc04(self) -> None:
        a, b = self.signers.get("CM03"), self.signers.get("PM03")
        if a is None or b is None:
            self.na(
                "XC04",
                "both root signatures must verify (CM03 and PM03) to compare the issuer keys",
                hint="see CM03 and PM03",
            )
            return
        if a.key.thumbprint == b.key.thumbprint:
            self.put(
                "XC04", PASS, f"both root tokens verify under mandate_issuer key {a.key.thumbprint}"
            )
        else:
            self.put(
                "XC04",
                WARN,
                f"the checkout mandate's root verifies under {a.label} (thumbprint "
                f"{a.key.thumbprint}) but the payment mandate's root under {b.label} (thumbprint "
                f"{b.key.thumbprint}): the checkout and the payment may have been authorised by "
                "different users or agent providers",
                reason="issuer_key_differs",
                hint="pin only the mandate_issuer key of the user in this dispute",
            )

    # ------------------------------------------------------------------ receipts

    def receipt_checks(self, rec: _Receipt, ch: _Chain) -> None:
        p = rec.prefix
        self.run(f"{p}01", lambda: self.r01(rec))
        if rec.jws is None:
            by = rec.unavailable or f"{p}01"
            why = {
                "B02": f"{rec.member} is not in the bundle",
                "B01": f"{rec.member} could not be read (see B01)",
            }.get(by, f"{rec.member} could not be parsed (see {p}01)")
            for i in range(2, 8):
                cid = f"{p}{i:02d}"
                self.blocked(cid, by, why, required=REGISTRY[cid].required)
            return
        jws = rec.jws
        self.run(f"{p}02", lambda: self.signature(f"{p}02", jws, rec.role, rec.member))
        self.run(f"{p}03", lambda: self.r03(rec))
        self.run(f"{p}04", lambda: self.r04(rec, ch))
        self.run(f"{p}05", lambda: self.r05(rec))
        self.run(f"{p}06", lambda: self.r06(rec, ch))
        self.run(f"{p}07", lambda: self.r07(rec))
        if self.status(f"{p}04") == FAIL:
            # True about the receipt, but the receipt answers another mandate: say so, so a
            # PASS here is not read as a statement about this payment.
            for n in ("05", "06"):
                res = self.results.get(f"{p}{n}")
                if res is not None and res.status == PASS:
                    res.detail += (
                        f"; this describes the receipt as presented, but {p}04 found that it "
                        f"refers to another mandate, so it says nothing about this {rec.kind}"
                    )

    def r01(self, rec: _Receipt) -> None:
        cid = f"{rec.prefix}01"
        if rec.unavailable is not None:
            self.blocked(
                cid,
                rec.unavailable,
                f"{rec.member} is not in the bundle"
                if rec.unavailable == "B02"
                else f"{rec.member} is not a string",
            )
            return
        assert rec.raw is not None
        unsigned = isinstance(rec.raw, dict)
        if not unsigned and isinstance(rec.raw, str) and rec.raw.strip().startswith("{"):
            try:
                unsigned = isinstance(strictjson.loads(rec.raw), dict)
            except strictjson.StrictJsonError:
                unsigned = False
        if unsigned:
            rec.unavailable = cid
            self.put(
                cid,
                SKIP,
                f"{rec.member} is a plain JSON object, not a signed JWT (the official x402 and "
                "human-present sample flows return such an object as their receipt). An unsigned "
                "receipt proves nothing: anyone could have written it. A receipt signed by the "
                f"{rec.role.replace('_', ' ')} is needed",
                reason="unsigned_receipt",
                required=True,
                hint=f"ask the {rec.role.replace('_', ' ')} for a signed {rec.kind} receipt "
                f"(a compact JWT) and put it into {rec.member}",
            )
            return
        assert isinstance(rec.raw, str)
        raw = rec.raw.strip()
        if "~" in raw:
            rec.unavailable = cid
            self.put(
                cid,
                FAIL,
                "the receipt contains '~': it is an SD-JWT, but receipts are plain signed JWTs",
                reason="sd_jwt_receipt",
                hint=f"{rec.member}: was a mandate pasted here by mistake?",
            )
            return
        try:
            jws = parse_compact(raw)
        except JoseError as exc:
            rec.unavailable = cid
            self.put(
                cid,
                FAIL,
                f"not a compact JWT: {u(str(exc), 200)}",
                reason="not_jws",
                hint=rec.member,
            )
            return
        if jws.alg != "ES256":
            rec.unavailable = cid
            self.put(
                cid,
                FAIL,
                f"receipt alg is {q(jws.alg, 40)}; only ES256 is accepted",
                reason="alg_not_allowed",
                expected="ES256",
                actual=jws.alg,
                hint=f"{rec.member} header",
            )
            return
        rec.jws = jws
        self.put(cid, PASS, f"ES256 compact JWT ({_kid_text(jws.header.get('kid'))})")

    @staticmethod
    def _outcome(p: dict[str, Any]) -> tuple[str | None, Any, bool]:
        """(field used, value, conflicting) for a receipt's outcome (status / result)."""
        status, result = p.get("status"), p.get("result")
        if status is not None and result is not None:
            same = (
                isinstance(status, str)
                and isinstance(result, str)
                and status.lower() == result.lower()
            )
            return "status", status, not same
        if status is not None:
            return "status", status, False
        if result is not None:
            return "result", result, False
        return None, None, False

    def r03(self, rec: _Receipt) -> None:
        cid = f"{rec.prefix}03"
        assert rec.jws is not None
        p = rec.jws.payload
        problems: list[str] = []
        notes: list[str] = []

        def present(k: str) -> bool:
            return p.get(k) is not None

        def need_str(k: str) -> None:
            if not present(k):
                problems.append(f"{k} is missing")
            elif not isinstance(p[k], str):
                problems.append(f"{k} is not a string")

        fld, outcome, conflict = self._outcome(p)
        where = f"{rec.member} payload"
        if conflict:
            self.put(
                cid,
                FAIL,
                f"the receipt carries both status {q(p.get('status'), 20)} and result "
                f"{q(p.get('result'), 20)}, which disagree: its outcome is ambiguous",
                reason="conflicting_outcome",
                hint=where,
            )
            return
        if fld == "result":
            if outcome not in ("success", "error"):
                problems.append(f"result {q(outcome, 20)} is not 'success' or 'error'")
            notes.append(
                "uses the prose Mandate Receipt form (result: success|error, "
                "agent_authorization.md) instead of the schema form (status: Success|Error)"
            )
            for k in ("iss", "reference"):
                need_str(k)
            if outcome == "error":
                need_str("error")
        else:
            if fld is None:
                problems.append("status is missing")
            elif outcome not in ("Success", "Error"):
                problems.append(f"status is {q(outcome, 20)}, expected 'Success' or 'Error'")
            for k in ("iss", "reference"):
                need_str(k)
            if rec.kind == "payment":
                need_str("payment_id")
            if outcome == "Success":
                ids = (
                    ("order_id",)
                    if rec.kind == "checkout"
                    else ("psp_confirmation_id", "network_confirmation_id")
                )
                for k in ids:
                    need_str(k)
            elif outcome == "Error":
                need_str("error")
                need_str("error_description")
        if not present("iat"):
            if fld != "result":
                problems.append("iat is missing")
        elif not C.is_int(p["iat"]):
            problems.append("iat is not an integer")
        hint = where
        other_ids = (
            ("payment_id", "psp_confirmation_id") if rec.kind == "checkout" else ("order_id",)
        )
        if any(present(k) for k in other_ids):
            other = "payment" if rec.kind == "checkout" else "checkout"
            hint += f"; this looks like a {other} receipt: were the receipt files swapped?"
        if problems:
            missing = any(x.endswith(" is missing") for x in problems)
            self.put(
                cid,
                FAIL,
                f"the receipt does not match code/sdk/schemas/ap2/{rec.kind}_receipt.json: "
                + "; ".join(problems),
                reason="missing_field" if missing else "wrong_type",
                hint=hint,
            )
        elif notes:
            self.put(cid, WARN, "; ".join(notes), reason="prose_receipt_form", hint=hint)
        else:
            self.put(cid, PASS, f"all fields required for status {q(outcome, 20)} are present")

    def r04(self, rec: _Receipt, ch: _Chain) -> None:
        cid = f"{rec.prefix}04"
        assert rec.jws is not None
        ref = rec.jws.payload.get("reference")
        if not isinstance(ref, str):
            self.blocked(cid, f"{rec.prefix}03", "the receipt has no string reference")
            return
        if not ch.usable:
            why = (
                f"{ch.member} is not in the bundle"
                if ch.unavailable == "B02"
                else f"{ch.member} is not usable"
            )
            self.blocked(
                cid,
                ch.unavailable or f"{ch.prefix}20",
                why + ", so the reference cannot be checked",
            )
            return
        leaf = ch.segments[-1]
        sdk_form = hash_b64(leaf.issuer_jwt, "sha-256")
        algs = ["sha-256"] + (
            [leaf.sd_alg] if leaf.sd_alg in HASH_ALGS and leaf.sd_alg != "sha-256" else []
        )
        prose = {hash_b64(leaf.presented, a): a for a in algs}
        if ref == sdk_form:
            self.put(
                cid,
                PASS,
                "reference equals SHA-256 of the closed mandate's issuer-signed JWT (the upstream "
                "SDK form, mandate.py get_closed_mandate_jwt)",
            )
            return
        if ref in prose:
            self.put(
                cid,
                PASS,
                f"reference equals {prose[ref]} of the closed mandate segment with its disclosures "
                "(the prose form, 'calculated in the same manner as sd_hash'); the upstream SDK "
                "would have produced the issuer-JWT-only form",
            )
            return
        other = []
        if ch.n == 2:
            first = ch.segments[0]
            if ref in (hash_b64(first.issuer_jwt), hash_b64(first.presented)):
                other.append("it matches the OPEN mandate instead of the closed one")
        for other_ch in (self.cm, self.pm):
            if (
                other_ch is not ch
                and other_ch.usable
                and ref
                in (
                    hash_b64(other_ch.segments[-1].issuer_jwt),
                    hash_b64(other_ch.segments[-1].presented),
                )
            ):
                other.append(f"it matches the closed {other_ch.kind} mandate instead")
        extra = f" ({'; '.join(other)})" if other else ""
        self.put(
            cid,
            FAIL,
            f"reference does not match the closed {ch.kind} mandate in this bundle in either "
            f"accepted form: the receipt belongs to a different mandate{extra}",
            reason="reference_mismatch",
            expected=f"{sdk_form} (SDK form) or {next(iter(prose))} (prose form)",
            actual=ref,
            hint=f"{rec.member} reference vs. segment {ch.n} of {ch.member}",
        )

    def r05(self, rec: _Receipt) -> None:
        cid = f"{rec.prefix}05"
        assert rec.jws is not None
        p = rec.jws.payload
        fld, outcome, conflict = self._outcome(p)
        errors = [k for k in ("error", "error_description") if p.get(k) not in (None, "")]
        if conflict or fld is None:
            self.blocked(cid, f"{rec.prefix}03", "the receipt has no unambiguous outcome")
        elif outcome in ("Success", "success") and errors:
            self.put(
                cid,
                FAIL,
                f"the receipt reports outcome {q(outcome, 20)} but also carries "
                + " and ".join(f"{k} {q(p[k], 120)}" for k in errors)
                + ": its outcome is contradictory, so it does not show a completed step",
                reason="success_with_error",
                expected="no error with a successful outcome",
                actual="; ".join(f"{k}={u(p[k], 120)}" for k in errors),
                hint=f"{rec.member}: ask the {rec.role.replace('_', ' ')} which outcome is right",
            )
        elif outcome in ("Success", "success"):
            self.receipt_outcome[rec.kind] = "success"
            self.put(
                cid, PASS, f"outcome {q(outcome, 20)} ({fld})", expected="success", actual="success"
            )
        elif outcome in ("Error", "error"):
            # This check only reads what the receipt says. Whether the receipt is genuine and
            # answers this bundle's mandate is for the signature, required fields, reference
            # and time checks; the report weighs the outcome only when those pass (the issuer
            # plausibility check 07 is a warning only, see report.RECEIPT_GATE).
            self.receipt_outcome[rec.kind] = "declined"
            pre = rec.prefix
            self.put(
                cid,
                WARN,
                f"the {rec.kind} receipt {error_text(p)}, that is, it says this {rec.kind} step "
                "was declined, not completed. This describes what the receipt says, not that it "
                "is genuine: its signature, required fields, reference and time checks are "
                f"{pre}02, {pre}03, {pre}04 and {pre}06",
                reason="declined",
                expected="success",
                actual="declined",
                hint=f"{rec.member}: the receipt says the transaction was declined; that counts "
                f"only if its signature, required fields, reference and time checks ({pre}02, "
                f"{pre}03, {pre}04, {pre}06) pass",
            )
        else:
            self.blocked(
                cid,
                f"{rec.prefix}03",
                f"the receipt has no recognisable outcome ({q(outcome, 20)})",
            )

    def r06(self, rec: _Receipt, ch: _Chain) -> None:
        cid = f"{rec.prefix}06"
        assert rec.jws is not None
        r_iat = rec.jws.payload.get("iat")
        if not C.is_int(r_iat):
            if self.status(f"{rec.prefix}03") == FAIL:
                self.blocked(cid, f"{rec.prefix}03", "the receipt has no integer iat")
            else:
                self.na(
                    cid,
                    "the receipt has no iat (the prose receipt form does not define one)",
                    hint=f"{rec.member} payload",
                )
            return
        if not ch.usable:
            self._unusable(cid, ch)
            return
        m_iat = ch.closed_iat()
        if not C.is_int(m_iat):
            self.na(
                cid,
                f"the closed {ch.kind} mandate has no integer iat to compare with",
                hint=f"segment {ch.n} of {ch.member}",
            )
            return
        if r_iat < m_iat - self.skew:
            self.put(
                cid,
                FAIL,
                f"the receipt was issued at {_utc(r_iat)}, {m_iat - r_iat} s before the closed "
                f"{ch.kind} mandate was signed ({_utc(m_iat)}): it cannot be a response to it",
                reason="receipt_before_mandate",
                expected=f"not earlier than {_utc(m_iat - self.skew)}",
                actual=_utc(r_iat),
                hint=f"{rec.member} iat vs. segment {ch.n} iat of {ch.member}",
            )
        else:
            self.put(
                cid,
                PASS,
                f"receipt issued at {_utc(r_iat)}, after the closed mandate ({_utc(m_iat)}, skew "
                f"{self.skew} s)",
            )

    def r07(self, rec: _Receipt) -> None:
        cid = f"{rec.prefix}07"
        assert rec.jws is not None
        iss = rec.jws.payload.get("iss")
        if rec.kind == "checkout":
            m = (self.checkout_payload or {}).get("merchant")
            ref = m.get("website") if isinstance(m, dict) else None
            label = "the checkout merchant's website"
        else:
            closed = self.pm.closed if self.pm.usable else None
            pisp = closed.get("pisp") if isinstance(closed, dict) else None
            ref = pisp.get("domain_name") if isinstance(pisp, dict) else None
            label = "the payment mandate's pisp.domain_name"
        named = isinstance(iss, str) and bool(iss)
        iss_txt = f"iss {q(iss, 80)}" if named else "the receipt names no issuer (iss), so it"
        if not isinstance(ref, str) or not ref:
            what = f"the issuer {q(iss, 80)}" if named else "the receipt's issuer (none named)"
            self.na(
                cid,
                f"{label} is not available, so {what} cannot be compared",
                hint=f"{rec.member} iss; nothing to compare it with",
            )
            return
        iss_host = _host(iss) if isinstance(iss, str) else None
        if iss_host is not None and iss_host == _host(ref):
            self.put(cid, PASS, f"iss {q(iss, 80)} matches {label} {q(ref, 80)}")
        else:
            self.put(
                cid,
                WARN,
                f"{iss_txt} does not match {label} {q(ref, 80)}; the receipt may come from "
                "a different party than expected",
                reason="issuer_mismatch",
                hint=f"{rec.member} iss",
            )


def _json_type(v: Any) -> str:
    """The JSON type name of a parsed value (object, array, string, number, boolean, null)."""
    names = {"bool": "boolean", "int": "number", "float": "number", "str": "string"}
    kind = _json_kind(v)
    return {"list": "array", "dict": "object", **names}.get(kind, kind)


def _json_kind(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "dict"
    return "null" if v is None else type(v).__name__


def _json_equal(a: Any, b: Any) -> bool:
    """Equality of JSON values that tells true, 1 and 1.0 apart (Python's == does not)."""
    stack = [(a, b)]
    while stack:
        x, y = stack.pop()
        kind = _json_kind(x)
        if kind != _json_kind(y):
            return False
        if kind == "list":
            if len(x) != len(y):
                return False
            stack.extend(zip(x, y, strict=True))
        elif kind == "dict":
            if x.keys() != y.keys():
                return False
            stack.extend((x[k], y[k]) for k in x)
        elif x != y:
            return False
    return True


def _host(value: str) -> str | None:
    """Lower-case host name of a URL or bare host, or None (unparsable, or with userinfo)."""
    v = value.strip()
    if "://" not in v:
        v = "//" + v
    try:
        parts = urlsplit(v)
        host = parts.hostname
    except ValueError:
        return None
    if "@" in parts.netloc or not host:
        return None
    return host


def _merchant_problems(v: Any, path: str, *, required: bool) -> list[str]:
    if v is None:
        return [f"{path} is missing"] if required else []
    if not isinstance(v, dict):
        return [f"{path} is not an object"]
    out = [
        f"{path}.{k} is missing" if k not in v else f"{path}.{k} is not a string"
        for k in ("id", "name")
        if not isinstance(v.get(k), str)
    ]
    if "website" in v and not isinstance(v["website"], str):
        out.append(f"{path}.website is not a string")
    return out


def _amount_problems(v: Any, path: str, *, required: bool) -> list[str]:
    if v is None:
        return [f"{path} is missing"] if required else []
    if not isinstance(v, dict):
        return [f"{path} is not an object"]
    out = []
    if not C.is_int(v.get("amount")):
        out.append(
            f"{path}.amount is missing"
            if "amount" not in v
            else f"{path}.amount is not an integer (minor units)"
        )
    elif v["amount"] < 0:
        out.append(f"{path}.amount is negative ({v['amount']} minor units)")
    if not currency.is_currency_code(v.get("currency")):
        out.append(
            f"{path}.currency is missing"
            if "currency" not in v
            else f"{path}.currency is not an ISO 4217 alpha-3 code"
        )
    return out


def _instrument_problems(v: Any, path: str, required: bool) -> list[str]:
    if v is None:
        return [f"{path} is missing"] if required else []
    if not isinstance(v, dict):
        return [f"{path} is not an object"]
    out = [
        f"{path}.{k} is missing" if k not in v else f"{path}.{k} is not a string"
        for k in ("id", "type")
        if not isinstance(v.get(k), str)
    ]
    if "description" in v and not isinstance(v["description"], str):
        out.append(f"{path}.description is not a string")
    return out


def _pisp_problems(v: Any, path: str, *, required: bool) -> list[str]:
    if v is None:
        return [f"{path} is missing"] if required else []
    if not isinstance(v, dict):
        return [f"{path} is not an object"]
    return [
        f"{path}.{k} is missing" if k not in v else f"{path}.{k} is not a string"
        for k in ("legal_name", "brand_name", "domain_name")
        if not isinstance(v.get(k), str)
    ]


RP_MEMBERS = ("agent_key", "checkout_id", "merchant_id", "total", "require_constraints")
"""Relying-party expectations accepted at the top level of ``verify_bundle(expected=...)``."""


def _check_rp(expected: dict[str, Any]) -> dict[str, Any]:
    """Validate the relying-party members of ``expected`` (checks EX01-EX05)."""
    rp: dict[str, Any] = {}
    if expected.get("agent_key") is not None:
        try:
            rp["agent_key"] = load_public_jwk(expected["agent_key"])
        except JoseError as exc:
            raise InputError(f"expected.agent_key: {exc}") from None
    for k in ("checkout_id", "merchant_id"):
        if expected.get(k) is not None:
            if not isinstance(expected[k], str) or not expected[k]:
                raise InputError(f"expected.{k} must be a non-empty string")
            rp[k] = expected[k]
    tot = expected.get("total")
    if tot is not None:
        if (
            not isinstance(tot, dict)
            or set(tot) != {"amount", "currency"}
            or not C.is_int(tot["amount"])
            or not currency.is_currency_code(tot["currency"])
        ):
            raise InputError(
                "expected.total must be {'amount': <integer minor units>, 'currency': <ISO 4217>}"
            )
        rp["total"] = dict(tot)
    req = expected.get("require_constraints")
    if req is not None:
        known = C.CHECKOUT_TYPES + C.PAYMENT_TYPES
        if not isinstance(req, list) or not all(isinstance(t, str) and t in known for t in req):
            raise InputError(
                "expected.require_constraints must be a list of constraint types, from: "
                + ", ".join(known)
            )
        rp["require_constraints"] = list(dict.fromkeys(req))
    return rp


def _check_history(history: Any) -> dict[str, Any]:
    """Validate ``verify_bundle(history=...)``: prior_total and prior_uses, both optional."""
    if history is None:
        return {}
    if not isinstance(history, dict) or set(history) - {"prior_total", "prior_uses"}:
        raise InputError(
            "history must be {'prior_total': {'amount': <int>, 'currency': <ISO 4217>}, "
            "'prior_uses': <int>} (both members optional)"
        )
    out: dict[str, Any] = {}
    pt = history.get("prior_total")
    if pt is not None:
        if (
            not isinstance(pt, dict)
            or set(pt) != {"amount", "currency"}
            or not C.is_int(pt["amount"])
            or pt["amount"] < 0
            or not currency.is_currency_code(pt["currency"])
        ):
            raise InputError(
                "history.prior_total must be {'amount': <non-negative integer minor units>, "
                "'currency': <ISO 4217 code>}"
            )
        out["prior_total"] = dict(pt)
    pu = history.get("prior_uses")
    if pu is not None:
        if not C.is_int(pu) or pu < 0:
            raise InputError("history.prior_uses must be a non-negative integer")
        out["prior_uses"] = pu
    return out


def _check_expected(expected: Any) -> dict[str, dict[str, str]]:
    if expected is None:
        return {}
    if not isinstance(expected, dict):
        raise InputError(
            "expected must be {'checkout': {'aud': ..., 'nonce': ...}, 'payment': {...}}"
        )
    out: dict[str, dict[str, str]] = {}
    for kind, vals in expected.items():
        if kind in RP_MEMBERS:
            continue
        if kind not in ("checkout", "payment") or not isinstance(vals, dict):
            raise InputError(f"expected: unknown member {kind!r}")
        for claim, value in vals.items():
            if claim not in ("aud", "nonce") or not isinstance(value, str):
                raise InputError(
                    f"expected.{kind}: {claim!r} must be 'aud' or 'nonce' with a string"
                )
            out.setdefault(kind, {})[claim] = value
    return out


def verify_bundle(
    bundle: Any,
    *,
    trusted_keys: KeyStore | dict[str, Any] | None = None,
    skew: int = 300,
    at: int | None = None,
    expected: dict[str, Any] | None = None,
    require_pinned: bool = False,
    history: dict[str, Any] | None = None,
) -> Report:
    """Verify an evidence bundle and return the report.

    Args:
        bundle: The parsed bundle (normally a dict in the ``ap2-evidence/1`` format).
            Anything else yields a FAILED report, never an exception.
        trusted_keys: Keys pinned by the verifier, either a loaded
            :class:`~ap2_evidence.bundle.KeyStore` or a ``{"role": [JWK, ...]}`` dict.
            They take precedence over keys inside the bundle.
        skew: Allowed clock skew in seconds for chronology checks.
        at: Optional Unix time at which validity is additionally asserted.
        expected: Pinned ``aud`` / ``nonce`` values, ``{"checkout": {"aud": ...}, ...}``;
            they take precedence over ``expected`` inside the bundle. Optional top-level
            relying-party members (checks EX01-EX05): ``agent_key`` (public JWK the closed
            mandates must be bound to, compared by RFC 7638 thumbprint), ``checkout_id``,
            ``merchant_id``, ``total`` (``{"amount": int, "currency": str}``) and
            ``require_constraints`` (constraint types the open mandates must carry).
        history: What the operator asserts happened under the open payment mandate before
            this payment, ``{"prior_total": {"amount": int, "currency": str},
            "prior_uses": int}`` (both optional). Used by PM39 for ``payment.budget`` and
            ``payment.agent_recurrence``; without it such a constraint is a required SKIP.
        require_pinned: If true, a signature check that succeeds only under a key supplied
            inside the bundle becomes a required SKIP (reason ``key_not_pinned``), so such a
            bundle is INCOMPLETE at best. Signatures checked against the agent key bound in
            an open mandate (CM08/PM08) are unaffected: that key is vouched for by the
            mandate issuer's signature, which this option makes pinned.

    Returns:
        The verification :class:`~ap2_evidence.report.Report`.

    Raises:
        InputError: If ``trusted_keys``, ``expected`` or ``history`` is invalid, or ``skew``
            is negative.
    """
    from .describe import build_conclusion, build_evidence, fallback_conclusion

    if not C.is_int(skew) or skew < 0:
        raise InputError("skew must be a non-negative integer number of seconds")
    pinned_expected = _check_expected(expected)
    rp = _check_rp(expected) if isinstance(expected, dict) else {}
    hist = _check_history(history)
    store: KeyStore | None
    if isinstance(trusted_keys, dict):
        store = KeyStore()
        store.add_role_map(trusted_keys, TRUSTED, "--trusted-keys")
        if store.problems or store.warnings:
            raise InputError("trusted keys: " + "; ".join(store.problems + store.warnings))
    else:
        store = trusted_keys
    v = _Verifier(bundle, store, skew, at, pinned_expected, require_pinned=bool(require_pinned))
    v.history = hist
    v.rp = rp
    v.verify()
    checks = [v.results[cid] for cid in REGISTRY]
    inputs: dict[str, Any] = {}
    b = bundle if isinstance(bundle, dict) else {}
    for m in ARTIFACTS:
        val = b.get(m)
        inputs[m] = (
            sha256_hex(val.encode("utf-8", "surrogatepass")) if isinstance(val, str) else None
        )
    options = {
        "skew_seconds": skew,
        "at": _utc(at) if at is not None else None,
        "trusted_keys": bool(store and store.entries),
        "roles": list(ROLES),
        "expected_pinned": sorted(f"{k}.{c}" for k, vals in pinned_expected.items() for c in vals),
        "require_pinned": bool(require_pinned),
        "expected_relying_party": sorted(rp),
        "history_supplied": sorted(hist),
    }
    try:
        evidence = build_evidence(v)
    except Exception as exc:  # noqa: BLE001 - the report must still be produced
        evidence = {
            "delegation": {"checkout": None, "payment": None},
            "authorised": {"checkout": None, "payment": None},
            "purchase": None,
            "payment": None,
            "receipts": {"checkout": None, "payment": None},
            "timeline": [],
            "error": f"the evidence section could not be built: {type(exc).__name__}",
        }
    report = Report(
        checks=checks,
        evidence=evidence,
        inputs=inputs,
        options=options,
        generated_at=_dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    )
    try:
        report.conclusion = build_conclusion(v, report)
    except Exception:  # noqa: BLE001
        report.conclusion = fallback_conclusion(report)
    return report
