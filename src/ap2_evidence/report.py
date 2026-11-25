"""Verification report: data model and text / Markdown / JSON / issue rendering.

All formats follow the same reading order for a dispute analyst: conclusion
(finding, what this means, what to do next, key trust), broken links, not
verified + warnings, evidence chain, all checks, limits, glossary. The HTML
format (:mod:`ap2_evidence.html`) uses the same order.

Every string that may come from a token is treated as untrusted: control
characters are escaped and whitespace is collapsed in text output, and
Markdown metacharacters are escaped (URLs and e-mail addresses are put in code
spans so they are not turned into links) in Markdown output. In the text
format only headings and the verdict start at column 0; all body text is
indented, so data cannot imitate a verdict line.
"""

from __future__ import annotations

import json
import platform
import re
import textwrap
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any

from ._version import __version__
from .checks import (
    EXPECT_OPTIONS,
    GROUPS,
    KEY_OPTIONS,
    REGISTRY,
    generic_action,
    reason_text,
)

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"
STATUSES = (PASS, FAIL, WARN, SKIP)

VERIFIED = "VERIFIED"
FAILED = "FAILED"
INCOMPLETE = "INCOMPLETE"

REPORT_SCHEMA_VERSION = "1"

ISSUE_MAX_CHARS = 60_000
"""Upper bound for ``--format issue`` (GitHub allows 65,536 characters per issue body)."""

ISSUE_MAX_ROWS = 80

ELLIPSIS = "…"
"""Marks a shortened key thumbprint; the text renderer prints it as '...'."""

FULL = 1_000_000
"""A length limit that never truncates (used for lines that must be shown in full)."""

LIMITS: list[str] = [
    "Trust in keys: the tool checks signatures against the keys it is given. It does not "
    "discover keys, and keys inside a bundle are only as trustworthy as whoever assembled it; "
    "use --trusted-keys to pin keys obtained from a source you trust.",
    "Keys are not bound to identities: the tool cannot know which key belongs to which "
    "merchant, user or agent provider, so any pinned key of a role is accepted for that role. "
    "Pin only the keys of the parties to this transaction. The report names the key "
    "(thumbprint) that verified each signature, and XC04 warns when the two mandates were "
    "signed by different issuer keys.",
    "Withheld disclosures: SD-JWT decoy digests cannot be told apart from withheld claims. A "
    "withheld constraint FAILs (CM22/PM22); any other digest without its disclosure in a "
    "mandate makes the verdict INCOMPLETE until the mandate is supplied with all disclosures "
    "as issued.",
    "Revocation and status of mandates or keys are not checked.",
    "x5c certificate chains are not validated in 0.1; a root token that relies on x5c is "
    "reported as not verified unless a key is supplied directly.",
    "Cumulative budgets and recurrence limits need the history of all payments under an open "
    "mandate; one bundle only shows one payment.",
    "Whether goods were delivered, refunds, chargebacks and anything after the receipts are "
    "outside AP2 evidence.",
    "AP2 v0.1 Intent / Cart mandates are not supported; only AP2 v0.2 mandate.checkout.* and "
    "mandate.payment.* are.",
    "Only ES256 (ECDSA P-256 / SHA-256) is verified; other algorithms are rejected.",
    "Wall-clock expiry is not checked (dispute evidence is always expired now) unless --at "
    "is given; only the relative chronology between artifacts is checked.",
    "Agent-to-agent delegation chains (more than two segments) are outside AP2 v0.2 and are "
    "not verified.",
    "The checkout content is read as a UCP Checkout object; for other formats only the "
    "members that are present and well-typed (merchant, line_items, currency, totals) are "
    "used, and checks that need missing members are not verified.",
]
"""What this tool does not check (rendered in every report)."""

SIGNATURE_ROLES = {
    "CM03": "mandate issuer",
    "PM03": "mandate issuer",
    "CM32": "merchant",
    "CR02": "merchant",
    "PR02": "payment processor",
}
"""Checks that verify a role key (as opposed to the agent key from cnf.jwk)."""

RECEIPT_GATE = ("02", "03", "04", "06")
"""A receipt counts for :attr:`Report.outcome` only if these checks (with the PR / CR
prefix) passed: its signature, required fields, reference and time checks. The issuer
plausibility check (07) is a warning only: a receipt's ``iss`` is self-declared, and what
matters is which key signed it."""

ARTIFACT_PARTIES: dict[str, tuple[str, str]] = {
    "checkout_mandate": ("the checkout mandate", "the agent provider"),
    "payment_mandate": ("the payment mandate", "the agent provider"),
    "checkout_receipt": ("the Checkout Receipt", "the merchant"),
    "payment_receipt": ("the Payment Receipt", "the payment processor"),
}
"""Bundle member -> (name in plain words, who can supply it)."""

# --------------------------------------------------------------------------- root causes

_ALTERED = frozenset({"unreferenced_disclosure", "duplicate_disclosure"})


def _ids(prefix: str, *nums: int) -> frozenset[str]:
    return frozenset(f"{prefix}{n:02d}" for n in nums)


CAUSE_RULES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    (
        "CM04",
        _ALTERED,
        _ids("CM", 9, 17, 18, 21, 22, 34, 35) | {"PM31"},
    ),
    (
        "PM04",
        _ALTERED,
        _ids("PM", 9, 17, 18, 21, 22, 31, 32, 33, 34, 35, 36, 37, 38),
    ),
    (
        "CM10",
        _ALTERED,
        _ids("CM", 11, 12, 13, 18, 30, 31, 32, 33, 34, 35) | {"PM30", "XC01", "XC02"},
    ),
    (
        "PM10",
        _ALTERED,
        _ids("PM", 11, 12, 13, 18, 30, 32, 33, 34, 35, 36, 37, 38) | {"XC01", "XC02"},
    ),
    ("CM31", frozenset({"hash_mismatch"}), frozenset({"PM30"})),
)
"""When a failed check is reported as a consequence of another (``caused_by``).

Each rule is ``(primary check, primary reasons, dependent checks)``. A FAIL of a
dependent check is marked ``caused_by`` the primary only if the primary FAILED
with one of the listed reasons. The primary reasons are integrity failures that
prove the data the dependent checks read was altered after it was signed:

* ``CM04`` / ``PM04`` with an unreferenced or duplicate disclosure: the open
  mandate as presented is not the one issued, so checks that read its limits or
  hash it as presented (sd_hash binding, payment.reference) ran on altered data.
* ``CM10`` / ``PM10`` likewise for the closed mandate (which carries the checkout
  JWT, checkout_hash, amount and payee).
* ``CM31`` (checkout_hash differs from the checkout JWT): PM30 compares the
  payment's transaction_id with both values, so it cannot pass.

Signature failures are never primaries (a wrong key does not alter content).
Anything not covered here is shown as an independent failure. A consequence is
still listed, in full, and counted; only its presentation changes.
"""

# --------------------------------------------------------------------------- data model


@dataclass
class CheckResult:
    """The outcome of one check."""

    id: str
    group: str
    title: str
    status: str
    required: bool
    detail: str
    hint: str | None = None
    expected: str | None = None
    actual: str | None = None
    spec_ref: str = ""
    blocked_by: str | None = None
    key_provenance: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON form of this result."""
        return asdict(self)


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def short_thumbprint(thumb: str | None) -> str:
    """First 8 characters of a key thumbprint plus an ellipsis (for summaries)."""
    if not thumb:
        return "(none)"
    return thumb if len(thumb) <= 9 else thumb[:8] + ELLIPSIS


def plain_text(c: CheckResult, report: Report | None = None) -> str:
    """The plain-language sentence for a non-PASS result (falls back to the title).

    With ``report``, a B02 "missing artifact" result names the missing documents.
    """
    if report is not None and c.id in report.plain_overrides:
        return report.plain_overrides[c.id]
    if c.id == "B02" and c.reason == "missing_artifact" and report is not None:
        names = [n for m, (n, _p) in ARTIFACT_PARTIES.items() if report.inputs.get(m) is None]
        if names:
            verb = "is" if len(names) == 1 else "are"
            text = f"{_join(names)} {verb} not in the bundle."
            return text[:1].upper() + text[1:]
    rt = reason_text(c.id, c.reason)
    return rt.plain if rt is not None else f"{c.title}: this check did not pass."


def action_text(c: CheckResult, report: Report | None = None) -> str:
    """The next step for a non-PASS result (falls back to a generic line)."""
    if report is not None and c.id in report.action_overrides:
        return report.action_overrides[c.id]
    rt = reason_text(c.id, c.reason)
    if rt is not None and rt.action:
        return rt.action
    return generic_action(c.id)


_KEY_REASONS = frozenset({"no_key", "x5c_unsupported", "key_not_pinned"})


def shown_hint(c: CheckResult, report: Report | None = None) -> str | None:
    """The hint as shown to a reader: command-line options first, never "edit the bundle".

    The original hint (which may name API arguments) stays in the JSON report.
    """
    if report is not None and c.id in report.hint_overrides:
        return report.hint_overrides[c.id]
    role = SIGNATURE_ROLES.get(c.id)
    if c.reason in _KEY_REASONS and role is not None:
        opt = KEY_OPTIONS[role.replace(" ", "_")]
        return (
            f"get the {role}'s public key directly from the {role} (not from the bundle) and "
            f"check again with {opt} FILE or --trusted-keys FILE"
        )
    if c.reason == "not_expected" and c.id in EXPECT_OPTIONS:
        return f"to check it, run the verifier again with {EXPECT_OPTIONS[c.id]}"
    return c.hint


@dataclass
class Report:
    """A complete verification report.

    Use :meth:`to_json`, :meth:`to_text`, :meth:`to_markdown`, :meth:`to_html` or
    :meth:`to_issue`. ``finding``, ``meaning``, ``next_steps`` and ``notes`` are
    filled in by :func:`ap2_evidence.describe.build_conclusion`; when empty, a
    generic wording derived from the checks is used.
    """

    checks: list[CheckResult]
    evidence: dict[str, Any]
    inputs: dict[str, Any]
    options: dict[str, Any]
    generated_at: str
    conclusion: str = ""
    limits: list[str] = field(default_factory=lambda: list(LIMITS))
    finding: str = ""
    meaning: str = ""
    next_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    plain_overrides: dict[str, str] = field(default_factory=dict)
    """Check ID -> plain sentence with the concrete figures (set by describe; not in JSON)."""
    action_overrides: dict[str, str] = field(default_factory=dict)
    """Check ID -> next step with the concrete figures (set by describe; not in JSON)."""
    hint_overrides: dict[str, str] = field(default_factory=dict)
    """Check ID -> what the reader can do, naming command-line options (not in JSON)."""
    source_sha256: str | None = None
    """SHA-256 (hex) of the input file, if the caller computed it (shown in the HTML footer)."""

    @property
    def verdict(self) -> str:
        """FAILED if any FAIL, else INCOMPLETE if a required check is SKIP, else VERIFIED."""
        if any(c.status == FAIL for c in self.checks):
            return FAILED
        if any(c.status == SKIP and c.required for c in self.checks):
            return INCOMPLETE
        return VERIFIED

    @property
    def outcome(self) -> str:
        """What the receipts that count say happened.

        A receipt counts only if its signature, required fields, reference and time checks
        passed (payment receipt PR02, PR03, PR04, PR06; checkout receipt CR02, CR03, CR04,
        CR06; see :meth:`receipt_counts`). The issuer plausibility checks PR07 / CR07 are
        warnings only and do not decide whether a receipt counts. Then:

        * ``conflicting``: both receipts count and one says success, the other an error;
        * ``declined``: the payment receipt counts and says the payment was declined;
        * ``success``: the payment receipt counts and says Success, and the checkout receipt
          is absent or counts and says Success too;
        * ``unknown``: anything else (no counting payment receipt, or a checkout receipt that
          is present but does not count).
        """
        pay = self.receipt_says("payment")
        chk = self.receipt_says("checkout")
        if pay is not None and chk is not None and pay != chk:
            return "conflicting"
        if pay == "declined":
            return "declined"
        if pay == "success" and (chk == "success" or self._checkout_receipt_absent()):
            return "success"
        return "unknown"

    def _checkout_receipt_absent(self) -> bool:
        """True only if the bundle has no checkout receipt at all (not merely an unusable one)."""
        try:
            return self.check("CR01").reason == "missing_artifact"
        except KeyError:
            return False

    def receipt_counts(self, kind: str) -> bool:
        """True if the ``payment`` / ``checkout`` receipt passed its outcome gate.

        The gate is the signature, required fields, reference and time checks (PR02, PR03,
        PR04, PR06 / CR02, CR03, CR04, CR06). Both accepted receipt forms count the same
        way: the prose form (``result: success|error``) passes the fields check with the
        ``prose_receipt_form`` warning, and, because that form defines no ``iat``, its time
        check is not applicable rather than passed. The issuer plausibility check (PR07 /
        CR07) is a warning only and is not part of the gate.
        """
        prefix = "PR" if kind == "payment" else "CR"
        by_id = {c.id: c for c in self.checks}
        fields = by_id.get(prefix + "03")
        prose = (
            fields is not None and fields.status == WARN and fields.reason == "prose_receipt_form"
        )
        for n in RECEIPT_GATE:
            c = by_id.get(prefix + n)
            if c is None:
                return False
            if c.status == PASS:
                continue
            if n == "03" and prose:
                continue
            if n == "06" and prose and c.status == SKIP and c.reason == "not_applicable":
                continue
            return False
        return True

    def receipt_says(self, kind: str) -> str | None:
        """``success`` / ``declined`` for a receipt that counts (see :attr:`outcome`), else None."""
        prefix = "PR" if kind == "payment" else "CR"
        by_id = {c.id: c for c in self.checks}
        if not self.receipt_counts(kind):
            return None
        res = by_id.get(prefix + "05")
        if res is None:
            return None
        if res.status == PASS:
            return "success"
        if res.reason in ("declined", "rejected"):
            return "declined"
        return None

    @property
    def verdict_label(self) -> str:
        """The verdict as shown to readers, e.g. ``VERIFIED - PAYMENT DECLINED``."""
        if self.outcome == "declined":
            return f"{self.verdict} - PAYMENT DECLINED"
        if self.outcome == "conflicting":
            return f"{self.verdict} - RECEIPTS DISAGREE"
        return self.verdict

    @property
    def exit_code(self) -> int:
        """CLI exit code for the verdict: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE."""
        return {VERIFIED: 0, FAILED: 1, INCOMPLETE: 3}[self.verdict]

    def key_roles(self) -> dict[str, list[str]]:
        """Roles whose signatures were checked, by key provenance (``trusted`` / ``bundle``)."""
        out: dict[str, list[str]] = {"trusted": [], "bundle": []}
        for c in self.checks:
            role = SIGNATURE_ROLES.get(c.id)
            if role is None or c.status not in (PASS, FAIL) or not c.key_provenance:
                continue
            for prov in c.key_provenance.split("/"):
                if prov in out and role not in out[prov]:
                    out[prov].append(role)
        return out

    @property
    def key_trust(self) -> str:
        """``pinned``, ``bundle``, ``mixed`` or ``none``: where the role keys used came from."""
        roles = self.key_roles()
        if roles["trusted"] and roles["bundle"]:
            return "mixed"
        if roles["trusted"]:
            return "pinned"
        if roles["bundle"]:
            return "bundle"
        return "none"

    def key_trust_text(self) -> str:
        """Short wording of :attr:`key_trust` for the verdict line."""
        kt = self.key_trust
        if kt == "pinned":
            return "keys: pinned"
        if kt == "bundle":
            return "keys: supplied in bundle, not pinned"
        if kt == "mixed":
            roles = self.key_roles()
            return (
                f"keys: mixed - pinned for {_join(roles['trusted'])}; supplied in bundle for "
                f"{_join(roles['bundle'])}"
            )
        return "keys: none used, no issuer/merchant/processor signature checked"

    def key_trust_sentence(self) -> str:
        """The key-trust caveat in plain words, explaining what "pinned" means."""
        roles = self.key_roles()
        parts: list[str] = []
        if roles["bundle"]:
            whose = _join([f"the {r}" for r in roles["bundle"]])
            opts = ", ".join(KEY_OPTIONS[r.replace(" ", "_")] for r in roles["bundle"])
            parts.append(
                f"The signatures of {whose} were checked with keys that came inside the file "
                "itself. Whoever assembled the file could have put any keys there. Get the keys "
                f"directly from {whose} and check again. (For whoever runs the tool: give them "
                f"with {opts} or --trusted-keys; keys given that way are called pinned keys.)"
            )
        if roles["trusted"]:
            whose = _join([f"the {r}" for r in roles["trusted"]])
            parts.append(
                f"The signatures of {whose} were checked with keys that the person running the "
                "tool supplied (pinned keys, e.g. with --trusted-keys), not keys from the file, "
                "so they are as trustworthy as the source those keys came from."
            )
        if not parts:
            parts.append(
                "No signature of the mandate issuer, merchant or payment processor was checked, "
                "because no key for them was used."
            )
        return " ".join(parts)

    def summary(self) -> dict[str, int]:
        """Count results per status."""
        return {s.lower(): sum(1 for c in self.checks if c.status == s) for s in STATUSES}

    def check(self, check_id: str) -> CheckResult:
        """Return the result for ``check_id``."""
        for c in self.checks:
            if c.id == check_id:
                return c
        raise KeyError(check_id)

    def causes(self) -> dict[str, str]:
        """Failed check ID -> the root failure it follows from (see :data:`CAUSE_RULES`)."""
        by_id = {c.id: c for c in self.checks}
        direct: dict[str, str] = {}
        for c in self.checks:
            if c.status != FAIL or c.reason in OWN_VIOLATIONS:
                continue
            for primary, reasons, deps in CAUSE_RULES:
                p = by_id.get(primary)
                if (
                    primary != c.id
                    and c.id in deps
                    and p is not None
                    and p.status == FAIL
                    and p.reason in reasons
                ):
                    direct[c.id] = primary
                    break
        out: dict[str, str] = {}
        for cid, root in direct.items():
            seen = {cid}
            while root in direct and root not in seen:
                seen.add(root)
                root = direct[root]
            out[cid] = root
        return out

    def primary_failures(self) -> list[CheckResult]:
        """FAIL results that are not a consequence of another failure."""
        causes = self.causes()
        return [c for c in self.checks if c.status == FAIL and c.id not in causes]

    def consequences_of(self, check_id: str) -> list[CheckResult]:
        """FAIL results whose root failure is ``check_id``."""
        causes = self.causes()
        return [c for c in self.checks if causes.get(c.id) == check_id]

    def broken_links(self) -> list[dict[str, Any]]:
        """FAIL results as what is wrong / what the check is for / where to look."""
        causes = self.causes()
        return [
            {
                "id": c.id,
                "title": c.title,
                "reason": c.reason,
                "what": c.detail,
                "why": REGISTRY[c.id].why,
                "where": c.hint,
                "caused_by": causes.get(c.id),
            }
            for c in self.checks
            if c.status == FAIL
        ]

    def not_verified(self) -> list[dict[str, Any]]:
        """Required SKIP results (the reasons the verdict may be INCOMPLETE)."""
        return [
            {
                "id": c.id,
                "title": c.title,
                "reason": c.detail,
                "reason_code": c.reason,
                "hint": c.hint,
                "blocked_by": c.blocked_by,
            }
            for c in self.checks
            if c.status == SKIP and c.required
        ]

    def warnings(self) -> list[dict[str, Any]]:
        """WARN results."""
        return [
            {"id": c.id, "title": c.title, "reason": c.reason, "detail": c.detail, "hint": c.hint}
            for c in self.checks
            if c.status == WARN
        ]

    # ------------------------------------------------------------------ conclusion parts

    def effective_finding(self) -> str:
        """:attr:`finding`, or a generic one derived from the checks."""
        return self.finding or default_finding(self)

    def effective_meaning(self) -> str:
        """:attr:`meaning`, or a generic one derived from the checks."""
        return self.meaning or default_meaning(self)

    def effective_next_steps(self) -> list[str]:
        """:attr:`next_steps`, or the list derived from the checks."""
        return list(self.next_steps) or derive_next_steps(self)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON form (validates against ``schemas/report.schema.json``)."""
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": {"name": "ap2-evidence", "version": __version__},
            "ap2_spec": "0.2",
            "generated_at": self.generated_at,
            "verdict": self.verdict,
            "outcome": self.outcome,
            "key_trust": self.key_trust,
            "summary": self.summary(),
            "conclusion": self.conclusion,
            "finding": self.effective_finding(),
            "meaning": self.effective_meaning(),
            "next_steps": self.effective_next_steps(),
            "broken_links": self.broken_links(),
            "not_verified": self.not_verified(),
            "warnings": self.warnings(),
            "evidence": self.evidence,
            "checks": [c.to_dict() for c in self.checks],
            "limits": list(self.limits),
            "inputs": self.inputs,
            "options": self.options,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Render as JSON (ASCII only)."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True) + "\n"

    def to_text(self) -> str:
        """Render as plain text with ASCII status markers."""
        return _TextRenderer(self).render()

    def to_markdown(self) -> str:
        """Render as Markdown; token-derived strings are escaped."""
        return _MarkdownRenderer(self).render()

    def to_html(self) -> str:
        """Render as one self-contained HTML page (inline CSS, no scripts, no external loads)."""
        from .html import render_html

        return render_html(self)

    def to_issue(self, command: str = "verify") -> str:
        """Render a short Markdown block for a GitHub issue (no evidence section)."""
        return _render_issue(self, command)


# --------------------------------------------------------------------------- conclusion

_VIOLATIONS = frozenset(
    {
        "merchant_not_allowed",
        "payee_not_allowed",
        "item_not_acceptable",
        "quantity_exceeded",
        "requirement_unfilled",
        "amount_above_max",
        "amount_below_min",
        "currency_mismatch",
        "instrument_not_allowed",
        "pisp_not_allowed",
        "execution_date_before_window",
        "execution_date_after_window",
        "budget_exceeded",
        "occurrences_exceeded",
        "preset_claim_changed",
        "signed_before_open",
        "signed_after_expiry",
    }
)


OWN_VIOLATIONS = _VIOLATIONS | frozenset(
    {"amount_mismatch", "payee_mismatch", "total_mismatch", "merchant_id_mismatch"}
)
"""Reasons that state a violation found in the check's own data: never shown as a consequence."""

HISTORY_CHECKS = frozenset({"PM39"})
"""Checks whose result rests on history figures supplied by the person running the tool."""


def undermines(report: Report) -> str | None:
    """Whose claim the first primary failure undermines, where the failing check makes it clear.

    Returns None when no check gives a clear answer.
    """
    status = {c.id: c.status for c in report.checks}
    out: list[str] = []
    claims: list[str] = []
    for c in report.primary_failures():
        text = _undermines_one(c, status)
        if text and text.startswith(_AGENT_SIGNED):
            claim = text[len(_AGENT_SIGNED) :].rstrip(".")
            if claim not in claims:
                claims.append(claim)
            if _AGENT_SIGNED not in out:
                out.append(_AGENT_SIGNED)
        elif text and text not in out:
            out.append(text)
    out = [_AGENT_SIGNED + " or ".join(claims) + "." if t == _AGENT_SIGNED else t for t in out]
    return " ".join(out[:2]) or None


_AGENT_SIGNED = (
    "The agent the user authorised signed this payment itself, so the agent provider cannot "
    "claim its agent "
)


def _undermines_one(c: CheckResult, status: dict[str, str]) -> str | None:
    """Whose claim one primary failure undermines, or None."""
    prefix = c.id[:2]
    if c.id in HISTORY_CHECKS:
        return (
            "This result rests on the history figures supplied by the person running the "
            "verifier, not on the bundle. If those figures are right, the agent the user "
            "authorised signed a payment that the user's cumulative limit does not allow."
        )
    if c.reason in _VIOLATIONS and prefix in ("CM", "PM"):
        if status.get(f"{prefix}08") == PASS:
            return (
                "The agent the user authorised signed this payment itself, so the agent "
                "provider cannot claim its agent stayed within the user's limit."
            )
        return (
            "It undermines a claim by the agent provider that its agent stayed within the "
            "user's limit."
        )
    if c.id in ("XC01", "XC02") and c.reason in ("amount_mismatch", "payee_mismatch"):
        if status.get("PM08") == PASS:
            return (
                "The agent the user authorised signed this payment itself, so the agent "
                "provider cannot claim its agent paid what the merchant's checkout asked for."
            )
        return (
            "It undermines a claim by the agent provider that its agent paid what the "
            "merchant's checkout asked for."
        )
    if c.reason in _ALTERED:
        return "Whoever supplied this file supplied altered evidence."
    if c.reason in ("binding_mismatch", "hash_mismatch"):
        return (
            "The documents in this file do not belong together, or one of them was changed "
            "after it was signed; whoever supplied the file should explain why."
        )
    if c.id in ("PM30", "PM31") and c.reason in (
        "reference_mismatch",
        "transaction_id_mismatch",
        "checkout_hash_mismatch",
    ):
        return (
            "The payment and checkout documents do not belong to one transaction, which "
            "undermines a claim that they show this payment."
        )
    if c.reason == "signature_invalid":
        if c.id in ("CM03", "PM03"):
            return (
                "It undermines a claim that the mandate issuer (the user's credential or "
                "agent provider) issued the user's instructions."
            )
        if c.id in ("CM08", "PM08"):
            return (
                "It undermines a claim that the agent the user authorised approved this "
                "transaction."
            )
        if c.id == "CM32":
            return "It undermines a claim that the merchant issued this checkout."
        if c.id in ("CR02", "PR02"):
            who = "merchant" if c.id == "CR02" else "payment processor"
            return f"It undermines a claim that the {who} issued this receipt."
    if c.id in ("CR04", "PR04") and c.reason == "reference_mismatch":
        who = "merchant" if c.id == "CR04" else "payment processor"
        return f"It undermines a claim that the {who} confirmed this particular transaction."
    if c.id in ("CR05", "PR05") and c.reason == "rejected":
        who = "merchant" if c.id == "CR05" else "payment processor"
        return (
            f"The {who} rejected the transaction, so the bundle documents that this step did "
            "not complete."
        )
    return None


def default_finding(report: Report) -> str:
    """A generic finding derived from the checks only (used if no richer one was built)."""
    verdict = report.verdict
    if verdict == FAILED:
        prim = report.primary_failures()
        text = " ".join(plain_text(c, report) for c in prim[:2])
        if len(prim) > 2:
            text += f" {len(prim) - 2} further independent problem(s) are listed below."
        return text
    if verdict == INCOMPLETE:
        n = len(report.not_verified())
        return f"Nothing was found broken, but {n} required check(s) could not be done."
    return "Every required check passed."


def default_meaning(report: Report) -> str:
    """A generic 'what this means' derived from the checks only."""
    verdict = report.verdict
    if verdict == FAILED:
        text = "This bundle cannot be used to show that the payment was authorised."
        und = undermines(report)
        return text + (" " + und if und else "")
    if verdict == INCOMPLETE:
        return (
            "Nothing in the bundle contradicts the claim that the payment was authorised, but "
            "the bundle does not prove it yet; see the checks that could not be done below."
        )
    return (
        "The checks this tool performs all passed. This does not show who the signing keys "
        "belong to, whether the goods were delivered, or other payments under the same mandate."
    )


_NUMBER_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")


def number_word(n: int) -> str:
    """'three' for 3 (up to nine), else the digits."""
    return _NUMBER_WORDS[n] if 0 <= n < len(_NUMBER_WORDS) else str(n)


ORIGINAL_OF: dict[str, str] = {
    "CM04": "the user's original shopping instructions",
    "PM04": "the user's original payment instructions",
    "CM10": "the agent's original checkout approval",
    "PM10": "the agent's original payment approval",
    "CM31": "the checkout the agent actually approved",
}
"""What to obtain before checking again, for each primary of :data:`CAUSE_RULES`."""


def side_effects_sentence(report: Report) -> str | None:
    """'Three further failures are side effects of this change; ...' (no check IDs)."""
    causes = report.causes()
    if not causes:
        return None
    roots = sorted(set(causes.values()))
    n = len(causes)
    what = _join([ORIGINAL_OF.get(r, "the original documents") for r in roots])
    are = "is a side effect" if n == 1 else "are side effects"
    failures = "failure" if n == 1 else "failures"
    text = (
        f"{number_word(n)} further {failures} {are} of this change; check again once you "
        f"have {what}."
    )
    return text[:1].upper() + text[1:]


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    for i in items:
        if i and i not in out:
            out.append(i)
    return out


def _key_step(roles: list[str]) -> str:
    whose = _join([f"the {r}" for r in roles])
    opts = ", ".join(KEY_OPTIONS[r.replace(" ", "_")] for r in roles)
    plural = "s" if len(roles) > 1 else ""
    return (
        f"Get the public key{plural} directly from {whose} (not from the file) and check again "
        f"with {opts} (or --trusted-keys FILE)."
    )


def derive_next_steps(report: Report) -> list[str]:
    """Concrete next steps from the failing, not-verified and warning results."""
    steps: list[str] = []
    for c in report.primary_failures():
        steps.append(action_text(c, report))
    signers: list[str] = []
    for c in report.checks:
        if c.status != SKIP or not c.required or c.blocked_by:
            continue
        if c.id == "B02" and c.reason == "missing_artifact":
            for member, (name, party) in ARTIFACT_PARTIES.items():
                if report.inputs.get(member) is None:
                    steps.append(f"Ask {party} for {name}.")
            continue
        if c.reason in _KEY_REASONS:
            role = SIGNATURE_ROLES.get(c.id)
            if role is not None:
                if role not in signers:
                    signers.append(role)
                continue
        steps.append(action_text(c, report))
    if signers:
        steps.append(_key_step(signers))
    for c in report.checks:
        if c.status == WARN:
            if c.reason in ("declined", "rejected"):
                kind = "payment" if c.id == "PR05" else "checkout"
                if report.outcome == "conflicting" or not report.receipt_counts(kind):
                    # Only a decline in a receipt that counts says this; disagreeing receipts
                    # get their own step (describe._receipt_steps).
                    continue
            if c.id in report.action_overrides:
                steps.append(report.action_overrides[c.id])
                continue
            rt = reason_text(c.id, c.reason)
            if rt is not None and rt.action:
                steps.append(rt.action)
    roles = report.key_roles()
    if roles["bundle"]:
        steps.append(_key_step(roles["bundle"]))
    if not steps:
        steps.append(NOTHING_MORE)
    return _dedupe(steps)


NOTHING_MORE = (
    "Nothing more is needed for what this tool checks; see the limits section for what it does "
    "not check."
)
"""The only next step when there is nothing to ask anyone (never shown next to another step)."""


# --------------------------------------------------------------------------- helpers

_WS = re.compile(r"\s+")


def clean(value: Any, limit: int = 400, *, collapse: bool = True) -> str:
    r"""Make an untrusted value safe to print on a terminal.

    Control and format characters (including ANSI escape sequences and
    bidirectional overrides) are replaced with ``\xNN`` / ``\uNNNN`` escapes,
    runs of whitespace are collapsed to one space (unless ``collapse`` is False)
    and long values are shortened at a word boundary (when there is one in the
    last third of the allowed length) followed by ``...``.
    """
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if collapse:
        text = _WS.sub(" ", text)
    out: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > limit:
        cut = result[:limit]
        if not result[limit].isspace():
            space = cut.rfind(" ")
            if space >= (2 * limit) // 3:
                cut = cut[:space]
        cut = cut.rstrip()
        result = f"{cut}... ({len(result) - len(cut)} more characters)"
    return result


_MD_SPECIAL = set("\\`*_[]<>|~#{}")
_LINKY = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9+.\-]*://|www\.)[^\s|`<>]+|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)
_TRAILING = ".,;:!?'\""


def _trim_link(link: str) -> str:
    """Drop trailing punctuation and unbalanced closing brackets that end a sentence."""
    while link:
        last = link[-1]
        if last in _TRAILING:
            link = link[:-1]
        elif last in ")]}":
            opening = {")": "(", "]": "[", "}": "{"}[last]
            if link.count(opening) < link.count(last):
                link = link[:-1]
            else:
                break
        else:
            break
    return link


def _md_escape(text: str) -> str:
    return "".join("\\" + ch if ch in _MD_SPECIAL else ch for ch in text)


def md(value: Any, limit: int = 400) -> str:
    """Escape an untrusted value for inline Markdown (also safe inside table cells).

    URLs and e-mail addresses become code spans so Markdown renderers do not
    turn them into clickable links; punctuation that ends the sentence (such
    as a closing parenthesis) stays outside the code span.
    """
    text = clean(value, limit)
    out: list[str] = []
    pos = 0
    for m in _LINKY.finditer(text):
        link = _trim_link(m.group(0))
        if not link:
            continue
        end = m.start() + len(link)
        out.append(_md_escape(text[pos : m.start()]))
        out.append("`" + link.replace("`", "'") + "`")
        pos = end
    out.append(_md_escape(text[pos:]))
    return "".join(out)


MARK = {PASS: "[PASS]", FAIL: "[FAIL]", WARN: "[WARN]", SKIP: "[SKIP]"}


def underlying_line(n_primary: int, n_fails: int) -> str:
    """Say how many failures are underlying and how many follow from them."""
    rest = n_fails - n_primary
    problems = "problem" if n_primary == 1 else "problems"
    failures = "failure follows" if rest == 1 else "failures follow"
    it = "it" if n_primary == 1 else "them"
    return f"{n_primary} underlying {problems}; the other {rest} {failures} from {it}."


INSPECT_LINE = (
    "To see the segments and disclosures these findings refer to, run: "
    "ap2-evidence inspect <the same bundle or token file>"
)

TIMELINE_NOTE = (
    "AP2 defines no order between the two closed mandates or between the two receipts; the "
    "closed payment mandate may precede the closed checkout mandate (as in the official samples)."
)

EVIDENCE_NOTE = (
    "Values below are as stated in the artifacts. They are proven only as far as the checks passed."
)

CONSEQUENCE_NOTE = (
    "These checks read data that {id} shows was altered after it was signed, so their failure "
    "follows from it. Check them again once {id} is resolved."
)

ISSUE_SKIP_NOTE = (
    "{n} further check(s) were skipped because they do not apply to this input (not required); "
    "they are not listed."
)


def group_not_verified(
    report: Report, items: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[tuple[str, str, list[str]]]]:
    """Split required SKIPs into root causes and (blocker, state, ids) groups."""
    roots: list[dict[str, Any]] = []
    groups: dict[str, list[str]] = {}
    for n in items:
        by = n.get("blocked_by")
        if by:
            groups.setdefault(by, []).append(n["id"])
        else:
            roots.append(n)
    out: list[tuple[str, str, list[str]]] = []
    for by, ids in groups.items():
        try:
            st = report.check(by).status
        except KeyError:  # pragma: no cover
            st = SKIP
        state = {FAIL: "failed", SKIP: "was not completed", WARN: "raised a warning"}.get(
            st, "did not pass"
        )
        out.append((by, state, ids))
    return roots, out


_group_not_verified = group_not_verified


def evidence_lines(ev: dict[str, Any]) -> list[tuple[int, str]]:
    """Flatten the evidence section into (indent level, line) pairs of plain text."""
    try:
        return _evidence_lines_unsafe(ev)
    except Exception:  # noqa: BLE001 - never let the evidence section break the report
        return [(0, "The evidence section could not be rendered.")]


_evidence_lines = evidence_lines


STATUS_GLOSS = {
    "incomplete": "in UCP, the state of a checkout before the buyer completes it; the official "
    "AP2 samples sign checkouts in this state",
    "ready_for_complete": "in UCP, ready for the buyer to complete",
    "requires_escalation": "in UCP, the checkout needs the buyer's attention before it can be "
    "completed",
    "complete_in_progress": "in UCP, the checkout is being completed",
    "completed": "in UCP, the checkout was completed",
    "canceled": "in UCP, the checkout was canceled",
}
"""Plain-language glosses of UCP checkout status values."""

NOTE_LABEL = "Note supplied with the bundle (free text, not verified)"


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _evidence_lines_unsafe(ev: dict[str, Any]) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    if ev.get("error"):
        lines.append((0, str(ev["error"])))
    if isinstance(ev.get("note"), str) and ev["note"]:
        lines.append((0, NOTE_LABEL))
        lines.append((1, '"' + ev["note"] + '"'))
    deleg = ev.get("delegation") or {}
    lines.append((0, "Who delegated to which agent key"))
    for kind in ("checkout", "payment"):
        d = deleg.get(kind)
        if not d:
            lines.append((1, f"{kind}: no {kind} mandate"))
            continue
        lines.append((1, f"{kind}: {d.get('summary', '')}"))
    keys = ev.get("keys")
    if keys:
        lines.append((0, "Keys used to check the signatures (full RFC 7638 thumbprints)"))
        for k in keys:
            used = _join([str(x) for x in k.get("used_for", [])])
            prov = k.get("provenance")
            prov_txt = f"; {prov}" if prov else ""
            role, thumb = k.get("role"), k.get("thumbprint")
            if used:
                lines.append((1, f"{role} key {thumb} (verified {used}{prov_txt})"))
            else:
                lines.append((1, f"{role} key {thumb} ({prov or 'source unknown'})"))
            for what in k.get("failed_for") or []:
                lines.append(
                    (
                        2,
                        f"{_cap(str(what))} was NOT signed by this {role} key, which the user's "
                        "mandate names.",
                    )
                )
    auth = ev.get("authorised") or {}
    lines.append((0, "What was authorised (open mandate constraints and pre-set claims)"))
    for kind in ("checkout", "payment"):
        items = auth.get(kind)
        if items is None:
            lines.append((1, f"{kind}: no open {kind} mandate"))
        elif not items:
            lines.append((1, f"{kind}: no constraints disclosed"))
        else:
            lines.append((1, f"{kind}:"))
            lines.extend((2, f"- {x}") for x in items)
    pur = ev.get("purchase")
    if not pur:
        lines.append((0, "What was bought (checkout JWT)"))
        lines.append((1, "no readable checkout JWT"))
    else:
        sig = pur.get("merchant_signature")
        if sig == "verified":
            lines.append((0, "What was bought (merchant-signed checkout JWT)"))
        else:
            lines.append((0, f"What was bought (checkout JWT; merchant signature {sig})"))
        for label, key in (
            ("merchant", "merchant"),
            ("checkout id", "checkout_id"),
            ("checkout status", "status"),
        ):
            if pur.get(key) is not None:
                gloss = STATUS_GLOSS.get(str(pur[key])) if key == "status" else None
                lines.append((1, f"{label}: {pur[key]}" + (f" ({gloss})" if gloss else "")))
        for item in pur.get("items", []):
            lines.append((1, f"item: {item}"))
        if pur.get("total") is not None:
            lines.append((1, f"total: {pur['total']}"))
        if pur.get("note"):
            lines.append((1, f"note: {pur['note']}"))
    pay = ev.get("payment")
    lines.append((0, "What the agent approved for payment (closed payment mandate)"))
    if not pay:
        lines.append((1, "no readable closed payment mandate"))
    else:
        for label, key in (
            ("amount", "amount"),
            ("payee", "payee"),
            ("instrument", "instrument"),
            ("PISP", "pisp"),
            ("execution date", "execution_date"),
            ("transaction_id", "transaction_id"),
        ):
            if pay.get(key) is not None:
                lines.append((1, f"{label}: {pay[key]}"))
    rec = ev.get("receipts") or {}
    lines.append((0, "Receipts"))
    for kind in ("checkout", "payment"):
        r = rec.get(kind)
        name = "Checkout Receipt" if kind == "checkout" else "Payment Receipt"
        lines.append((1, f"{name}: {r['summary'] if r else 'not in the bundle'}"))
    lines.append((0, "Timeline (UTC)"))
    timeline = ev.get("timeline") or []
    if not timeline:
        lines.append((1, "no timestamps found"))
    for t in timeline:
        lines.append((1, f"{t['time']}  {t['event']}"))
    if timeline:
        lines.append((1, f"Note: {TIMELINE_NOTE}"))
    return lines


# --------------------------------------------------------------------------- glossary

GLOSSARY: list[tuple[str, str, str]] = [
    (
        "open mandate",
        r"\bopen (?:checkout |payment )?mandates?\b",
        "The user's (or their agent provider's) signed instructions to an agent: which agent key "
        "may act and within which limits (allowed merchants, items, amounts).",
    ),
    (
        "closed mandate",
        r"\bclosed (?:checkout |payment )?mandates?\b",
        "The agent's signed approval of one specific checkout or payment, made under an open "
        "mandate.",
    ),
    (
        "mandate issuer",
        r"\bmandate[ _-]issuer",
        "The party whose key signs the open mandates: the user's credential or the agent "
        "provider acting for the user.",
    ),
    (
        "agent provider",
        r"\bagent provider",
        "The company operating the AI agent that shopped and paid for the user.",
    ),
    (
        "segment",
        r"\bsegments?\b",
        "One signed token inside a mandate: segment 1 is the open mandate, segment 2 the closed "
        "mandate.",
    ),
    (
        "disclosure",
        r"\bdisclosures?\b",
        "A piece of a mandate that is revealed separately; the signed token holds only its "
        "digest, so a changed or added disclosure no longer matches.",
    ),
    (
        "digest",
        r"\bdigests?\b",
        "A fingerprint (hash) of a piece of data; if the data changes, the digest no longer "
        "matches.",
    ),
    (
        "withheld",
        r"\bwithheld\b|\bundisclosed\b|\bnot disclosed\b",
        "A part of a mandate whose disclosure was left out of the bundle; its content cannot be "
        "seen or checked.",
    ),
    (
        "constraint",
        r"\bconstraints?\b",
        "A limit the user set in the open mandate, for example a maximum amount or a list of "
        "allowed merchants.",
    ),
    (
        "key binding",
        r"\bkey[ -]binding\b|\bbound agent key\b|\bcnf(?:\.jwk)?\b",
        "The open mandate names one agent key (cnf.jwk); only that key may sign the closed "
        "mandate.",
    ),
    (
        "thumbprint",
        r"\bthumbprints?\b",
        "A short fingerprint that identifies a public key (RFC 7638).",
    ),
    (
        "pinned key",
        r"\bpinned\b|--trusted-keys",
        "A public key you gave this tool with --trusted-keys, obtained from a source you trust. "
        "Keys that only came inside the bundle are only as trustworthy as whoever assembled it.",
    ),
    (
        "kid",
        r"\bkid\b",
        "Key identifier: a label in a token's header that names the key meant to verify it.",
    ),
    (
        "checkout JWT",
        r"\bcheckout[ _]jwt\b|\bsigned checkout\b",
        "The merchant's signed statement of the checkout: items, prices, total and merchant.",
    ),
    (
        "checkout_hash",
        r"\bcheckout_hash\b",
        "The fingerprint of the merchant's checkout JWT inside the closed checkout mandate; it is "
        "how the agent's signature covers the checkout.",
    ),
    (
        "transaction_id",
        r"\btransaction_id\b",
        "The fingerprint of the checkout inside the payment mandate; it ties the payment to the "
        "checkout.",
    ),
    (
        "sd_hash",
        r"\bsd_hash\b|\bissuer_jwt_hash\b",
        "The fingerprint of the open mandate inside the closed mandate; it ties the agent's "
        "approval to the user's instructions.",
    ),
    (
        "receipt reference",
        r"\breference\b",
        "The fingerprint inside a receipt (or in payment.reference) of the mandate it belongs to.",
    ),
    (
        "SD-JWT",
        r"\bSD-JWT\b|\bkb\+sd-jwt\b",
        "Selective-Disclosure JSON Web Token: the signed token format of AP2 mandates.",
    ),
    (
        "vct",
        r"\bvct\b",
        "The type label of a mandate, for example mandate.payment.1.",
    ),
    (
        "iat / exp",
        r"\biat\b|\bexp\b",
        "Issued-at and expiry times inside a token (Unix seconds, shown in UTC).",
    ),
    (
        "PISP",
        r"\bPISPs?\b",
        "Payment initiation service provider: the service that starts the payment from the "
        "user's account.",
    ),
    (
        "UCP Checkout",
        r"\bUCP\b",
        "The standard checkout format the merchant's checkout JWT is expected to use.",
    ),
    (
        "minor units",
        r"\bminor units\b",
        "Amounts counted in the smallest currency unit, e.g. cents (19900 = USD 199.00).",
    ),
]
"""Glossary entries: (term, pattern that finds it in a report, definition in plain words)."""


def glossary_for(text: str) -> list[tuple[str, str]]:
    """The glossary entries whose term occurs in ``text``, in glossary order."""
    return [
        (term, definition)
        for term, pattern, definition in GLOSSARY
        if re.search(pattern, text, re.IGNORECASE)
    ]


def report_glossary(report: Report) -> list[tuple[str, str]]:
    """The glossary of terms that appear in the rendered report (same for all formats)."""
    return glossary_for(_TextRenderer(report).render_body())


# --------------------------------------------------------------------------- text


_LABEL_LIKE = re.compile(
    r"(?:#+\s*)?\**\s*(?:(?:verdict|finding|what this means|what to do next|about the keys|"
    r"keys|checks|what is wrong|technical detail|where to look|what this check is for|"
    r"reason code|not checked|warning|what you can do|consequences of [a-z]{2}\d\d)"
    r"\s*\**\s*:|note\b[^:]{0,60}:|generated at\b)"
    r"|\[(?:pass|fail|warn|skip)\]|- |\d+\.\s|=+$|-+$",
    re.IGNORECASE,
)
"""Line starts that only the report's own labels may produce."""


def _ascii_marks(text: str) -> str:
    return text.replace(ELLIPSIS, "...")


class _TextRenderer:
    WIDTH = 100
    BODY = 2  # every body line is indented by at least this much

    def __init__(self, report: Report) -> None:
        self.r = report
        self.out: list[str] = []

    def para(self, text: str, indent: int = 0, first: str = "") -> None:
        pad = " " * (self.BODY + indent)
        wrapped = textwrap.wrap(
            clean(_ascii_marks(text), FULL),
            width=self.WIDTH,
            initial_indent=pad + first,
            subsequent_indent=pad + " " * len(first),
            break_long_words=True,
            break_on_hyphens=False,
        )
        # A continuation line comes from the middle of a sentence, which may hold untrusted
        # data; if it would start like one of the report's own labels, mark it.
        for i in range(1, len(wrapped)):
            body = wrapped[i].lstrip(" ")
            if _LABEL_LIKE.match(body):
                wrapped[i] = wrapped[i][: len(wrapped[i]) - len(body)] + "| " + body
        self.out.extend(wrapped or [pad + first])

    def heading(self, text: str) -> None:
        self.out += ["", text, "-" * len(text)]

    def failure(self, c: CheckResult, indent: int) -> None:
        self.para(f"{c.id} {c.title}", indent=indent, first="[FAIL] ")
        sub = indent + 7
        self.para(f"What is wrong: {plain_text(c, self.r)}", indent=sub)
        self.para(f"Technical detail: {c.detail}", indent=sub)
        hint = shown_hint(c, self.r)
        if hint:
            self.para(f"Where to look (technical): {hint}", indent=sub)
        self.para(f"What this check is for: {REGISTRY[c.id].why}", indent=sub)
        self.para(f"Reason code: {c.reason}", indent=sub)

    def render_body(self) -> str:
        r = self.r
        title = f"AP2 evidence report (ap2-evidence {__version__}, AP2 v0.2)"
        self.out += [title, "=" * len(title)]
        s = r.summary()
        self.out.append(f"VERDICT: {r.verdict_label} ({r.key_trust_text()})")
        self.out.append(
            f"Checks: pass {s['pass']}, fail {s['fail']}, warn {s['warn']}, skip {s['skip']}"
        )
        self.heading("1. Conclusion")
        for note in r.notes:
            self.para(note)
        self.para(f"Finding: {r.effective_finding()}")
        self.out.append("")
        self.para(f"What this means: {r.effective_meaning()}")
        self.out.append("")
        self.para("What to do next:")
        for step in r.effective_next_steps():
            self.para(step, first="- ")
        self.out.append("")
        self.para(f"About the keys: {r.key_trust_sentence()}")

        fails = [c for c in r.checks if c.status == FAIL]
        prim = r.primary_failures()
        self.heading(f"2. Broken links ({len(fails)})")
        if not fails:
            self.para("None.")
        elif len(prim) != len(fails):
            self.para(underlying_line(len(prim), len(fails)))
        for c in prim:
            self.failure(c, 0)
            cons = r.consequences_of(c.id)
            if cons:
                self.para(f"Consequences of {c.id}: " + CONSEQUENCE_NOTE.format(id=c.id), 7)
                for d in cons:
                    self.failure(d, 7)
        if fails:
            self.para(INSPECT_LINE)

        nv, warns = r.not_verified(), r.warnings()
        self.heading(f"3. Not verified ({len(nv)}) and warnings ({len(warns)})")
        if not nv and not warns:
            self.para("None.")
        roots, groups = group_not_verified(r, nv)
        for n in roots:
            c = r.check(n["id"])
            self.para(f"{c.id} {c.title}", first="[SKIP] ")
            self.para(f"Not checked: {plain_text(c, self.r)}", indent=7)
            if not (c.id == "B02" and c.reason == "missing_artifact"):
                # for B02 the plain sentence already names the missing documents
                self.para(f"Technical detail: {c.detail}", indent=7)
            if c.hint:
                self.para(f"What you can do: {shown_hint(c, self.r)}", indent=7)
        for by, state, ids in groups:
            self.para(
                f"{len(ids)} check(s) not performed because {by} {state}: {', '.join(ids)}",
                first="[SKIP] ",
            )
        for w in warns:
            c = r.check(w["id"])
            self.para(f"{c.id} {c.title}", first="[WARN] ")
            self.para(f"Warning: {plain_text(c, self.r)}", indent=7)
            self.para(f"Technical detail: {c.detail}", indent=7)
            if c.hint:
                self.para(f"What you can do: {shown_hint(c, self.r)}", indent=7)

        self.heading("4. Evidence chain")
        self.para(EVIDENCE_NOTE)
        for level, line in evidence_lines(r.evidence):
            self.para(line, indent=2 * level)

        self.heading("5. All checks")
        causes = r.causes()
        for group, label in GROUPS.items():
            rows = [c for c in r.checks if c.group == group]
            if not rows:
                continue
            self.out += ["", f"  {label}:"]
            for c in rows:
                req = "" if c.required or c.status != SKIP else " (not required)"
                self.para(f"{c.id} {c.title}{req}", indent=2, first=MARK[c.status] + " ")
                self.para(c.detail, indent=12)
                if c.reason:
                    self.para(f"reason: {c.reason}", indent=12)
                if c.id in causes:
                    self.para(f"caused by: {causes[c.id]}", indent=12)
                if c.key_provenance:
                    self.para(f"key provenance: {c.key_provenance}", indent=12)
                if c.status != PASS and c.expected is not None:
                    self.para(f"expected: {c.expected}", indent=12)
                if c.status != PASS and c.actual is not None:
                    self.para(f"actual:   {c.actual}", indent=12)
                if c.status != PASS and shown_hint(c, r):
                    self.para(f"hint: {shown_hint(c, r)}", indent=12)
                if c.blocked_by:
                    self.para(f"blocked by: {c.blocked_by}", indent=12)

        self.heading("6. Limits (what this tool does not check)")
        for lim in r.limits:
            self.para(lim, first="- ")
        return "\n".join(self.out) + "\n"

    def render(self) -> str:
        body = self.render_body()
        self.heading("7. Glossary (terms used in this report)")
        for term, definition in glossary_for(body):
            self.para(f"{term}: {definition}", first="- ")
        self.out += ["", f"  Generated at {self.r.generated_at}."]
        return "\n".join(self.out) + "\n"


# --------------------------------------------------------------------------- markdown


class _MarkdownRenderer:
    def __init__(self, report: Report) -> None:
        self.r = report

    def failure(self, c: CheckResult, indent: str) -> list[str]:
        return [
            f"{indent}- **[FAIL] {c.id} {md(c.title)}**",
            f"{indent}  - What is wrong: {md(plain_text(c, self.r), FULL)}",
            f"{indent}  - Technical detail: {md(c.detail, FULL)}",
            *(
                [f"{indent}  - Where to look (technical): {md(shown_hint(c, self.r), FULL)}"]
                if shown_hint(c, self.r)
                else []
            ),
            f"{indent}  - What this check is for: {md(REGISTRY[c.id].why, FULL)}",
            f"{indent}  - Reason code: {md(c.reason or '')}",
        ]

    def render(self) -> str:
        r = self.r
        s = r.summary()
        out: list[str] = [
            "# AP2 evidence report",
            "",
            f"ap2-evidence {__version__}, AP2 v0.2. Generated at {md(r.generated_at)}.",
            "",
            f"**Verdict: {r.verdict_label}** ({md(r.key_trust_text())}). Checks: pass {s['pass']}, "
            f"fail {s['fail']}, warn {s['warn']}, skip {s['skip']}.",
            "",
            "## 1. Conclusion",
            "",
        ]
        for note in r.notes:
            out += [md(note, FULL), ""]
        out += [
            f"**Finding:** {md(r.effective_finding(), FULL)}",
            "",
            f"**What this means:** {md(r.effective_meaning(), FULL)}",
            "",
            "**What to do next:**",
            "",
        ]
        out += [f"- {md(step, FULL)}" for step in r.effective_next_steps()]
        out += ["", f"**About the keys:** {md(r.key_trust_sentence(), FULL)}", ""]
        fails = [c for c in r.checks if c.status == FAIL]
        prim = r.primary_failures()
        out += [f"## 2. Broken links ({len(fails)})", ""]
        if not fails:
            out += ["None.", ""]
        elif len(prim) != len(fails):
            out += [underlying_line(len(prim), len(fails)), ""]
        for c in prim:
            out += self.failure(c, "")
            cons = r.consequences_of(c.id)
            if cons:
                out.append(
                    f"  - Consequences of {c.id}: {md(CONSEQUENCE_NOTE.format(id=c.id), FULL)}"
                )
                for d in cons:
                    out += self.failure(d, "    ")
        if fails:
            out += ["", md(INSPECT_LINE)]
        out.append("")
        nv, warns = r.not_verified(), r.warnings()
        out += [f"## 3. Not verified ({len(nv)}) and warnings ({len(warns)})", ""]
        if not nv and not warns:
            out += ["None.", ""]
        roots, groups = group_not_verified(r, nv)
        for n in roots:
            c = r.check(n["id"])
            out += [
                f"- [SKIP] **{c.id} {md(c.title)}**: {md(plain_text(c, self.r), FULL)}",
                f"  - Technical detail: {md(c.detail, FULL)}",
            ]
            if c.hint:
                out.append(f"  - What you can do: {md(shown_hint(c, r), FULL)}")
        for by, state, ids in groups:
            out.append(
                f"- [SKIP] {len(ids)} check(s) not performed because {by} {state}: {', '.join(ids)}"
            )
        for w in warns:
            c = r.check(w["id"])
            out += [
                f"- [WARN] **{c.id} {md(c.title)}**: {md(plain_text(c, self.r), FULL)}",
                f"  - Technical detail: {md(c.detail, FULL)}",
            ]
            if c.hint:
                out.append(f"  - What you can do: {md(shown_hint(c, r), FULL)}")
        out += ["", "## 4. Evidence chain", "", EVIDENCE_NOTE, ""]
        for level, line in evidence_lines(r.evidence):
            if level == 0:
                out += ["", f"**{md(line)}**", ""]
            else:
                out.append("  " * (level - 1) + f"- {md(line.removeprefix('- '), FULL)}")
        out += ["", "## 5. All checks", ""]
        causes = r.causes()
        for group, label in GROUPS.items():
            rows = [c for c in r.checks if c.group == group]
            if not rows:
                continue
            out += [
                f"### {label}",
                "",
                "| Status | ID | Check | Required | Reason | Detail | Hint |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
            for c in rows:
                detail = c.detail
                if c.key_provenance:
                    detail += f" (key provenance: {c.key_provenance})"
                if c.status != PASS and c.expected is not None:
                    detail += f" Expected: {c.expected}. Actual: {c.actual}."
                if c.id in causes:
                    detail += f" Caused by {causes[c.id]}."
                hint = shown_hint(c, r) or ""
                if c.blocked_by:
                    hint = (hint + " " if hint else "") + f"Blocked by {c.blocked_by}."
                out.append(
                    f"| [{c.status}] | {c.id} | {md(c.title)} | "
                    f"{'yes' if c.required else 'no'} | {md(c.reason or '')} | "
                    f"{md(detail, 1500)} | {md(hint if c.status != PASS else '', 800)} |"
                )
            out.append("")
        out += ["## 6. Limits (what this tool does not check)", ""]
        out += [f"- {md(lim, FULL)}" for lim in r.limits]
        out += ["", "## 7. Glossary (terms used in this report)", ""]
        out += [f"- **{md(term)}**: {md(d, FULL)}" for term, d in report_glossary(r)]
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- issue


def os_family() -> str:
    """Windows, Linux, macOS or the platform's own system name."""
    system = platform.system()
    return {"Darwin": "macOS"}.get(system, system or "unknown OS")


def _render_issue(r: Report, command: str) -> str:
    s = r.summary()
    opts = r.options
    opt_parts = [f"skew {opts.get('skew_seconds')} s"]
    if opts.get("at"):
        opt_parts.append(f"--at {opts['at']}")
    opt_parts.append(f"--trusted-keys {'given' if opts.get('trusted_keys') else 'not given'}")
    if opts.get("expected_pinned"):
        opt_parts.append("pinned expected values: " + ", ".join(opts["expected_pinned"]))
    if opts.get("require_pinned"):
        opt_parts.append("--require-pinned")
    if opts.get("expected_relying_party"):
        opt_parts.append("expected: " + ", ".join(opts["expected_relying_party"]))
    if opts.get("history_supplied"):
        opt_parts.append("history: " + ", ".join(opts["history_supplied"]))
    head = [
        "> **Before posting:** review this block. It contains identifiers, names and hashes "
        "taken from your tokens. Post only test or sandbox data, never production tokens or keys.",
        "",
        "### ap2-evidence result",
        "",
        f"- ap2-evidence: {__version__} (AP2 v0.2)",
        f"- Python: {platform.python_version()} on {md(os_family())}",
        f"- Command: `{command.replace('`', '')}`; options: {md('; '.join(opt_parts))}",
        f"- Verdict: **{r.verdict_label}** ({md(r.key_trust_text())})",
        f"- Checks: pass {s['pass']}, fail {s['fail']}, warn {s['warn']}, skip {s['skip']}",
        "",
    ]
    order = {FAIL: 0, WARN: 1, SKIP: 2}
    rows = sorted(
        (c for c in r.checks if c.status in (FAIL, WARN) or (c.status == SKIP and c.required)),
        key=lambda c: order[c.status],
    )
    optional_skips = sum(1 for c in r.checks if c.status == SKIP and not c.required)
    causes = r.causes()
    body = [
        f"#### Checks that failed, warned or could not be done ({len(rows)})",
        "",
        "| ID | Status | Reason | Detail | Expected | Actual |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    if not rows:
        body = ["All required checks passed."]
    omitted = 0
    size = sum(len(x) + 1 for x in head + body)
    for i, c in enumerate(rows):
        reason = c.reason or ""
        if c.id in causes:
            reason += f" (caused by {causes[c.id]})"
        row = (
            f"| {c.id} | {c.status} | {md(reason, 80)} | {md(c.detail, 300)} | "
            f"{md(c.expected or '', 150)} | {md(c.actual or '', 150)} |"
        )
        if i >= ISSUE_MAX_ROWS or size + len(row) + 200 > ISSUE_MAX_CHARS:
            omitted = len(rows) - i
            break
        body.append(row)
        size += len(row) + 1
    if omitted:
        body += ["", f"({omitted} more non-passing check(s) omitted to keep this short.)"]
    if optional_skips:
        body += ["", ISSUE_SKIP_NOTE.format(n=optional_skips)]
    body += ["", "<sub>Generated by `ap2-evidence --format issue`; no evidence section.</sub>"]
    return "\n".join(head + body) + "\n"
