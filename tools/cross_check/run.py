"""Run the verifier in-process and classify each verdict against the author's expectation."""

from __future__ import annotations

from typing import Any

from ap2_evidence import verify_bundle

AGREE = "agree"
AGREE_INCOMPLETE = "agree (incomplete input)"
STRICTER = "stricter"
DISAGREE = "disagree"
CLASSES = (AGREE, AGREE_INCOMPLETE, STRICTER, DISAGREE)

#: Required-SKIP reasons that only say "something else is missing"; not listed as blocking.
NOT_BLOCKING = frozenset({"missing_artifact", "blocked"})


def classify(expected: str, verdict: str) -> str:
    """Compare our verdict with the author's expected outcome.

    ``agree (incomplete input)``: the author accepts, we say INCOMPLETE (we could not check
    everything with what the vector provides). ``stricter``: the author leaves the outcome open
    (indeterminate / unresolved), we say FAILED.
    """
    if expected == "accept":
        return {"VERIFIED": AGREE, "INCOMPLETE": AGREE_INCOMPLETE}.get(verdict, DISAGREE)
    if expected == "reject":
        return AGREE if verdict == "FAILED" else DISAGREE
    return {"INCOMPLETE": AGREE, "FAILED": STRICTER}.get(verdict, DISAGREE)


def verify(bundle: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Verify one bundle; return verdict, failing and blocking checks as ``ID:reason``."""
    report = verify_bundle(bundle, **options)
    failing = [f"{c.id}:{c.reason or '-'}" for c in report.checks if c.status == "FAIL"]
    blocking = [
        f"{c.id}:{c.reason or '-'}"
        for c in report.checks
        if c.status == "SKIP" and c.required and c.reason not in NOT_BLOCKING
    ]
    return {"verdict": report.verdict, "failing": failing, "blocking": blocking}
