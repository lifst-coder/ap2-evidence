"""The ``explain`` command: what one check verifies, from the registry in :mod:`checks`."""

from __future__ import annotations

import difflib
import textwrap

from .bundle import InputError
from .checks import GROUPS, REGISTRY, CheckDef

_WORST = {
    "FAIL": "FAIL - a failure makes the verdict FAILED",
    "WARN": "WARN - advisory only, never changes the verdict",
    "SKIP": "SKIP - reports input this version cannot check",
}


def find(check_id: str) -> CheckDef:
    """Look up a check by ID (case-insensitive).

    Raises:
        InputError: For an unknown ID, naming the closest known IDs.
    """
    key = check_id.strip().upper()
    if key in REGISTRY:
        return REGISTRY[key]
    close = difflib.get_close_matches(key, list(REGISTRY), n=5, cutoff=0.5)
    prefix = [i for i in REGISTRY if key[:2] and i.startswith(key[:2])][:5]
    hint = close or prefix
    tail = f"; closest: {', '.join(hint)}" if hint else ""
    shown = check_id if len(check_id) <= 20 else check_id[:20] + "..."
    raise InputError(
        f"unknown check ID {shown!r}{tail}; 'ap2-evidence explain --list' shows all {len(REGISTRY)}"
    )


def _field(label: str, text: str, width: int = 100) -> list[str]:
    lead = f"  {label + ':':<16}"
    return textwrap.wrap(
        text, width=width, initial_indent=lead, subsequent_indent=" " * len(lead)
    ) or [lead]


def render(d: CheckDef) -> str:
    """Plain-text explanation of one check."""
    if d.required:
        req = "yes - if it cannot be checked (SKIP), the verdict is INCOMPLETE"
    else:
        req = "no - a SKIP does not change the verdict"
    lines = [f"{d.id}: {d.title}"]
    lines += _field("Family", GROUPS.get(d.group, d.group))
    lines += _field("What it checks", d.what)
    lines += _field("Purpose", d.why)
    lines += _field("Required", req)
    lines += _field("Worst status", _WORST.get(d.worst, d.worst))
    if not d.can_pass:
        lines += _field("Note", "informational: this check never reports PASS")
    lines.append("  Spec reference (upstream AP2 repository, v0.2.0):")
    lines += textwrap.wrap(
        d.spec_ref, width=100, initial_indent=" " * 18, subsequent_indent=" " * 18
    )
    lines += (
        _field("Note", "a result may be marked not required when the check does not apply")
        if d.required
        else []
    )
    return "\n".join(lines) + "\n"


def render_list() -> str:
    """All checks, one per line, grouped by family."""
    lines: list[str] = []
    for group, label in GROUPS.items():
        lines.append(f"{label}:")
        for d in REGISTRY.values():
            if d.group == group:
                req = "required" if d.required else "optional"
                lines.append(f"  {d.id:<5} {req:<8} worst {d.worst:<4}  {d.title}")
        lines.append("")
    lines.append(f"{len(REGISTRY)} checks. 'ap2-evidence explain ID' shows one in full.")
    return "\n".join(lines) + "\n"
