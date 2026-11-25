"""Offline consistency checks: fixtures vs manifests vs results.json vs the page.

Needs no network and no third-party clone; used by ``tests/test_third_party.py`` and by
``python tools/cross_check check``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import layout
import page
import pipeline
import run
import sources
from keyscan import find_private_keys
from wire import load_json

HOW = (
    "If ap2-evidence changed on purpose, regenerate deliberately with `"
    + layout.REGENERATE
    + "` (tools/cross_check/README.md) and review the diff: every changed row needs a human "
    "decision (is the new verdict right, does the reason code still fit?) before it is "
    "committed."
)


def manifests() -> dict[str, dict[str, Any]]:
    """The redistributed groups' manifests, by group key."""
    return {
        g.key: load_json(layout.FIXTURES / g.key / "MANIFEST.json")
        for g in sources.GROUPS
        if g.redistribute
    }


def reverify(group: str, entry: dict[str, Any]) -> list[str]:
    """Problems for one manifest entry: our current result differs from the recorded one."""
    bundle = load_json(layout.FIXTURES / group / entry["bundle"])
    problems = []
    for opt_key, res_key in (("options", "result"), ("context_options", "result_with_context")):
        got = run.verify(bundle, entry[opt_key])
        want = entry[res_key]
        got["classification"] = run.classify(entry["expected"], got["verdict"])
        for field in ("verdict", "failing", "blocking", "classification"):
            if got[field] != want[field]:
                problems.append(
                    f"{group}/{entry['id']} {res_key}.{field}: recorded {want[field]!r}, "
                    f"now {got[field]!r}"
                )
    return problems


def check_licences() -> list[str]:
    """Each redistributed directory carries its source's licence files and no private keys."""
    problems = []
    for g in sources.GROUPS:
        if not g.redistribute:
            continue
        d = layout.FIXTURES / g.key
        for name in sources.REPOS[g.repo].licence_files:
            if not (d / name).is_file():
                problems.append(f"{d.name}: {name} missing")
        for f in sorted(d.glob("*.json")):
            hits = find_private_keys(load_json(f))
            if hits:
                problems.append(f"{g.key}/{f.name}: private key material: {hits[0]}")
    return problems


def check_results_and_page() -> list[str]:
    """results.json agrees with the manifests, and the page is what results.json renders to."""
    problems: list[str] = []
    doc = load_json(layout.RESULTS)
    rows = {(r["group"], r["id"]): r for r in doc["rows"]}
    for group, man in manifests().items():
        ids = {e["id"] for e in man["vectors"]}
        in_doc = {i for (g, i) in rows if g == group}
        if ids != in_doc:
            problems.append(f"{group}: results.json and MANIFEST.json list different vectors")
        for e in man["vectors"]:
            r = rows.get((group, e["id"]))
            for key in ("result", "result_with_context"):
                if r is not None and r[key] != e[key]:
                    problems.append(f"{group}/{e['id']}: {key} differs from results.json")
        for key, skey in (("result", "summary"), ("result_with_context", "summary_with_context")):
            if pipeline.summary([e for e in man["vectors"]], key) != man[skey]:
                problems.append(f"{group}: {skey} does not match its rows")
    left = page.unexplained(doc)
    if left:
        problems.append("rows without a reason code: " + ", ".join(left))
    text = layout.PAGE.read_text(encoding="utf-8") if layout.PAGE.is_file() else ""
    if text != page.render(doc):
        problems.append(f"{Path(layout.PAGE).name} is stale relative to results.json")
    return problems


def check_all() -> list[str]:
    """Every check, including re-verifying each redistributed vector."""
    problems = check_licences() + check_results_and_page()
    for group, man in manifests().items():
        for e in man["vectors"]:
            problems += reverify(group, e)
    return problems
