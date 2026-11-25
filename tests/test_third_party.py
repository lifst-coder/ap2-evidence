"""Snapshot of ap2-evidence's verdicts on redistributed third-party AP2 vectors.

The bundles in tests/fixtures/third-party/ are converted from other authors' published test
vectors (see each MANIFEST.json and the repository NOTICE). Every row records our verdict and
failing / blocking checks, without and with the author's context. A change in behaviour makes
these tests fail loudly; regenerating the snapshot is a deliberate step (see ``check.HOW``).
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "cross_check"))

import check  # noqa: E402
import layout  # noqa: E402
import run  # noqa: E402
from wire import load_json  # noqa: E402

MANIFESTS = check.manifests()
ENTRIES = [(g, e) for g, m in MANIFESTS.items() for e in m["vectors"]]
KEYS = (("result", "options"), ("result_with_context", "context_options"))
FIELDS = ("verdict", "failing", "blocking", "classification")
_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}


def _now(group: str, entry: dict[str, Any], key: str, opt_key: str) -> dict[str, Any]:
    k = (group, entry["id"], key)
    if k not in _CACHE:
        bundle = load_json(layout.FIXTURES / group / entry["bundle"])
        res = run.verify(bundle, entry[opt_key])
        res["classification"] = run.classify(entry["expected"], res["verdict"])
        _CACHE[k] = res
    return _CACHE[k]


def test_fixtures_are_present() -> None:
    assert set(MANIFESTS) == {"goodmeta", "kya-bench", "cuichangquan", "evidence-pack"}
    assert all(m["vectors"] for m in MANIFESTS.values())


@pytest.mark.parametrize(("group", "entry"), ENTRIES, ids=[f"{g}/{e['id']}" for g, e in ENTRIES])
def test_verdict_matches_manifest(group: str, entry: dict[str, Any]) -> None:
    problems = []
    for key, opt_key in KEYS:
        got, want = _now(group, entry, key, opt_key), entry[key]
        problems += [
            f"{group}/{entry['id']} {key}.{f}: recorded {want[f]!r}, now {got[f]!r}"
            for f in FIELDS
            if got[f] != want[f]
        ]
    assert not problems, "\n".join(problems) + "\n\n" + check.HOW


@pytest.mark.parametrize("group", sorted(MANIFESTS))
def test_classification_counts(group: str) -> None:
    man = MANIFESTS[group]
    for (key, opt_key), skey in zip(KEYS, ("summary", "summary_with_context"), strict=True):
        got = Counter(_now(group, e, key, opt_key)["classification"] for e in man["vectors"])
        counts = {"vectors": len(man["vectors"]), **{c: got[c] for c in run.CLASSES}}
        assert counts == man[skey], (
            f"{group} {skey}: now {counts}, recorded {man[skey]}\n\n{check.HOW}"
        )


def test_every_difference_has_a_reason() -> None:
    for g, e in ENTRIES:
        for key, _ in KEYS:
            res = e[key]
            if res["classification"] != run.AGREE:
                assert res["reason"] and res["reason"] != "UNEXPLAINED", f"{g}/{e['id']} {key}"


def test_licences_present_and_no_private_keys() -> None:
    problems = check.check_licences()
    assert not problems, "\n".join(problems)


def test_results_page_is_current() -> None:
    problems = check.check_results_and_page()
    assert not problems, "\n".join(problems) + "\n\n" + check.HOW
