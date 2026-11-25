"""Convert, verify, classify, and write the fixtures, ``results.json`` and the results page."""

from __future__ import annotations

import datetime
import hashlib
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import convert
import layout
import page
import reasons
import run
import sources
from keyscan import find_private_keys
from wire import b64e, jws_payload, load_json

from ap2_evidence import __version__

MODES = (("bare", "result"), ("context", "result_with_context"))


def evaluate(vec: convert.Vector) -> dict[str, Any]:
    """Run both modes for one vector and return its row (without the bundle)."""
    row: dict[str, Any] = {
        "group": vec.group,
        "id": vec.vid,
        "origin": vec.origin,
        "expected": vec.expected,
        "detail": vec.detail,
        "resigned": vec.resigned,
        "notes": vec.notes,
    }
    if vec.facts:
        row["facts"] = vec.facts
    for mode, key in MODES:
        res = run.verify(vec.bundle, vec.options(mode == "context"))
        cls = run.classify(vec.expected, res["verdict"])
        res["classification"] = cls
        res["reason"] = reasons.assign(vec.group, vec.vid, mode, cls, res["blocking"])
        row[key] = res
    return row


def summary(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    """Classification counts of ``rows`` for result ``key``."""
    c = Counter(r[key]["classification"] for r in rows)
    return {"vectors": len(rows), **{cls: c[cls] for cls in run.CLASSES}}


def reference_form(chain: str, ref: Any) -> str:
    """``sdk`` (SHA-256 of the leaf issuer JWT), ``prose`` (sd_hash form) or ``neither``."""
    last = chain.split("~~")[-1]
    sdk = b64e(hashlib.sha256(last.split("~")[0].encode()).digest())
    seg = last if last.endswith("~") else last + "~"
    prose = b64e(hashlib.sha256(seg.encode()).digest())
    return "sdk" if ref == sdk else "prose" if ref == prose else "neither"


def reference_forms(vectors: list[convert.Vector], src: Path) -> dict[str, Any]:
    """Which receipt-reference form each source's receipts use (computed, not asserted)."""
    out: dict[str, dict[str, int]] = {}
    pairs = (("payment_receipt", "payment_mandate"), ("checkout_receipt", "checkout_mandate"))
    for v in vectors:
        for rk, mk in pairs:
            if isinstance(v.bundle.get(rk), str) and isinstance(v.bundle.get(mk), str):
                ref = (jws_payload(v.bundle[rk]) or {}).get("reference")
                form = reference_form(v.bundle[mk], ref)
                out.setdefault(v.group, {"sdk": 0, "prose": 0, "neither": 0})[form] += 1
    gm = src / sources.REPOS["goodmeta"].directory / "vectors" / "linkage.json"
    linkage = {"sdk": 0, "prose": 0, "neither": 0}
    for item in load_json(gm)["receiptReferences"]:
        linkage[reference_form(item["chain"], item["ap2Reference"])] += 1
    return {"receipts": out, "goodmeta_linkage_receiptReferences": linkage}


def collect(src: Path) -> tuple[dict[str, list[convert.Vector]], dict[str, Any]]:
    """Convert every group from the clones under ``src``; check the pinned commits."""
    repos: dict[str, Any] = {}
    for key, repo in sources.REPOS.items():
        clone = src / repo.directory
        if not clone.is_dir():
            raise SystemExit(f"missing clone {clone}; run `python tools/cross_check sources`")
        head = sources.head_commit(clone)
        if head is not None and not head.startswith(repo.commit):
            raise SystemExit(f"{clone} is at {head}, expected {repo.commit}")
        if head is None:
            print(f"warning: cannot read the commit of {clone}; expected {repo.commit}")
        repos[key] = {
            "name": repo.name,
            "url": repo.url,
            "commit": repo.commit,
            "licence": repo.licence,
            "commit_confirmed": head is not None,
        }
    vectors = {
        g.key: convert.CONVERTERS[g.key](src / sources.REPOS[g.repo].directory)
        for g in sources.GROUPS
    }
    for g, vs in vectors.items():
        ids = [v.vid for v in vs]
        bad = [i for i in ids if not convert.SAFE_ID.match(i)]
        if bad or len(set(ids)) != len(ids):
            raise SystemExit(f"{g}: unusable or duplicate vector ids {bad}")
    return vectors, repos


def build(src: Path) -> tuple[dict[str, Any], dict[str, list[convert.Vector]]]:
    """The complete results document."""
    vectors, repos = collect(src)
    rows = [evaluate(v) for g in sources.GROUPS for v in vectors[g.key]]
    doc = {
        "format": layout.FORMAT,
        "generated": datetime.date.today().isoformat(),
        "tool_version": __version__,
        "ap2_commit": sources.AP2_COMMIT,
        "repos": repos,
        "groups": [
            {
                "key": g.key,
                "repo": g.repo,
                "title": g.title,
                "redistributed": g.redistribute,
                "resigned": g.resigned,
                "scope": g.scope,
            }
            for g in sources.GROUPS
        ],
        "observations": reference_forms([v for vs in vectors.values() for v in vs], src),
        "rows": rows,
    }
    return doc, vectors


def write_fixtures(doc: dict[str, Any], vectors: dict[str, list[convert.Vector]]) -> list[str]:
    """Write the redistributable groups; return what was excluded and why."""
    excluded: list[str] = []
    rows = {(r["group"], r["id"]): r for r in doc["rows"]}
    for g in sources.GROUPS:
        if not g.redistribute:
            continue
        repo = sources.REPOS[g.repo]
        d = layout.FIXTURES / g.key
        if d.is_dir():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        entries = []
        kept: list[dict[str, Any]] = []
        for v in vectors[g.key]:
            hits = find_private_keys(v.bundle)
            if hits:
                excluded.append(f"{g.key}/{v.vid}: private key material ({hits[0]})")
                continue
            row = rows[(g.key, v.vid)]
            name = f"{v.vid}.bundle.json"
            layout.dump(d / name, v.bundle)
            entries.append(
                {
                    "id": v.vid,
                    "bundle": name,
                    "origin": v.origin,
                    "expected": v.expected,
                    "detail": v.detail,
                    "notes": v.notes,
                    "options": v.options(False),
                    "context_options": v.options(True),
                    "result": row["result"],
                    "result_with_context": row["result_with_context"],
                }
            )
            kept.append(row)
        manifest = {
            "format": layout.FORMAT,
            "group": g.key,
            "title": g.title,
            "source": {
                "name": repo.name,
                "url": repo.url,
                "commit": repo.commit,
                "licence": repo.licence,
                "files": g.scope,
            },
            "conversion": (
                "Each *.bundle.json re-wraps one vector of the source into the ap2-evidence/1 "
                "bundle format (tools/cross_check/convert.py); tokens are copied unchanged. "
                "`options` are the verify_bundle arguments without the author's context, "
                "`context_options` with it."
            ),
            "regenerate": layout.REGENERATE,
            "summary": summary(kept, "result"),
            "summary_with_context": summary(kept, "result_with_context"),
            "vectors": entries,
        }
        if find_private_keys(manifest):
            raise SystemExit(f"{g.key}: private key material in the manifest")
        layout.dump(d / "MANIFEST.json", manifest)
    return excluded


def copy_licences(src: Path) -> None:
    """Copy each redistributed source's licence files verbatim."""
    for g in sources.GROUPS:
        if not g.redistribute:
            continue
        repo = sources.REPOS[g.repo]
        for name in repo.licence_files:
            shutil.copyfile(src / repo.directory / name, layout.FIXTURES / g.key / name)


def write_all(src: Path) -> dict[str, Any]:
    """Run everything and write fixtures, results.json and the page."""
    doc, vectors = build(src)
    doc["excluded"] = write_fixtures(doc, vectors)
    copy_licences(src)
    layout.dump(layout.RESULTS, doc)
    layout.write_text(layout.PAGE, page.render(doc))
    return doc
