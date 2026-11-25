"""Render ``docs/cross-implementation.md`` from ``results.json``.

Every number on the page comes from the results document; the prose around it is fixed text.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import reasons
import run
import sources

CONTEXT = {
    "goodmeta": "none (both runs use the suite's canonical clock `at=1780000000`, "
    "`VECTORS.md:7-10`)",
    "goodmeta-decoded": "the vector's `context` (past spend and uses) as `history`; "
    "`requiredConstraints` as `expected.require_constraints`",
    "kya-bench": "the `fixtures/jwks.json` trust list (its EC keys) pinned as `trusted_keys`; "
    "`mandate_context` as `history`",
    "cuichangquan": "expected agent key, checkout id, merchant id and total as `expected`; "
    "`skew=0`",
    "evidence-pack": "none",
    "agent-payment-chain": "none",
    "amep": "`history` from the earlier successful payments of the same family under the same "
    "open mandate (none when an earlier payment's outcome is unknown)",
    "pulse": "none",
    "ap2-pr369": "none",
}

NOT_REDISTRIBUTED = {
    "goodmeta-decoded": "re-signed by us from decoded payloads; not part of the redistributed "
    "set (the tool regenerates them)",
    "agent-payment-chain": "not part of the redistributed set (one chain)",
    "amep": "licence split between code (Apache-2.0) and specification, NOTICE and trademark "
    "restrictions: not redistributed",
    "pulse": "80 cases, mostly about the x402 / settlement layer, which is out of scope: "
    "not redistributed",
    "ap2-pr369": "licence stated only in the text of a closed pull request: not redistributed",
}


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _short(rows: list[dict[str, Any]], key: str) -> Counter[str]:
    return Counter(r[key]["classification"] for r in rows)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _result(res: dict[str, Any]) -> str:
    out = f"{res['verdict']}, {res['classification']}"
    parts = []
    if res["failing"]:
        parts.append("FAIL " + ", ".join(res["failing"]))
    if res["blocking"]:
        parts.append("SKIP " + ", ".join(res["blocking"]))
    return out + (": " + "; ".join(parts) if parts else "")


def _summary_table(doc: dict[str, Any], key: str) -> list[str]:
    head = "| Source | Vectors | " + " | ".join(run.CLASSES) + " |"
    lines = [head, "|---|" + "---:|" * (1 + len(run.CLASSES))]
    total: Counter[str] = Counter()
    n = 0
    for g in doc["groups"]:
        rows = [r for r in doc["rows"] if r["group"] == g["key"]]
        c = _short(rows, key)
        total += c
        n += len(rows)
        mark = " †" if g["resigned"] else ""
        cells = " | ".join(str(c[cls]) for cls in run.CLASSES)
        lines.append(f"| {g['title']}{mark} | {len(rows)} | {cells} |")
    cells = " | ".join(f"**{total[cls]}**" for cls in run.CLASSES)
    lines.append(f"| **Total** | **{n}** | {cells} |")
    return lines


def _vector(row: dict[str, Any]) -> str:
    return f"`{row['id']}`" + (" †" if row["resigned"] else "")


def _differences(doc: dict[str, Any]) -> list[str]:
    by_code: dict[str, list[dict[str, Any]]] = {}
    for r in doc["rows"]:
        codes = []
        for key in ("result", "result_with_context"):
            res = r[key]
            if res["classification"] in (run.DISAGREE, run.STRICTER) and res["reason"]:
                codes.append(res["reason"])
        for code in dict.fromkeys(codes):
            by_code.setdefault(code, []).append(r)
    lines: list[str] = []
    for cat, cat_title in reasons.CATEGORIES.items():
        codes = [c for c, r in reasons.REASONS.items() if r.category == cat and c in by_code]
        if not codes:
            continue
        lines += [f"### {cat_title}", ""]
        for code in codes:
            reason = reasons.REASONS[code]
            rows = by_code[code]
            lines += [f"#### {reason.title} (`{code}`, {_plural(len(rows), 'vector')})", ""]
            lines += [reason.position, ""]
            if reason.evidence:
                lines += ["Evidence:", ""] + [f"- {e}" for e in reason.evidence] + [""]
            lines += [
                "| Vector | Source file | Author | Without context | With context |",
                "|---|---|---|---|---|",
            ]
            for r in rows:
                author = f"{r['expected']}: {r['detail']}"
                extra = ""
                diff = (r.get("facts") or {}).get("differs_from_valid_in")
                if diff:
                    extra = f" (signed tokens as `{r['facts']['signed_tokens_as_valid_case']}`; "
                    extra += "differs in " + ", ".join(f"`{p}`" for p in diff) + ")"
                lines.append(
                    f"| {_vector(r)} | `{_cell(r['origin'])}`{_cell(extra)} | {_cell(author)} | "
                    f"{_cell(_result(r['result']))} | "
                    f"{_cell(_result(r['result_with_context']))} |"
                )
            lines.append("")
    if "UNEXPLAINED" in by_code:
        lines += ["### Not yet explained", ""]
        lines += [f"- `{r['group']}` `{r['id']}`" for r in by_code["UNEXPLAINED"]] + [""]
    return lines


def _incomplete(doc: dict[str, Any]) -> list[str]:
    counts: dict[str, Counter[str]] = {}
    for r in doc["rows"]:
        for key, tag in (("result", "without"), ("result_with_context", "with")):
            res = r[key]
            if res["classification"] == run.AGREE_INCOMPLETE:
                counts.setdefault(res["reason"] or "?", Counter())[f"{r['group']}|{tag}"] += 1
    lines = [
        "| Reason | Source | Without context | With context |",
        "|---|---|---:|---:|",
    ]
    titles = {g["key"]: g["title"] for g in doc["groups"]}
    for code, c in sorted(counts.items()):
        title = reasons.REASONS[code].title if code in reasons.REASONS else code
        for g in doc["groups"]:
            a, b = c[f"{g['key']}|without"], c[f"{g['key']}|with"]
            if a or b:
                lines.append(f"| {title} (`{code}`) | {titles[g['key']]} | {a} | {b} |")
    return lines


def _fixes(doc: dict[str, Any]) -> list[str]:
    rows = {(r["group"], r["id"]): r for r in doc["rows"]}
    lines: list[str] = []
    for title, text, vids in reasons.FIXES:
        lines += [f"### {title}", "", text, ""]
        lines += [
            "| Vector | Source | Now, without context | Now, with context |",
            "|---|---|---|---|",
        ]
        for g, vid in vids:
            r = rows[(g, vid)]
            a, b = r["result"], r["result_with_context"]
            lines.append(
                f"| {_vector(r)} | {g} | {a['verdict']}, {a['classification']} | "
                f"{b['verdict']}, {b['classification']} |"
            )
        lines.append("")
    return lines


def _reference(doc: dict[str, Any]) -> list[str]:
    obs = doc["observations"]
    titles = {g["key"]: g["title"] for g in doc["groups"]}
    lines = [
        "| Receipts in | SDK form | prose form | neither |",
        "|---|---:|---:|---:|",
    ]
    for g in doc["groups"]:
        c = obs["receipts"].get(g["key"])
        if c:
            lines.append(f"| {titles[g['key']]} | {c['sdk']} | {c['prose']} | {c['neither']} |")
    lk = obs["goodmeta_linkage_receiptReferences"]
    lines.append(
        f"| goodmeta `vectors/linkage.json` `receiptReferences` (reference values, no receipt) "
        f"| {lk['sdk']} | {lk['prose']} | {lk['neither']} |"
    )
    only: dict[str, list[str]] = {"sdk": [], "prose": []}
    for g in doc["groups"]:
        c = obs["receipts"].get(g["key"])
        if c and c["sdk"] and not c["prose"]:
            only["sdk"].append(titles[g["key"]])
        if c and c["prose"] and not c["sdk"]:
            only["prose"].append(titles[g["key"]])
    lines += [
        "",
        '"neither" counts receipts whose reference is wrong or missing on purpose (negative '
        "vectors). "
        f"Only the SDK form: {', '.join(only['sdk']) or 'none'}. Only the prose form: "
        f"{', '.join(only['prose']) or 'none'}.",
    ]
    return lines


def render(doc: dict[str, Any]) -> str:
    """The whole page."""
    repos = doc["repos"]
    n = len(doc["rows"])
    resigned = sum(1 for r in doc["rows"] if r["resigned"])
    out = [
        "# Cross-implementation comparison",
        "",
        "<!-- Generated by tools/cross_check from tools/cross_check/results.json. Do not edit: "
        "see tools/cross_check/README.md. -->",
        "",
        f"ap2-evidence {doc['tool_version']} was run on {n} AP2 v0.2 test vectors published by "
        f"other authors, and each verdict was compared with the outcome the author expects. Run "
        f"date: {doc['generated']}. Upstream references are to google-agentic-commerce/AP2 at "
        f"commit `{doc['ap2_commit'][:7]}` (`{doc['ap2_commit']}`).",
        "",
        "This compares test vectors, not deployments: no production AP2 evidence was available. "
        "The authors' verifiers were not run; their published expected outcomes were used as "
        "they are.",
        "",
        "## Sources",
        "",
        "| Source | Repository at commit | Licence | Vectors used | Count | In this repository |",
        "|---|---|---|---|---:|---|",
    ]
    for g in doc["groups"]:
        repo = repos[g["repo"]]
        count = sum(1 for r in doc["rows"] if r["group"] == g["key"])
        where = (
            f"bundles and manifest in `tests/fixtures/third-party/{g['key']}/`"
            if g["redistributed"]
            else "results only; " + NOT_REDISTRIBUTED.get(g["key"], "not redistributed")
        )
        commit = repo["commit"][:7] + ("" if repo["commit_confirmed"] else " (not confirmed)")
        out.append(
            f"| {g['title']}{' †' if g['resigned'] else ''} | [{repo['name']}]({repo['url']}) "
            f"`{commit}` | {_cell(repo['licence'])} | {g['scope']} | {count} | {where} |"
        )
    out += [
        "",
        "† The source ships these vectors as decoded JSON payloads only. We re-wrapped each "
        "payload into a signed AP2 chain with keys generated for the purpose (placeholder `cnf` "
        "keys replaced, checkout JWTs re-signed, hashes recomputed only where the original hash "
        f"matched). {resigned} of the {n} vectors are of this kind; every row from them is marked "
        "†. Their outcome depends on our re-wrapping as well as on the verifier.",
        "",
        "## How rows are classified",
        "",
        "- **agree**: VERIFIED where the author accepts, FAILED where the author rejects, "
        "INCOMPLETE where the author leaves the outcome open (indeterminate / unresolved).",
        "- **agree (incomplete input)**: the author accepts and we say INCOMPLETE because the "
        "vector does not carry everything we check (a key, a receipt, the other mandate).",
        "- **stricter**: the author leaves the outcome open and we say FAILED.",
        "- **disagree**: everything else.",
        "",
        "Every vector is run twice. **Without context**: the bundle and the vector's evaluation "
        "time (`at`) only; keys and expected `aud`/`nonce` come from the bundle. **With context**: "
        "also what the author's verifier is told beyond the evidence itself:",
        "",
    ]
    out += [f"- {g['title']}: {CONTEXT.get(g['key'], 'none')}" for g in doc["groups"]]
    out += ["", "## Results", "", "### Without context", ""]
    out += _summary_table(doc, "result")
    out += ["", "### With context", ""]
    out += _summary_table(doc, "result_with_context")
    out += [
        "",
        "## Changes made to ap2-evidence because of this comparison",
        "",
        "The first run showed places where ap2-evidence was wrong. They were fixed before the run "
        "above; the vectors that showed them and how they come out now:",
        "",
    ]
    out += _fixes(doc)
    out += [
        "## Remaining differences",
        "",
        "Every vector that is `disagree` or `stricter` in either run, grouped by cause. Each "
        "group states our position and where to check it.",
        "",
    ]
    out += _differences(doc)
    out += [
        "## Agree with incomplete input",
        "",
        "Counts of `agree (incomplete input)` rows by what was missing:",
        "",
    ]
    out += _incomplete(doc)
    out += [
        "",
        "## Receipt `reference`: SDK form and prose form",
        "",
        'The prose says a receipt\'s `reference` is computed "in the same manner as `sd_hash`" '
        "over the final SD-JWT of the chain (`docs/ap2/agent_authorization.md:509-513`, "
        "`docs/ap2/specification.md:354-360`): the closed segment with its disclosures. The SDK "
        "and its samples hash only the closed mandate's issuer-signed JWT "
        "(`code/sdk/python/ap2/sdk/mandate.py:402-417`). Upstream issue #405 (opened by AMEP's "
        "author) proposes aligning the prose with the SDK. Computed over the receipts of the "
        "converted vectors:",
        "",
    ]
    out += _reference(doc)
    out += [
        "",
        "The prose form is used by an implementation: goodmeta's generator computes it "
        '(`generators/gen_ap2_v02_vectors.py:213-217`, "sd_hash of the final segment"), its '
        "vector documentation requires it for receipts (`VECTORS.md:87, 137`) and its glossary "
        "states it (`GLOSSARY.md:124`). ap2-evidence accepts both and names the form found in "
        "CR04/PR04 "
        "(`docs/spec-notes.md` section A); both bind the agent-signed closed JWT.",
        "",
        "## What this comparison does not show",
        "",
        "- That ap2-evidence is correct on real traffic: no production AP2 evidence exists to test "
        "with.",
        f"- Independent agreement: several suites mint their vectors with the same upstream SDK. "
        f"{resigned} vectors were re-signed by us (marked †), so for those rows the comparison "
        "also tests our re-wrapping.",
        "- Conformance: a vector set is not the specification, and an author's expected outcome "
        "is that author's reading.",
        "- Anything about the x402 / settlement layer or about state across payments (replay, "
        "running totals beyond the `history` option): an evidence bundle does not contain it.",
        "- What the authors' own verifiers do on our bundles: we did not run third-party code.",
        "",
        "## Excluded from redistribution",
        "",
    ]
    for g in doc["groups"]:
        if not g["redistributed"]:
            out.append(f"- {g['title']}: {NOT_REDISTRIBUTED.get(g['key'], 'not redistributed')}.")
    excluded = doc.get("excluded") or []
    out.append(
        "- Private key material: "
        + ("; ".join(excluded) if excluded else "none found in the redistributed bundles")
        + ". Every redistributed file is scanned for private JWK members, PEM and DER private "
        "keys, also inside base64url segments. Some source repositories hold or generate test "
        "private keys in scripts, tests and CI files; the converters read only the vector files "
        "listed under Sources."
    )
    out += [
        "",
        "## Run it yourself",
        "",
        "`tools/cross_check/README.md` lists the git commands for each source at its pinned "
        "commit (`python tools/cross_check sources`), converts and verifies everything in-process "
        "(`python tools/cross_check run --src DIR`) and regenerates this page, the manifests "
        "and `tools/cross_check/results.json`. `tests/test_third_party.py` re-verifies the "
        "redistributed vectors and fails if this page or a manifest is stale.",
        "",
    ]
    return "\n".join(out)


def unexplained(doc: dict[str, Any]) -> list[str]:
    """Rows whose difference has no reason code yet."""
    return [
        f"{r['group']}/{r['id']} ({key})"
        for r in doc["rows"]
        for key in ("result", "result_with_context")
        if r[key]["reason"] == reasons.UNEXPLAINED
    ]


def counts(doc: dict[str, Any], key: str) -> dict[str, dict[str, int]]:
    """Per-group classification counts (for the report and the tests)."""
    out: dict[str, dict[str, int]] = {}
    for g in sources.GROUPS:
        rows = [r for r in doc["rows"] if r["group"] == g.key]
        c = _short(rows, key)
        out[g.key] = {"vectors": len(rows), **{cls: c[cls] for cls in run.CLASSES}}
    return out
