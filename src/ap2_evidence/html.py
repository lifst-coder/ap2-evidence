"""Standalone HTML rendering of a :class:`~ap2_evidence.report.Report`.

The page is one self-contained file meant to be attached to a dispute file or
printed to PDF: inline CSS only, no JavaScript, no external fonts, images or
links, and a Content-Security-Policy that forbids loading anything. It follows
the reading order of the text report.

Everything that comes from the bundle is attacker-controlled. Every value is
passed through :func:`~ap2_evidence.report.clean` (control and bidirectional
characters become visible escapes) and then :func:`html.escape`; no value is
ever written into an attribute, and no link is created from bundle content.
"""

from __future__ import annotations

from html import escape as _escape
from typing import Any

from ._version import __version__
from .checks import GROUPS, REGISTRY
from .report import (
    CONSEQUENCE_NOTE,
    EVIDENCE_NOTE,
    FAIL,
    FAILED,
    FULL,
    INCOMPLETE,
    INSPECT_LINE,
    PASS,
    SKIP,
    WARN,
    CheckResult,
    Report,
    clean,
    evidence_lines,
    group_not_verified,
    plain_text,
    report_glossary,
    shown_hint,
    underlying_line,
)

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--panel:#f6f8fa;
--fail:#b3261e;--fail-bg:#fdecea;--ok:#1a7f37;--ok-bg:#e8f5ec;--inc:#9a6700;--inc-bg:#fff8e1;
--warn:#9a6700;--skip:#57606a}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;
--line:#30363d;--panel:#161b22;--fail:#ff7b72;--fail-bg:#3a1714;--ok:#56d364;--ok-bg:#12261a;
--inc:#e3b341;--inc-bg:#2e2410;--warn:#e3b341;--skip:#9da7b3}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0 auto;max-width:60rem;padding:1rem;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans","Helvetica Neue",Arial,
sans-serif;overflow-wrap:anywhere}
h1{font-size:1.4rem;margin:.2rem 0 1rem}
h2{font-size:1.15rem;margin:1.8rem 0 .6rem;padding-bottom:.2rem;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:1.2rem 0 .4rem}
p{margin:.4rem 0}
ul{padding-left:1.3rem;margin:.4rem 0}
li{margin:.2rem 0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
font-size:.9em}
.banner{border:2px solid var(--line);border-radius:8px;padding:.8rem 1rem;margin-bottom:1rem}
.banner .verdict{font-size:1.6rem;font-weight:700;letter-spacing:.02em}
.banner.failed{border-color:var(--fail);background:var(--fail-bg)}
.banner.failed .verdict{color:var(--fail)}
.banner.verified{border-color:var(--ok);background:var(--ok-bg)}
.banner.verified .verdict{color:var(--ok)}
.banner.incomplete{border-color:var(--inc);background:var(--inc-bg)}
.banner.incomplete .verdict{color:var(--inc)}
.label{font-weight:600}
.muted{color:var(--muted)}
.item{border:1px solid var(--line);border-left-width:4px;border-radius:6px;padding:.5rem .8rem;
margin:.6rem 0;background:var(--panel);break-inside:avoid;page-break-inside:avoid}
.item.fail{border-left-color:var(--fail)}
.item.warn{border-left-color:var(--warn)}
.item.skip{border-left-color:var(--skip)}
.item .item{background:var(--bg)}
.item dl{margin:.3rem 0 0;display:grid;grid-template-columns:max-content 1fr;gap:.15rem .8rem}
.item dt{color:var(--muted)}
.item dd{margin:0}
@media (max-width:40rem){.item dl{grid-template-columns:1fr}.item dd{margin-bottom:.3rem}}
.st{font-weight:700;font-family:ui-monospace,Consolas,monospace}
.st.FAIL{color:var(--fail)}.st.PASS{color:var(--ok)}.st.WARN{color:var(--warn)}
.st.SKIP{color:var(--skip)}
table{border-collapse:collapse;width:100%;font-size:.88rem;margin:.4rem 0 1rem}
th,td{border:1px solid var(--line);padding:.3rem .4rem;text-align:left;vertical-align:top}
th{background:var(--panel)}
tr{break-inside:avoid;page-break-inside:avoid}
.tablewrap{overflow-x:auto}
details{margin:.6rem 0}
summary{cursor:pointer;font-weight:600}
.ev0{font-weight:600;margin-top:.7rem}
.ev1{margin-left:1rem}.ev2{margin-left:2rem}.ev3{margin-left:3rem}
footer{margin-top:2rem;padding-top:.6rem;border-top:1px solid var(--line);color:var(--muted);
font-size:.85rem}
@media print{
:root{--bg:#fff;--fg:#000;--muted:#444;--line:#999;--panel:#fff;--fail:#a00;--fail-bg:#fff;
--ok:#060;--ok-bg:#fff;--inc:#740;--inc-bg:#fff;--warn:#740;--skip:#444}
@page{size:auto;margin:15mm}
body{max-width:none;padding:0;font-size:10.5pt}
h2{break-after:avoid;page-break-after:avoid}
h3{break-after:avoid;page-break-after:avoid}
.banner{break-inside:avoid;page-break-inside:avoid}
.tablewrap{overflow:visible}
.appendix{break-before:page;page-break-before:always}
}
"""


def e(value: Any, limit: int = FULL) -> str:
    """Escape an untrusted value for HTML text content (never for attributes)."""
    return _escape(clean(value, limit), quote=True)


_STATUS_CLASS = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "SKIP"}
_VERDICT_CLASS = {FAILED: "failed", INCOMPLETE: "incomplete"}


def _st(status: str) -> str:
    cls = _STATUS_CLASS.get(status, "SKIP")
    return f'<span class="st {cls}">[{e(status)}]</span>'


def _dl(rows: list[tuple[str, str | None]]) -> str:
    parts = ["<dl>"]
    for label, value in rows:
        if value:
            parts.append(f"<dt>{e(label)}</dt><dd>{e(value)}</dd>")
    parts.append("</dl>")
    return "".join(parts)


def _failure(c: CheckResult, report: Report, nested: bool = False) -> str:
    out = [
        '<div class="item fail">',
        f"<div>{_st(FAIL)} <strong>{e(c.id)} {e(c.title)}</strong></div>",
        _dl(
            [
                ("What is wrong", plain_text(c, report)),
                ("Technical detail", c.detail),
                ("Where to look (technical)", shown_hint(c, report)),
                ("What this check is for", REGISTRY[c.id].why),
                ("Reason code", c.reason),
            ]
        ),
    ]
    if not nested:
        cons = report.consequences_of(c.id)
        if cons:
            out.append(
                f'<p class="muted"><span class="label">Consequences of {e(c.id)}:</span> '
                f"{e(CONSEQUENCE_NOTE.format(id=c.id))}</p>"
            )
            out.extend(_failure(d, report, nested=True) for d in cons)
    out.append("</div>")
    return "".join(out)


def _other(c: CheckResult, report: Report, label: str, cls: str) -> str:
    return (
        f'<div class="item {cls}"><div>{_st(c.status)} <strong>{e(c.id)} {e(c.title)}</strong>'
        f"</div>"
        + _dl(
            [
                (label, plain_text(c, report)),
                ("Technical detail", c.detail),
                ("What you can do", shown_hint(c, report)),
            ]
        )
        + "</div>"
    )


def render_html(r: Report) -> str:
    """Render ``r`` as a standalone HTML document."""
    s = r.summary()
    verdict_cls = _VERDICT_CLASS.get(r.verdict, "verified")
    if r.outcome in ("declined", "conflicting"):
        verdict_cls = "incomplete"  # never the green "all good" banner for these
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        '<meta name="referrer" content="no-referrer">',
        '<meta name="color-scheme" content="light dark">',
        f"<title>AP2 evidence report: {e(r.verdict_label)}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<h1>AP2 evidence report</h1>",
        f'<section class="banner {verdict_cls}">',
        f'<div class="verdict">{e(r.verdict_label)}</div>',
        f'<div><span class="label">Keys:</span> {e(r.key_trust_text().removeprefix("keys: "))}'
        "</div>",
        f"<p>{e(r.key_trust_sentence())}</p>",
        f'<div class="muted">Checks: pass {s["pass"]}, fail {s["fail"]}, warn {s["warn"]}, '
        f"skip {s['skip']}</div>",
        "</section>",
    ]
    for note in r.notes:
        out.append(f"<p>{e(note)}</p>")
    out += [
        "<h2>Finding</h2>",
        f"<p>{e(r.effective_finding())}</p>",
        "<h2>What this means</h2>",
        f"<p>{e(r.effective_meaning())}</p>",
        "<h2>What to do next</h2>",
        "<ul>",
        *[f"<li>{e(step)}</li>" for step in r.effective_next_steps()],
        "</ul>",
    ]
    fails = [c for c in r.checks if c.status == FAIL]
    prim = r.primary_failures()
    out.append(f"<h2>Broken links ({len(fails)})</h2>")
    if not fails:
        out.append("<p>None.</p>")
    elif len(prim) != len(fails):
        out.append(f"<p>{e(underlying_line(len(prim), len(fails)))}</p>")
    out.extend(_failure(c, r) for c in prim)

    nv, warns = r.not_verified(), r.warnings()
    out.append(f"<h2>Not verified ({len(nv)}) and warnings ({len(warns)})</h2>")
    if not nv and not warns:
        out.append("<p>None.</p>")
    roots, groups = group_not_verified(r, nv)
    for n in roots:
        out.append(_other(r.check(n["id"]), r, "Not checked", "skip"))
    for by, state, ids in groups:
        out.append(
            f'<div class="item skip">{_st(SKIP)} {len(ids)} check(s) not performed because '
            f"{e(by)} {e(state)}: {e(', '.join(ids))}</div>"
        )
    for w in warns:
        out.append(_other(r.check(w["id"]), r, "Warning", "warn"))

    out += ["<h2>Evidence chain</h2>", f'<p class="muted">{e(EVIDENCE_NOTE)}</p>']
    for level, line in evidence_lines(r.evidence):
        lvl = min(level, 3)
        out.append(f'<div class="ev{lvl}">{e(line)}</div>')

    out += [
        '<section class="appendix">',
        f"<h2>Technical appendix: all {len(r.checks)} checks</h2>",
        f'<p class="muted">{e(INSPECT_LINE)}</p>',
    ]
    causes = r.causes()
    for group, label in GROUPS.items():
        rows = [c for c in r.checks if c.group == group]
        if not rows:
            continue
        out += [
            f"<h3>{e(label)}</h3>",
            '<div class="tablewrap"><table>',
            "<thead><tr><th>Status</th><th>ID</th><th>Check</th><th>Required</th>"
            "<th>Reason</th><th>Detail</th></tr></thead><tbody>",
        ]
        for c in rows:
            detail = c.detail
            if c.key_provenance:
                detail += f" (key provenance: {c.key_provenance})"
            if c.status != PASS and c.expected is not None:
                detail += f" Expected: {c.expected}. Actual: {c.actual}."
            if c.id in causes:
                detail += f" Caused by {causes[c.id]}."
            if c.status != PASS and shown_hint(c, r):
                detail += f" Hint: {shown_hint(c, r)}"
            if c.blocked_by:
                detail += f" Blocked by {c.blocked_by}."
            out.append(
                f'<tr><td>{_st(c.status)}</td><td class="mono">{e(c.id)}</td>'
                f"<td>{e(c.title)}</td><td>{'yes' if c.required else 'no'}</td>"
                f'<td class="mono">{e(c.reason or "")}</td><td>{e(detail)}</td></tr>'
            )
        out.append("</tbody></table></div>")
    out.append("</section>")

    out += ["<h2>Limits (what this tool does not check)</h2>", "<ul>"]
    out += [f"<li>{e(lim)}</li>" for lim in r.limits]
    out += ["</ul>", "<h2>Glossary (terms used in this report)</h2>", "<dl>"]
    for term, definition in report_glossary(r):
        out.append(f"<dt><strong>{e(term)}</strong></dt><dd>{e(definition)}</dd>")
    out.append("</dl>")
    footer = [
        f"ap2-evidence {e(__version__)}, AP2 v0.2.",
        f"Generated at {e(r.generated_at)} (UTC).",
    ]
    if r.source_sha256:
        footer.append(
            f'SHA-256 of the input bundle: <span class="mono">{e(r.source_sha256)}</span>.'
        )
    inputs = [(k, v) for k, v in r.inputs.items() if isinstance(v, str)]
    out += ["</main>", "<footer>", f"<p>{' '.join(footer)}</p>"]
    if inputs:
        out.append("<p>SHA-256 of each artifact as supplied:</p><ul>")
        out += [f'<li>{e(k)}: <span class="mono">{e(v)}</span></li>' for k, v in inputs]
        out.append("</ul>")
    out += ["</footer>", "</body>", "</html>"]
    return "\n".join(out) + "\n"
