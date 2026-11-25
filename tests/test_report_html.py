"""Standalone HTML report: structure, offline-safety and hostile bundle content."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Any

import pytest

from ap2_evidence.demo import build_demo_bundle
from helpers import EXAMPLE, builder, verify

HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(document.cookie)",
    "Evil\x1b[2J\x07Shop",
    "Shop‮exe.txt",
    "</style><style>body{display:none}</style>",
    "<a href='https://evil.example'>click</a>",
]

ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "h3", "section",
    "div", "p", "span", "strong", "ul", "li", "dl", "dt", "dd", "table", "thead", "tbody",
    "tr", "th", "td", "details", "summary", "footer",
}  # fmt: skip
ALLOWED_ATTRS = {"lang", "charset", "name", "content", "http-equiv", "class"}


class _Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _parse(page: str) -> _Collect:
    p = _Collect()
    p.feed(page)
    return p


def _hostile_bundle() -> dict[str, Any]:
    b = builder()
    name = " ".join(HOSTILE)
    b.checkout_payload["merchant"] = dict(
        b.checkout_payload["merchant"], name=name, website="javascript:alert(1)"
    )
    b.closed_payment["payee"] = dict(b.closed_payment["payee"], name=name)
    b.checkout_payload["line_items"][0]["item"]["title"] = name
    return b.build().bundle


def _assert_inert(page: str) -> None:
    low = page.lower()
    for bad in ("<script", "<img", "<a ", "<iframe", "<link", "<object", "<embed", "<form"):
        assert bad not in low, bad
    # hostile text such as "href=" may appear, but only as escaped text (no "<" before it)
    assert "<" + "a" not in low.replace("<abbr", "")
    assert "\x1b" not in page and "\x07" not in page and "‮" not in page
    parsed = _parse(page)
    for tag, attrs in parsed.tags:
        assert tag in ALLOWED_TAGS, tag
        for attr, value in attrs:
            assert attr in ALLOWED_ATTRS, (tag, attr)
            assert "javascript" not in (value or "").lower()
            assert "alert" not in (value or "")
    # only two <style> boundaries: ours
    assert low.count("<style>") == 1 and low.count("</style>") == 1


def test_hostile_strings_come_out_inert() -> None:
    r = verify(_hostile_bundle())
    page = r.to_html()
    _assert_inert(page)
    text = "".join(_parse(page).text)
    assert "<script>alert(1)</script>" in text  # shown as text, not executed
    assert "\\u202e" in text and "\\x1b" in text  # control characters made visible


@pytest.mark.parametrize("mode", [None, "amount", "disclosure", "receipt", "key"])
def test_demo_pages_are_self_contained(mode: str | None) -> None:
    r = verify(build_demo_bundle(mode) if mode else build_demo_bundle())
    page = r.to_html()
    assert page.startswith("<!DOCTYPE html>")
    _assert_inert(page)
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "@media print" in page and "prefers-color-scheme:dark" in page
    assert 'name="viewport"' in page
    css = page.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "url(" not in css and "@import" not in css and "http" not in css


def test_section_order_matches_text_report() -> None:
    r = verify(build_demo_bundle("disclosure"))
    page = r.to_html()
    order = [
        'class="verdict"',
        "<h2>Finding</h2>",
        "<h2>What this means</h2>",
        "<h2>What to do next</h2>",
        "<h2>Broken links (",
        "<h2>Not verified",
        "<h2>Evidence chain</h2>",
        "Technical appendix: all",
        "<h2>Limits",
        "<h2>Glossary",
        "<footer>",
    ]
    pos = [page.index(m) for m in order]
    assert pos == sorted(pos)
    assert "Consequences of CM04" in page
    assert r.key_trust_sentence() in "".join(_parse(page).text)
    assert "(UTC)" in page and r.generated_at in page


def test_footer_hashes() -> None:
    r = verify(json.loads(EXAMPLE.read_text(encoding="utf-8")))
    page = r.to_html()
    assert r.inputs["checkout_mandate"] in page
    assert "SHA-256 of the input bundle" not in page
    r.source_sha256 = "ab" * 32
    assert "SHA-256 of the input bundle" in r.to_html()


def test_broken_bundles_render() -> None:
    for bundle in ({}, [1, 2, 3], {"bundle_version": "ap2-evidence/1", "checkout_mandate": "~"}):
        page = verify(bundle).to_html()
        _assert_inert(page)
