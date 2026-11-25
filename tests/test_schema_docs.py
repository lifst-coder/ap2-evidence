"""JSON schemas shipped in the package, and docs generated from the registry."""

from __future__ import annotations

import copy
import json
from importlib import resources
from typing import Any

import pytest

from ap2_evidence.checks import REGISTRY, checks_markdown
from ap2_evidence.demo import build_demo_bundle
from helpers import EXAMPLE, ROOT, build, verify

jsonschema = pytest.importorskip("jsonschema")


def schema(name: str) -> dict[str, Any]:
    text = resources.files("ap2_evidence").joinpath("schemas", name).read_text(encoding="utf-8")
    return json.loads(text)


REPORTS = {
    "demo": lambda: verify(build_demo_bundle()).to_dict(),
    "tampered": lambda: verify(build_demo_bundle("disclosure")).to_dict(),
    "official": lambda: verify(json.loads(EXAMPLE.read_text(encoding="utf-8"))).to_dict(),
    "empty": lambda: verify({}).to_dict(),
    "garbage": lambda: verify([1, 2, 3]).to_dict(),
}


@pytest.mark.parametrize("name", sorted(REPORTS))
def test_report_validates(name: str) -> None:
    jsonschema.validate(REPORTS[name](), schema("report.schema.json"))


def _mutations(r: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    a = copy.deepcopy(r)
    a["result"] = a.pop("verdict")
    out.append(a)
    b = copy.deepcopy(r)
    del b["checks"][0]["hint"]
    out.append(b)
    c = copy.deepcopy(r)
    c["checks"][0]["severity"] = "high"
    out.append(c)
    d = copy.deepcopy(r)
    d["checks"][0]["status"] = "OK"
    out.append(d)
    e = copy.deepcopy(r)
    del e["limits"]
    out.append(e)
    f = copy.deepcopy(r)
    f["extra"] = 1
    out.append(f)
    g = copy.deepcopy(r)
    g["summary"]["passed"] = g["summary"].pop("pass")
    out.append(g)
    return out


def test_report_schema_is_strict() -> None:
    r = REPORTS["demo"]()
    s = schema("report.schema.json")
    for bad in _mutations(r):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, s)


def test_bundle_schema() -> None:
    s = schema("bundle.schema.json")
    jsonschema.validate(build(), s)
    jsonschema.validate(json.loads(EXAMPLE.read_text(encoding="utf-8")), s)
    for bad in (
        {},
        {"bundle_version": "ap2-evidence/2"},
        dict(build(), extra=1),
        dict(build(), keys={"merchant": [{"kty": "EC"}]}),
        dict(build(), checkout_mandate=5),
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, s)


def test_checks_md_matches_registry() -> None:
    doc = (ROOT / "docs" / "checks.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    # The module writes the file itself (UTF-8, LF), so no shell redirection is needed; '>' in
    # Windows PowerShell 5.1 would write UTF-16.
    assert doc == checks_markdown(), (
        "docs/checks.md is out of date; regenerate it from the repository root with: "
        "python -m ap2_evidence.checksdoc docs/checks.md"
    )


def test_every_check_is_documented() -> None:
    doc = (ROOT / "docs" / "checks.md").read_text(encoding="utf-8")
    for cid in REGISTRY:
        assert f"| {cid} |" in doc


def test_every_registry_entry_is_complete() -> None:
    for d in REGISTRY.values():
        assert d.title and d.what and d.why and d.spec_ref, d.id
        assert d.worst in ("FAIL", "WARN", "SKIP")


def test_schema_requires_reason_and_key_trust() -> None:
    s = schema("report.schema.json")
    r = REPORTS["tampered"]()
    for mutate in (
        lambda x: x.pop("key_trust"),
        lambda x: x.__setitem__("key_trust", "trusted"),
        lambda x: x["checks"][0].pop("reason"),
        lambda x: x["checks"][0].__setitem__("reason", "Not Snake Case"),
        lambda x: x["broken_links"][0].pop("reason"),
    ):
        bad = copy.deepcopy(r)
        mutate(bad)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, s)
