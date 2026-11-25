"""Broken input never raises.

It ends as FAIL / INCOMPLETE checks, or as InputError for unreadable text.
"""

from __future__ import annotations

import json
import random
import string
from typing import Any

import pytest

from ap2_evidence.bundle import InputError, parse_bundle_text
from ap2_evidence.inspector import inspect_input
from ap2_evidence.jose import b64url_encode
from helpers import build, disclosure, segments, statuses, verify

V = "ap2-evidence/1"


def b64j(obj: Any) -> str:
    return b64url_encode(json.dumps(obj).encode())


GOOD = build()
CM = GOOD["checkout_mandate"]
OPEN, CLOSED = segments(CM)
HDR, PAY, SIG = OPEN.split("~", 1)[0].split(".")
NAN_PAYLOAD = b64url_encode(b'{"x": NaN}')


def with_member(member: str, value: Any) -> dict[str, Any]:
    b = dict(GOOD)
    b[member] = value
    return b


def deep(n: int) -> Any:
    v: Any = 1
    for _ in range(n):
        v = [v]
    return v


BROKEN: dict[str, Any] = {
    "empty bundle": {},
    "only version": {"bundle_version": V},
    "list": [],
    "string": "hello",
    "null": None,
    "number": 42,
    "wrong version type": dict(GOOD, bundle_version=1),
    "mandate is number": with_member("checkout_mandate", 5),
    "mandate is list": with_member("payment_mandate", ["a"]),
    "mandate is object": with_member("payment_mandate", {"a": 1}),
    "receipt is bool": with_member("checkout_receipt", True),
    "empty mandate": with_member("checkout_mandate", ""),
    "whitespace mandate": with_member("checkout_mandate", "   "),
    "truncated JWT": with_member("checkout_mandate", CM[:50]),
    "truncated chain": with_member("checkout_mandate", CM[: len(CM) // 2]),
    "chain without final tilde": with_member("checkout_mandate", CM[:-1]),
    "missing ~ (plain JWT as mandate)": with_member("checkout_mandate", GOOD["checkout_receipt"]),
    "extra ~~": with_member("checkout_mandate", CM.replace("~~", "~~~~")),
    "triple tilde": with_member("checkout_mandate", CM.replace("~~", "~~~")),
    "bad base64 in header": with_member("checkout_mandate", "e!!." + CM[4:]),
    "padded base64": with_member("checkout_mandate", f"{HDR}=.{PAY}.{SIG}~~{CLOSED}"),
    "alg none": with_member("checkout_mandate", f"{b64j({'alg': 'none'})}.{PAY}.~~{CLOSED}"),
    "header not object": with_member("checkout_mandate", f"{b64j([1])}.{PAY}.{SIG}~~{CLOSED}"),
    "payload not object": with_member("checkout_mandate", f"{HDR}.{b64j('str')}.{SIG}~~{CLOSED}"),
    "duplicate JSON keys in header": with_member(
        "checkout_mandate",
        b64url_encode(b'{"alg":"ES256","alg":"none"}') + f".{PAY}.{SIG}~~{CLOSED}",
    ),
    "NaN in payload": with_member("checkout_mandate", f"{HDR}.{NAN_PAYLOAD}.{SIG}~~{CLOSED}"),
    "disclosure not an array": with_member(
        "checkout_mandate", OPEN + b64j({"a": 1}) + "~~" + CLOSED
    ),
    "disclosure with 4 elements": with_member(
        "checkout_mandate", OPEN + b64j(["s", "n", 1, 2]) + "~~" + CLOSED
    ),
    "disclosure non-string salt": with_member(
        "checkout_mandate", OPEN + b64j([1, "n", 1]) + "~~" + CLOSED
    ),
    "disclosure bad base64": with_member("checkout_mandate", OPEN + "%%%~~" + CLOSED),
    "duplicate disclosure": with_member(
        "checkout_mandate", OPEN + OPEN.split("~")[1] + "~~" + CLOSED
    ),
    "deeply nested payload": with_member(
        "checkout_mandate", f"{HDR}.{b64j(deep(500))}.{SIG}~~{CLOSED}"
    ),
    "deep disclosure": with_member(
        "checkout_mandate", OPEN + b64j(["s", deep(200)]) + "~~" + CLOSED
    ),
    "very long token": with_member("checkout_mandate", "eyJ" + "A" * 5_000_000 + "~"),
    "many disclosures": with_member(
        "checkout_mandate",
        OPEN + "~".join([disclosure(["s", i]) for i in range(600)]) + "~~" + CLOSED,
    ),
    "receipt is an SD-JWT": with_member("payment_receipt", GOOD["payment_mandate"]),
    "receipt truncated": with_member("payment_receipt", GOOD["payment_receipt"][:30]),
    "receipt payload list": with_member("payment_receipt", f"{HDR}.{b64j([1])}.{SIG}"),
    "keys wrong type": dict(GOOD, keys=[1, 2]),
    "keys role wrong type": dict(GOOD, keys={"merchant": "abc"}),
    "keys jwk garbage": dict(GOOD, keys={"merchant": [1, None, "x", {"kty": "RSA"}]}),
    "keys private": dict(GOOD, keys={"merchant": [dict(GOOD["keys"]["merchant"][0], d="AAAA")]}),
    "expected wrong type": dict(GOOD, expected="x"),
    "expected inner wrong type": dict(GOOD, expected={"checkout": {"aud": 5}}),
    "note wrong type": dict(GOOD, note=["x"]),
    "huge integers": with_member("checkout_mandate", f"{HDR}.{b64j({'iat': 10**200})}.{SIG}~"),
    "unicode garbage": with_member("checkout_mandate", "‮\x1b[31m\u0000~~~"),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_broken_bundle_never_raises(name: str) -> None:
    report = verify(BROKEN[name])
    assert report.verdict in ("FAILED", "INCOMPLETE"), name
    # every renderer copes with it too
    report.to_text()
    report.to_markdown()
    json.loads(report.to_json())


def test_specific_failures() -> None:
    assert statuses(verify(BROKEN["alg none"]))["CM02"] == "FAIL"
    assert statuses(verify(BROKEN["padded base64"]))["CM01"] == "FAIL"
    assert statuses(verify(BROKEN["duplicate JSON keys in header"]))["CM01"] == "FAIL"
    assert statuses(verify(BROKEN["disclosure not an array"]))["CM01"] == "FAIL"
    assert statuses(verify(BROKEN["duplicate disclosure"]))["CM04"] == "FAIL"
    assert statuses(verify(BROKEN["receipt is an SD-JWT"]))["PR01"] == "FAIL"
    assert statuses(verify(BROKEN["missing ~ (plain JWT as mandate)"]))["CM01"] == "FAIL"
    assert statuses(verify(BROKEN["keys private"]))["B03"] == "FAIL"
    assert statuses(verify(BROKEN["empty bundle"]))["B01"] == "FAIL"
    assert statuses(verify(BROKEN["empty bundle"]))["B02"] == "FAIL"


@pytest.mark.parametrize(
    "text",
    [
        b"",
        b"   ",
        b"not json",
        b"{",
        b'{"a":1,"a":2}',
        b"[1,",
        b"\xff\xfe\x00",
        b'{"x": NaN}',
        b"[" * 5000,
    ],
)
def test_unreadable_bundle_text(text: bytes) -> None:
    with pytest.raises(InputError):
        parse_bundle_text(text)


def test_inspect_never_raises() -> None:
    for value in BROKEN.values():
        if isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str):
                    inspect_input(v)
        inspect_input(json.dumps(value) if not isinstance(value, str) else value)


# --------------------------------------------------------------------------- mutation fuzzing

B64_ALPHABET = string.ascii_letters + string.digits + "-_"
ARTIFACTS = ("checkout_mandate", "payment_mandate", "checkout_receipt", "payment_receipt")


def _mutate(rng: random.Random, s: str) -> str:
    pos = rng.randrange(len(s))
    op = rng.choice(("flip", "flip", "truncate", "delete", "insert"))
    if op == "flip":
        c = rng.choice([x for x in B64_ALPHABET + ".~" if x != s[pos]])
        return s[:pos] + c + s[pos + 1 :]
    if op == "truncate":
        return s[:pos]
    if op == "delete":
        return s[:pos] + s[pos + 1 :]
    return s[:pos] + rng.choice(B64_ALPHABET + ".~") + s[pos:]


def test_seeded_mutations_never_verify() -> None:
    """Every character of every artifact is inside a signed or hashed region.

    JWT header and payload are signed; signatures are verified; disclosures
    are bound by their digests; '~' and '.' separators change the parse. So
    any single-character change must stop the bundle from being VERIFIED.
    """
    rng = random.Random(20261115)
    base = build()
    assert verify(base).verdict == "VERIFIED"
    for _ in range(300):
        member = rng.choice(ARTIFACTS)
        mutated = dict(base)
        mutated[member] = _mutate(rng, base[member])
        if mutated[member].strip() == base[member]:
            continue
        report = verify(mutated)  # must not raise
        assert report.verdict != "VERIFIED", (member, mutated[member][:80])
