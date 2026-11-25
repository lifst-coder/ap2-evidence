"""Verifier-side options of ``verify``: --require-pinned, --at, history and expectations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ap2_evidence.jose import public_jwk
from helpers import EXAMPLE, ROOT
from helpers import run_cli as _run_cli

FX = ROOT / "tests" / "fixtures" / "upstream-sdk"
CARD = str(FX / "card" / "bundle.json")
CARD_KEYS = str(FX / "card" / "trusted_keys.json")
EXTRAS = str(FX / "v_extras_usd" / "bundle.json")  # payment.budget max USD 150.00, paid 99.98
EXTRAS_KEYS = str(FX / "v_extras_usd" / "trusted_keys.json")
AGENT = str(FX / "loose" / "agent.jwk")
DEMO = str(EXAMPLE.parent / "demo-valid.bundle.json")  # keys embedded in the bundle


def run_cli(*args: str) -> Any:
    return _run_cli(*args, env={"PYTHONIOENCODING": "utf-8"})


def _json(*args: str) -> tuple[int, dict[str, Any]]:
    p = run_cli(*args, "--format", "json")
    assert b"Traceback" not in p.stderr, p.stderr
    assert p.returncode in (0, 1, 3), p.stderr
    return p.returncode, json.loads(p.stdout)


def _checks(r: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in r["checks"]}


def _usage_error(*args: str) -> str:
    p = run_cli(*args)
    err = p.stderr.decode("utf-8", "replace")
    assert p.returncode == 2, (args, p.stdout, err)
    assert "Traceback" not in err
    lines = err.strip().splitlines()
    assert len(lines) == 1 and lines[0].startswith("ap2-evidence: error:"), err
    return lines[0]


# ----------------------------------------------------------------------------- --require-pinned


def test_require_pinned() -> None:
    code, r = _json("verify", DEMO)
    assert (code, r["verdict"], r["options"]["require_pinned"]) == (0, "VERIFIED", False)
    code, r = _json("verify", DEMO, "--require-pinned")
    assert (code, r["verdict"]) == (3, "INCOMPLETE")
    assert r["options"]["require_pinned"] is True
    assert _checks(r)["CM03"]["reason"] == "key_not_pinned"
    # with pinned keys it is satisfied
    code, r = _json("verify", CARD, "--trusted-keys", CARD_KEYS, "--require-pinned")
    assert (code, r["verdict"]) == (0, "VERIFIED")
    issue = run_cli("verify", DEMO, "--require-pinned", "--format", "issue").stdout
    assert b"--require-pinned" in issue


# ----------------------------------------------------------------------------- --at


def test_at_forms() -> None:
    for value in ("2026-11-24T00:00:00Z", "2026-11-24T09:00:00+09:00", "1795537400", "2026-11-24"):
        code, r = _json("verify", CARD, "--trusted-keys", CARD_KEYS, "--at", value)
        assert r["options"]["at"] is not None
    for bad in ("yesterday", "2026-11-24T09:00:00", "2026-13-01T00:00:00Z", "9" * 13):
        line = _usage_error("verify", CARD, "--at", bad)
        assert "Unix seconds" in line and "RFC 3339" in line and "midnight UTC" in line


# ----------------------------------------------------------------------------- expectations


def test_expectations_pass() -> None:
    code, r = _json(
        "verify",
        CARD,
        "--trusted-keys",
        CARD_KEYS,
        "--expect-agent-key",
        AGENT,
        "--expect-checkout-id",
        "cart_87a50473919f",
        "--expect-merchant-id",
        "merchant_1",
        "--expect-total",
        "9998",
        "usd",
        "--require-constraint",
        "payment.amount_range",
        "--require-constraint",
        "payment.allowed_payees",
    )
    assert (code, r["verdict"]) == (0, "VERIFIED")
    c = _checks(r)
    assert {c[i]["status"] for i in ("EX01", "EX02", "EX03", "EX04", "EX05")} == {"PASS"}
    assert r["options"]["expected_relying_party"] == [
        "agent_key",
        "checkout_id",
        "merchant_id",
        "require_constraints",
        "total",
    ]


@pytest.mark.parametrize(
    ("args", "check"),
    [
        (["--expect-agent-key", str(FX / "loose" / "issuer.pem")], "EX01"),
        (["--expect-checkout-id", "cart_other"], "EX02"),
        (["--expect-merchant-id", "merchant_2"], "EX03"),
        (["--expect-total", "9999", "USD"], "EX04"),
        (["--expect-total", "9998", "EUR"], "EX04"),
        (["--require-constraint", "payment.budget"], "EX05"),
    ],
)
def test_expectations_fail(args: list[str], check: str) -> None:
    code, r = _json("verify", CARD, "--trusted-keys", CARD_KEYS, *args)
    assert (code, r["verdict"]) == (1, "FAILED")
    assert [i for i, c in _checks(r).items() if c["status"] == "FAIL"] == [check]


def test_expectation_input_errors(tmp_path: Path) -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    priv = tmp_path / "agent.pem"
    priv.write_bytes(
        k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    two = tmp_path / "two.jwks"
    two.write_text(json.dumps({"keys": [public_jwk(k), public_jwk(k, "b")]}), encoding="utf-8")
    cases = [
        (["--expect-agent-key", str(priv)], "PRIVATE key"),
        (["--expect-agent-key", str(two)], "holds 2 keys"),
        (["--expect-agent-key", str(tmp_path / "none.jwk")], "file not found"),
        (["--expect-total", "99.98", "USD"], "USD 99.98 is 9998"),
        (["--expect-total", "100", "dollars"], "not an ISO 4217"),
        (["--expect-total", "-5", "USD"], "must not be negative"),
        (["--expect-checkout-id", " "], "must not be empty"),
        (["--require-constraint", "payment.ammount_range"], "did you mean 'payment.amount_range'"),
        (["--require-constraint", "budget"], "Known: checkout.allowed_merchants"),
    ]
    for args, msg in cases:
        assert msg in _usage_error("verify", CARD, *args), args


# ----------------------------------------------------------------------------- history


def test_budget_needs_history_and_fails_when_over() -> None:
    """goodmeta-style: a budget-constrained mandate is INCOMPLETE without history, FAILED over."""
    code, r = _json("verify", EXTRAS, "--trusted-keys", EXTRAS_KEYS)
    assert (code, r["verdict"]) == (3, "INCOMPLETE")
    assert _checks(r)["PM39"]["reason"] == "history_needed"
    assert r["options"]["history_supplied"] == []
    # 50.03 already spent + 99.98 now = 150.01 > 150.00
    code, r = _json(
        "verify", EXTRAS, "--trusted-keys", EXTRAS_KEYS, "--prior-total", "5003", "USD",
        "--prior-uses", "0",
    )  # fmt: skip
    assert (code, r["verdict"]) == (1, "FAILED")
    assert _checks(r)["PM39"]["reason"] == "budget_exceeded"
    assert r["options"]["history_supplied"] == ["prior_total", "prior_uses"]
    code, r = _json(
        "verify", EXTRAS, "--trusted-keys", EXTRAS_KEYS, "--prior-total", "5002", "USD",
        "--prior-uses", "0",
    )  # fmt: skip
    assert (code, r["verdict"]) == (0, "VERIFIED")
    assert "supplied by whoever ran the verifier" in _checks(r)["PM39"]["detail"]


def test_history_input_errors() -> None:
    for args, msg in (
        (["--prior-total", "1.5", "USD"], "whole number of minor units"),
        (["--prior-total", "100", "XXXX"], "ISO 4217"),
        (["--prior-total", "-1", "USD"], "must not be negative"),
        (["--prior-uses", "-1"], "must not be negative"),
    ):
        assert msg in _usage_error("verify", EXTRAS, *args), args
    p = run_cli("verify", EXTRAS, "--prior-uses", "two")
    assert p.returncode == 2 and b"Traceback" not in p.stderr
    p = run_cli("verify", EXTRAS, "--prior-total", "100")
    assert p.returncode == 2 and b"Traceback" not in p.stderr


# ----------------------------------------------------------------------------- batch + report


def test_batch_options(tmp_path: Path) -> None:
    k7 = str(FX / "tamper" / "K7_error_receipt" / "bundle.json")
    for args, flag in (
        (["--expect-total", "9998", "USD"], "--expect-total"),
        (["--expect-checkout-id", "x"], "--expect-checkout-id"),
        (["--prior-total", "0", "USD"], "--prior-total"),
        (["--prior-uses", "0"], "--prior-uses"),
    ):
        assert flag in _usage_error("verify", CARD, k7, *args)
    p = run_cli(
        "verify",
        CARD,
        k7,
        DEMO,
        "--trusted-keys",
        CARD_KEYS,
        "--require-pinned",
        "--expect-merchant-id",
        "merchant_1",
        "--format",
        "json",
    )
    s = json.loads(p.stdout)
    rows = [(r["verdict"], r["outcome"]) for r in s["bundles"]]
    # DEMO's keys are inside the bundle (and differ from the card keys): not VERIFIED
    assert rows[0] == ("VERIFIED", "success")
    # K7: authentic Error payment receipt (with a Success checkout receipt)
    assert rows[1][0] == "VERIFIED" and rows[1][1] in ("declined", "conflicting")
    assert rows[2][0] != "VERIFIED"
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "src/ap2_evidence/schemas/batch-summary.schema.json").read_text())
    jsonschema.validate(s, schema)
    text = run_cli("verify", CARD, k7, "--trusted-keys", CARD_KEYS).stdout.decode()
    assert "OUTCOME" in text and ("outcome declined" in text or "outcome conflicting" in text)
    csv_path = tmp_path / "s.csv"
    run_cli("verify", CARD, k7, "--trusted-keys", CARD_KEYS, "--summary-csv", str(csv_path))
    assert csv_path.read_text(encoding="utf-8").splitlines()[0].startswith("file,verdict,outcome")


def test_report_options_validate_and_source_hash(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "src/ap2_evidence/schemas/report.schema.json").read_text())
    _code, r = _json(
        "verify", EXTRAS, "--trusted-keys", EXTRAS_KEYS, "--prior-uses", "1", "--require-pinned",
        "--expect-total", "9998", "USD",
    )  # fmt: skip
    jsonschema.validate(r, schema)
    sha = hashlib.sha256(Path(CARD).read_bytes()).hexdigest()
    html = run_cli("verify", CARD, "--format", "html").stdout.decode()
    assert sha in html
    out = tmp_path / "r"
    run_cli("verify", CARD, "--out-dir", str(out), "--format", "html")
    assert sha in next(out.iterdir()).read_text(encoding="utf-8")


def test_help_lists_new_flags() -> None:
    text = run_cli("verify", "--help").stdout.decode()
    for flag in (
        "--require-pinned",
        "--expect-agent-key",
        "--expect-checkout-id",
        "--expect-merchant-id",
        "--expect-total",
        "--require-constraint",
        "--prior-total",
        "--prior-uses",
        "12500 USD",
    ):
        assert flag in text
