"""Inputs a first-time user gives by mistake or as Windows saves them.

Windows PowerShell 5.1 writes UTF-16 LE with a BOM on ``>`` and ``Out-File``; other editors save
UTF-8 with a BOM. Each kind of input file must read the same as plain UTF-8. A file that holds
only a BOM or whitespace is "empty" where the CLI refuses it, while an empty token file given to
``verify`` is damaged evidence and still gets a report. ``pack`` keeps a file that is not a token,
but warns about it once on stderr.
"""

from __future__ import annotations

import codecs
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from helpers import ROOT
from helpers import run_cli as _run_cli

BUNDLE = json.loads((ROOT / "examples" / "demo-valid.bundle.json").read_text(encoding="utf-8"))
LOOSE = ROOT / "tests" / "fixtures" / "upstream-sdk" / "loose"
LOOSE_FILES = {
    "--checkout-mandate": ("CM01", LOOSE / "checkout_mandate.txt"),
    "--payment-mandate": ("PM01", LOOSE / "payment_mandate.txt"),
    "--checkout-receipt": ("CR01", LOOSE / "checkout_receipt.jwt"),
    "--payment-receipt": ("PR01", LOOSE / "payment_receipt.jwt"),
}
CHECK_FILE = "; check that the right file was given"
WARNING = "ap2-evidence: warning: "

ENCODINGS: dict[str, Callable[[str], bytes]] = {
    "utf-8-bom": lambda s: codecs.BOM_UTF8 + s.encode("utf-8"),
    "utf-16-le-bom": lambda s: codecs.BOM_UTF16_LE + s.encode("utf-16-le"),
    "utf-16-be-bom": lambda s: codecs.BOM_UTF16_BE + s.encode("utf-16-be"),
}

EMPTY: dict[str, bytes] = {
    "utf-16-le BOM only": codecs.BOM_UTF16_LE,
    "utf-16-be BOM only": codecs.BOM_UTF16_BE,
    "utf-8 BOM only": codecs.BOM_UTF8,
    "utf-16-le BOM and whitespace": codecs.BOM_UTF16_LE + " \r\n".encode("utf-16-le"),
    "whitespace only": b" \r\n",
}


def run_cli(*args: str, stdin: bytes | None = None) -> Any:
    return _run_cli(*args, env={"PYTHONIOENCODING": "utf-8"}, stdin=stdin)


def _out(p: Any) -> str:
    return str(p.stdout.decode("utf-8"))


def _err(p: Any) -> str:
    err = str(p.stderr.decode("utf-8"))
    assert "Traceback" not in err, err
    return err


def _verdict(p: Any) -> str:
    return next(ln for ln in _out(p).splitlines() if ln.startswith("VERDICT:"))


def _write(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def _warnings(p: Any) -> list[str]:
    return [ln for ln in _err(p).splitlines() if ln.startswith(WARNING)]


# ------------------------------------------------------------------ BOM-encoded files read as text


@pytest.mark.parametrize("enc", ENCODINGS)
def test_bom_bundle_verifies_like_utf8(tmp_path: Path, enc: str) -> None:
    text = json.dumps(BUNDLE, indent=2) + "\r\n"
    plain = run_cli("verify", _write(tmp_path / "plain.json", text.encode("utf-8")))
    p = run_cli("verify", _write(tmp_path / "b.json", ENCODINGS[enc](text)))
    assert p.returncode == plain.returncode, _err(p)
    assert _verdict(p) == _verdict(plain)


@pytest.mark.parametrize("enc", ENCODINGS)
def test_bom_trusted_keys_file_pins_keys(tmp_path: Path, enc: str) -> None:
    bundle = _write(tmp_path / "b.json", json.dumps(BUNDLE).encode("utf-8"))
    keys = _write(tmp_path / "k.json", ENCODINGS[enc](json.dumps(BUNDLE["keys"]) + "\r\n"))
    p = run_cli("verify", bundle, "--trusted-keys", keys)
    _err(p)
    assert "(keys: pinned)" in _verdict(p)


@pytest.mark.parametrize("enc", ENCODINGS)
def test_bom_loose_token_verify_pack_inspect(tmp_path: Path, enc: str) -> None:
    token = BUNDLE["checkout_mandate"]
    plain = _write(tmp_path / "plain.txt", token.encode("utf-8"))
    f = _write(tmp_path / "t.txt", ENCODINGS[enc](token + "\r\n"))
    want = run_cli("verify", "--checkout-mandate", plain)
    v = run_cli("verify", "--checkout-mandate", f)
    assert v.returncode == want.returncode, _err(v)
    assert _verdict(v) == _verdict(want)
    out = tmp_path / "p.json"
    p = run_cli("pack", "--checkout-mandate", f, "--out", str(out))
    assert p.returncode == 0, _err(p)
    assert "warning:" not in _err(p)
    assert json.loads(out.read_text(encoding="utf-8"))["checkout_mandate"] == token
    i = run_cli("inspect", f)
    assert i.returncode == 0, _err(i)
    assert "sd-jwt chain" in _out(i)


# ----------------------------------------------- refused empty inputs say so and name the input


@pytest.mark.parametrize("data", EMPTY.values(), ids=list(EMPTY))
def test_bom_only_or_blank_files_are_empty(tmp_path: Path, data: bytes) -> None:
    f = _write(tmp_path / "e.bin", data)
    bundle = _write(tmp_path / "b.json", json.dumps(BUNDLE).encode("utf-8"))
    mandate = str(LOOSE / "checkout_mandate.txt")
    x = str(tmp_path / "x.json")
    for args, named in (
        (["verify", f], f"bundle {f} is empty"),
        (["verify", bundle, "--trusted-keys", f], f"trusted keys file {f} is empty"),
        (["verify", bundle, "--issuer-key", f], "key file e.bin is empty"),
        (["pack", "--checkout-mandate", f, "--out", x], f"checkout mandate file {f} is empty"),
        (
            ["pack", "--checkout-mandate", mandate, "--trusted-keys", f, "--out", x],
            f"trusted keys file {f} is empty",
        ),
        (["inspect", f], f"input {f} is empty"),
    ):
        p = run_cli(*args)
        assert p.returncode == 2, (args, _out(p), _err(p))
        err = _err(p).strip()
        assert named + CHECK_FILE in err, (args, err)
        assert err.endswith(CHECK_FILE), (args, err)
    assert not Path(x).exists()


@pytest.mark.parametrize("data", [b"", codecs.BOM_UTF16_LE, b" \n"], ids=["empty", "bom", "blank"])
def test_empty_stdin_says_so(tmp_path: Path, data: bytes) -> None:
    out = str(tmp_path / "x.json")
    for args, named in (
        (["verify", "-"], "bundle on stdin is empty"),
        (["inspect", "-"], "input on stdin is empty"),
        (["pack", "--checkout-mandate", "-", "--out", out], "checkout mandate on stdin is empty"),
    ):
        p = run_cli(*args, stdin=data)
        assert p.returncode == 2, (args, _out(p), _err(p))
        assert _err(p).strip().endswith(named + CHECK_FILE), (args, _err(p))
    assert not Path(out).exists()


# ------------------------------------- an empty token file given to verify is reported, as in 0.1.0


@pytest.mark.parametrize("flag", LOOSE_FILES)
def test_verify_reports_an_empty_loose_file_and_checks_the_rest(tmp_path: Path, flag: str) -> None:
    empty = _write(tmp_path / "empty.txt", codecs.BOM_UTF16_LE)
    args = ["verify", "--format", "json"]
    for f, (_check, path) in LOOSE_FILES.items():
        args += [f, empty if f == flag else str(path)]
    p = run_cli(*args)
    assert p.returncode == 1, _err(p)
    report = json.loads(_out(p))
    assert report["verdict"] == "FAILED"
    status = {c["id"]: c["status"] for c in report["checks"]}
    for f, (check, _path) in LOOSE_FILES.items():
        assert status[check] == ("FAIL" if f == flag else "PASS"), (flag, check, status[check])


def test_verify_one_empty_and_one_valid_mandate(tmp_path: Path) -> None:
    empty = _write(tmp_path / "empty.txt", b"")
    p = run_cli(
        "verify",
        "--checkout-mandate",
        empty,
        "--payment-mandate",
        str(LOOSE / "payment_mandate.txt"),
        "--format",
        "json",
    )
    assert p.returncode == 1, _err(p)
    checks = {c["id"]: c for c in json.loads(_out(p))["checks"]}
    assert checks["CM01"]["status"] == "FAIL"
    assert checks["PM01"]["status"] == "PASS"
    assert any(
        i.startswith("PM") and c["status"] != "SKIP" for i, c in checks.items() if i != "PM01"
    )


# ------------------------------------------- pack: each warning once on stderr, a marker on stdout


def test_pack_warns_on_stderr_for_a_file_that_is_not_a_token(tmp_path: Path) -> None:
    junk = _write(tmp_path / "notbundle.txt", b"this is not a token\r\n")
    out = tmp_path / "p.json"
    p = run_cli("pack", "--checkout-mandate", junk, "--payment-receipt", junk, "--out", str(out))
    assert p.returncode == 0, _err(p)
    lines = _warnings(p)
    assert len(lines) == 2, _err(p)
    mandate, receipt = lines
    assert f"checkout_mandate file {junk} does not look like an SD-JWT mandate chain" in mandate
    assert f"payment_receipt file {junk} does not look like a signed receipt" in receipt
    for line in lines:
        assert "packed as it is" in line and "'ap2-evidence verify' will report it" in line
    summary = _out(p)
    assert "warning:" not in summary
    assert summary.count("(unparsed)") == 2
    b = json.loads(out.read_text(encoding="utf-8"))
    assert b["checkout_mandate"] == b["payment_receipt"] == "this is not a token"  # bytes kept
    v = run_cli("verify", str(out))
    assert v.returncode == 1, _err(v)  # verify reports it


def test_pack_swapped_receipt_warns_once(tmp_path: Path) -> None:
    mandate = str(LOOSE / "checkout_mandate.txt")
    out = tmp_path / "p.json"
    p = run_cli(
        "pack", "--checkout-mandate", mandate, "--checkout-receipt", mandate, "--out", str(out)
    )
    assert p.returncode == 0, _err(p)
    lines = _warnings(p)
    assert len(lines) == 1, _err(p)
    assert f"checkout_receipt file {mandate} contains '~' like an SD-JWT" in lines[0]
    assert "swapped" in lines[0]
    summary = _out(p)
    assert "warning:" not in summary and "not swapped" not in summary
    assert f"checkout_receipt  {mandate} (unparsed)" in summary
    raw = (LOOSE / "checkout_mandate.txt").read_text(encoding="utf-8").strip()
    assert json.loads(out.read_text(encoding="utf-8"))["checkout_receipt"] == raw


def test_pack_unsigned_receipt_warns_once(tmp_path: Path) -> None:
    r = _write(tmp_path / "r.json", json.dumps({"status": "SETTLED"}).encode("utf-8"))
    p = run_cli(
        "pack",
        "--payment-mandate",
        str(LOOSE / "payment_mandate.txt"),
        "--payment-receipt",
        r,
        "--out",
        str(tmp_path / "p.json"),
    )
    assert p.returncode == 0, _err(p)
    lines = _warnings(p)
    assert len(lines) == 1, _err(p)
    assert "this flow produced no signed payment receipt" in lines[0]
    summary = _out(p)
    assert "warning:" not in summary and "this flow produced" not in summary
    assert f"payment_receipt   {r} (unsigned JSON object, proves nothing)" in summary


def test_pack_valid_tokens_with_crlf_print_no_warning(tmp_path: Path) -> None:
    receipt = (LOOSE / "checkout_receipt.jwt").read_text(encoding="utf-8").strip()
    crlf = _write(tmp_path / "r.jwt", (receipt + "\r\n").encode("utf-8"))
    out = tmp_path / "p.json"
    p = run_cli(
        "pack",
        "--checkout-mandate",
        str(LOOSE / "checkout_mandate.txt"),
        "--checkout-receipt",
        crlf,
        "--out",
        str(out),
    )
    assert p.returncode == 0, _err(p)
    assert "warning:" not in _err(p) and "warning:" not in _out(p)
    assert f"{crlf} (JWT)" in _out(p)
    assert json.loads(out.read_text(encoding="utf-8"))["checkout_receipt"] == receipt
