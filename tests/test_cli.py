"""The command line, run as a subprocess exactly as a user would."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ap2_evidence.jose import public_jwk
from ap2_evidence.report import FAIL
from helpers import EXAMPLE, KEYS, OFFICIAL, build, run_cli


def _no_traceback(proc: object) -> None:
    err = proc.stderr.decode("utf-8", "replace")  # type: ignore[attr-defined]
    assert "Traceback" not in err, err


def test_version() -> None:
    p = run_cli("--version")
    assert p.returncode == 0
    assert b"ap2-evidence 0.1.0" in p.stdout


def test_demo_exit_0() -> None:
    p = run_cli("demo")
    assert p.returncode == 0, p.stdout.decode(errors="replace")
    assert b"VERDICT: VERIFIED" in p.stdout
    _no_traceback(p)


@pytest.mark.parametrize("mode", ["amount", "receipt", "disclosure", "key"])
def test_demo_tamper_exit_1(mode: str) -> None:
    p = run_cli("demo", "--tamper", mode)
    assert p.returncode == 1
    assert b"VERDICT: FAILED" in p.stdout
    assert b"[FAIL]" in p.stdout


def test_official_example_exit_3() -> None:
    p = run_cli("verify", str(EXAMPLE))
    assert p.returncode == 3
    assert b"VERDICT: INCOMPLETE" in p.stdout
    _no_traceback(p)


def test_loose_files_exit_3() -> None:
    p = run_cli(
        "verify",
        "--checkout-mandate",
        str(OFFICIAL / "checkout_chain.txt"),
        "--payment-mandate",
        str(OFFICIAL / "payment_chain.txt"),
    )
    assert p.returncode == 3


@pytest.mark.parametrize(
    "content",
    [b"", b"garbage", b"{not json", b'{"a": 1, "a": 2}', b"\xff\xfe\xfd", b"[" * 3000],
)
def test_garbage_exit_2(tmp_path: Path, content: bytes) -> None:
    f = tmp_path / "bad.json"
    f.write_bytes(content)
    p = run_cli("verify", str(f))
    assert p.returncode == 2
    lines = p.stderr.decode().strip().splitlines()
    assert len(lines) == 1 and lines[0].startswith("ap2-evidence: error:"), lines
    _no_traceback(p)


def test_wrong_shape_json(tmp_path: Path) -> None:
    f = tmp_path / "b.json"
    # an object without bundle_version is not a bundle: the CLI refuses it (exit 2) ...
    f.write_text("{}", encoding="utf-8")
    line = _one_error_line(run_cli("verify", str(f)))
    assert "not an ap2-evidence bundle: no bundle_version member" in line
    assert "key file" not in line
    # ... while a wrong bundle_version is still verified (FAILED, B01)
    f.write_text('{"bundle_version": "ap2-evidence/9"}', encoding="utf-8")
    p = run_cli("verify", str(f), "--format", "json")
    assert p.returncode == 1
    assert {c["id"]: c["status"] for c in json.loads(p.stdout)["checks"]}["B01"] == FAIL
    f.write_text("[1, 2]", encoding="utf-8")
    assert run_cli("verify", str(f)).returncode == 2  # not an object: unreadable, exit 2
    # the Python API is unchanged: {} is a FAILED report
    from ap2_evidence import verify_bundle

    assert verify_bundle({}).verdict == "FAILED"


@pytest.mark.parametrize(
    "content",
    [
        {"mandate_issuer": [], "merchant": []},
        {"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}]},
        {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
    ],
)
def test_key_file_given_as_bundle(tmp_path: Path, content: object) -> None:
    f = tmp_path / "keys.json"
    f.write_text(json.dumps(content), encoding="utf-8")
    for stdin in (False, True):
        p = run_cli("verify", "-", stdin=f.read_bytes()) if stdin else run_cli("verify", str(f))
        line = _one_error_line(p)
        assert "no bundle_version member" in line and "looks like a key file" in line
        assert "--trusted-keys" in line and "--issuer-key" in line
        assert p.stdout == b""


def test_trusted_keys_given_pem(tmp_path: Path) -> None:
    pem = OFFICIAL.parents[1] / "fixtures" / "upstream-sdk" / "loose" / "issuer.pem"
    line = _one_error_line(run_cli("verify", str(EXAMPLE), "--trusted-keys", str(pem)))
    assert "is PEM" in line and "--issuer-key" in line and "--merchant-key" in line
    junk = tmp_path / "k.txt"
    junk.write_text("not json", encoding="utf-8")
    line = _one_error_line(run_cli("verify", str(EXAMPLE), "--trusted-keys", str(junk)))
    assert "line 1, column 1" in line and "--issuer-key" in line


@pytest.mark.parametrize(
    "args",
    [
        ["verify"],
        ["verify", "does-not-exist.json"],
        ["verify", str(EXAMPLE), "--skew", "-5"],
        ["verify", str(EXAMPLE), "--skew", "abc"],
        ["verify", str(EXAMPLE), "--at", "yesterday"],
        ["verify", str(EXAMPLE), "--checkout-mandate", str(EXAMPLE)],
        ["verify", str(EXAMPLE), "--trusted-keys", "missing.json"],
        ["verify", str(EXAMPLE), "--format", "pdf"],
        ["demo", "--tamper", "everything"],
        ["inspect", "missing.txt"],
        ["nonsense"],
        [],
    ],
)
def test_usage_errors_exit_2(args: list[str]) -> None:
    p = run_cli(*args)
    assert p.returncode == 2, (args, p.stdout, p.stderr)
    _no_traceback(p)


def test_directory_as_input(tmp_path: Path) -> None:
    p = run_cli("verify", str(tmp_path))
    assert p.returncode == 2
    _no_traceback(p)


def test_stdin_bundle() -> None:
    p = run_cli("verify", "-", "--format", "json", stdin=EXAMPLE.read_bytes())
    assert p.returncode == 3
    assert json.loads(p.stdout)["verdict"] == "INCOMPLETE"


def test_json_output_validates(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).parents[1] / "src/ap2_evidence/schemas/report.schema.json").read_text()
    )
    for args, code in (
        (["demo", "--format", "json"], 0),
        (["demo", "--tamper", "disclosure", "--format", "json"], 1),
        (["verify", str(EXAMPLE), "--format", "json"], 3),
    ):
        p = run_cli(*args)
        assert p.returncode == code
        jsonschema.validate(json.loads(p.stdout), schema)
        p.stdout.decode("ascii")  # ensure_ascii


def test_save_bundle_and_reverify(tmp_path: Path) -> None:
    out = tmp_path / "demo.bundle.json"
    report = tmp_path / "report.md"
    p = run_cli("demo", "--save-bundle", str(out), "--format", "md", "--out", str(report))
    assert p.returncode == 0
    assert report.read_text(encoding="utf-8").startswith("# AP2 evidence report")
    p2 = run_cli("verify", str(out))
    assert p2.returncode == 0
    assert b"VERDICT: VERIFIED" in p2.stdout


def test_trusted_keys_file(tmp_path: Path) -> None:
    bundle = build()
    (tmp_path / "b.json").write_text(json.dumps(bundle), encoding="utf-8")
    keys = {
        "mandate_issuer": [public_jwk(KEYS.issuer, KEYS.issuer_kid)],
        "merchant": [public_jwk(KEYS.merchant, KEYS.merchant_kid)],
        "payment_processor": [public_jwk(KEYS.processor, KEYS.processor_kid)],
    }
    (tmp_path / "k.json").write_text(json.dumps(keys), encoding="utf-8")
    p = run_cli(
        "verify",
        str(tmp_path / "b.json"),
        "--trusted-keys",
        str(tmp_path / "k.json"),
        "--format",
        "json",
    )
    assert p.returncode == 0
    r = json.loads(p.stdout)
    assert {c["key_provenance"] for c in r["checks"] if c["id"] in ("CM03", "CR02", "PR02")} == {
        "trusted"
    }
    (tmp_path / "jwks.json").write_text(json.dumps({"keys": keys["merchant"]}), encoding="utf-8")
    p = run_cli("verify", str(tmp_path / "b.json"), "--trusted-keys", str(tmp_path / "jwks.json"))
    assert p.returncode == 2
    assert b"plain JWKS" in p.stderr


def test_at_option(tmp_path: Path) -> None:
    p = run_cli("verify", str(EXAMPLE), "--at", "2026-04-28T02:30:00Z", "--format", "json")
    r = json.loads(p.stdout)
    assert {c["id"]: c["status"] for c in r["checks"]}["CM19"] == "PASS"
    p = run_cli("verify", str(EXAMPLE), "--at", "1900000000", "--format", "json")
    assert p.returncode == 1
    assert {c["id"]: c["status"] for c in json.loads(p.stdout)["checks"]}["CM19"] == FAIL


def test_inspect(tmp_path: Path) -> None:
    p = run_cli("inspect", str(OFFICIAL / "checkout_chain.txt"))
    assert p.returncode == 0
    out = p.stdout.decode("utf-8", "replace")
    assert "FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8" in out
    assert "segment 2" in out
    p = run_cli("inspect", str(EXAMPLE), "--format", "json")
    info = json.loads(p.stdout)
    assert info["kind"] == "bundle" and set(info["artifacts"]) == {
        "checkout_mandate",
        "payment_mandate",
    }
    f = tmp_path / "r.txt"
    f.write_text(build()["payment_receipt"], encoding="utf-8")
    p = run_cli("inspect", str(f), "--format", "json")
    assert json.loads(p.stdout)["kind"] == "jwt"
    f.write_text("!!!", encoding="utf-8")
    assert run_cli("inspect", str(f)).returncode == 2


def test_cp949_console(tmp_path: Path) -> None:
    """Korean-locale Windows console: stdout is cp949 and cannot show every character."""

    def m(b: object) -> None:
        b.checkout_payload["merchant"]["name"] = "데모 상점 \U0001f600"  # type: ignore[attr-defined]
        b.closed_payment["payee"]["name"] = "데모 상점 \U0001f600"  # type: ignore[attr-defined]

    f = tmp_path / "k.json"
    f.write_text(json.dumps(build(mutate=m)), encoding="utf-8")
    env = {"PYTHONIOENCODING": "cp949"}
    for args in (
        ["verify", str(f)],
        ["verify", str(f), "--format", "md"],
        ["demo"],
        ["inspect", str(f)],
    ):
        p = run_cli(*args, env=env)
        _no_traceback(p)
        assert p.returncode in (0, 1, 3), (args, p.stderr)
        text = p.stdout.decode("cp949")
        if args[0] == "verify" and "md" not in args:
            assert "[PASS]" in text or "[FAIL]" in text
            assert "\\U0001f600" in text  # unencodable emoji escaped, not crashing
            assert "데모 상점" in text
    p = run_cli("verify", str(f), "--out", str(tmp_path / "r.txt"), env=env)
    assert "\U0001f600" in (tmp_path / "r.txt").read_text(encoding="utf-8")


def test_terminal_injection_is_neutralised(tmp_path: Path) -> None:
    def m(b: object) -> None:
        b.checkout_payload["merchant"]["name"] = "Evil\x1b[2J‮Shop"  # type: ignore[attr-defined]

    f = tmp_path / "e.json"
    f.write_text(json.dumps(build(mutate=m)), encoding="utf-8")
    p = run_cli("verify", str(f))
    assert b"\x1b" not in p.stdout
    assert "‮".encode() not in p.stdout
    p = run_cli("verify", str(f), "--format", "md")
    assert b"\x1b" not in p.stdout


@pytest.mark.parametrize(("name", "code"), [("demo-valid", 0), ("demo-tamper-amount", 1)])
def test_committed_examples(name: str, code: int) -> None:
    p = run_cli("verify", str(EXAMPLE.parent / f"{name}.bundle.json"))
    assert p.returncode == code


# ------------------------------------------------------------------ error messages, encodings


def _one_error_line(p: object) -> str:
    err = p.stderr.decode("ascii")  # type: ignore[attr-defined]  # English only, no mojibake
    lines = err.strip().splitlines()
    assert len(lines) == 1 and lines[0].startswith("ap2-evidence: error:"), err
    return lines[0]


@pytest.mark.parametrize("enc", ["cp949", "ascii", "utf-8"])
def test_missing_file_message_is_english(enc: str) -> None:
    p = run_cli("verify", "nonexist.json", env={"PYTHONIOENCODING": enc})
    assert p.returncode == 2
    line = _one_error_line(p)
    assert line == (
        "ap2-evidence: error: cannot read bundle nonexist.json: file not found; check the path "
        "and the current directory"
    )


def test_error_reasons(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{\n  "bundle_version": "ap2-evidence/1",\n  "note": oops\n}', encoding="utf-8")
    line = _one_error_line(run_cli("verify", str(bad)))
    assert "not valid JSON at line 3, column 11" in line
    binf = tmp_path / "bin.json"
    binf.write_bytes(b"\x00\x01\x02\xff" * 50)
    assert "binary file" in _one_error_line(run_cli("verify", str(binf)))
    latin = tmp_path / "latin.json"
    latin.write_bytes('{"note": "caf\xe9"}'.encode("latin-1"))
    assert "not valid UTF-8" in _one_error_line(run_cli("verify", str(latin)))
    assert "it is a directory" in _one_error_line(
        run_cli("verify", "--checkout-mandate", str(tmp_path))
    )
    assert "file not found" in _one_error_line(
        run_cli("verify", str(EXAMPLE), "--trusted-keys", str(tmp_path / "k.json"))
    )
    out = tmp_path / "nofolder" / "r.txt"
    assert "folder does not exist" in _one_error_line(
        run_cli("verify", str(EXAMPLE), "--out", str(out))
    )


@pytest.mark.parametrize("enc", ["cp949", "ascii"])
def test_narrow_console_never_crashes(tmp_path: Path, enc: str) -> None:
    """Non-ASCII paths and content on a cp949 or ASCII console: escaped, never a traceback."""
    d = tmp_path / "증거 é\U0001f600"
    d.mkdir()
    f = d / "번들.json"
    f.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    env = {"PYTHONIOENCODING": enc}
    for args in (
        ["verify", str(f)],
        ["verify", str(d)],
        ["verify", str(d / "없음.json")],
        [
            "pack",
            "--checkout-mandate",
            str(OFFICIAL / "checkout_chain.txt"),
            "--note",
            "메모",
            "--out",
            str(d / "새.json"),
        ],
        ["explain", "PM32"],
        ["explain", "없는ID"],
        ["verify", "--help"],
    ):
        p = run_cli(*args, env=env)
        _no_traceback(p)
        assert p.returncode in (0, 2, 3), (args, p.stderr)
        p.stdout.decode(enc)
        p.stderr.decode(enc)
    p = run_cli("verify", str(d / "없음.json"), env=env)
    assert b"\\" in p.stderr  # the unencodable path characters are backslash-escaped


def test_explain() -> None:
    p = run_cli("explain", "PM32")
    assert p.returncode == 0
    out = p.stdout.decode()
    assert out.startswith("PM32: ")
    labels = (
        "What it checks:",
        "Purpose:",
        "Required:",
        "Worst status:",
        "Spec reference (upstream AP2 repository, v0.2.0):",
    )
    for label in labels:
        assert label in out
    assert "payment_mandate.md" in out
    assert run_cli("explain", "pm32").stdout == p.stdout
    p = run_cli("explain", "XC4")
    assert p.returncode == 2
    assert "closest:" in _one_error_line(p) and "XC04" in p.stderr.decode()
    p = run_cli("explain", "--list")
    assert p.returncode == 0
    listed = p.stdout.decode()
    from ap2_evidence.checks import REGISTRY

    assert all(f"  {cid} " in listed for cid in REGISTRY)
    assert run_cli("explain").returncode == 2
    assert run_cli("explain", "PM32", "--list").returncode == 2


def test_html_format(tmp_path: Path) -> None:
    from ap2_evidence.report import Report

    if not hasattr(Report, "to_html"):
        p = run_cli("verify", str(EXAMPLE), "--format", "html")
        assert p.returncode == 2 and b"html" in p.stderr
        pytest.skip("Report.to_html not available yet")
    p = run_cli("verify", str(EXAMPLE), "--format", "html")
    assert p.returncode == 3
    assert b"<html" in p.stdout.lower()
    assert run_cli("demo", "--format", "html").returncode == 0


@pytest.mark.parametrize("cmd", ["verify", "pack", "explain", "demo", "inspect"])
def test_subcommand_help(cmd: str) -> None:
    p = run_cli(cmd, "--help")
    assert p.returncode == 0
    assert b"usage: ap2-evidence " + cmd.encode() in p.stdout


@pytest.mark.parametrize("enc", ["cp949", "ascii"])
def test_console_transliterates_punctuation(tmp_path: Path, enc: str) -> None:
    card = OFFICIAL.parents[1] / "fixtures" / "upstream-sdk" / "card" / "bundle.json"
    p = run_cli("verify", str(card), env={"PYTHONIOENCODING": enc})
    text = p.stdout.decode(enc)
    assert re.search(r"Card \*{3,4}4242", text), text[:2000]
    assert "\\u2022" not in text
    out = tmp_path / "r.txt"
    run_cli("verify", str(card), "--out", str(out), env={"PYTHONIOENCODING": enc})
    assert re.search("Card \u2022{3,4}4242", out.read_text(encoding="utf-8"))  # files stay UTF-8


def test_console_fallback_table() -> None:
    from ap2_evidence.fileio import ERROR_HANDLER

    s = "a\u2022b\u2026c\u2013d\u2014e\u201cf\u201dg\u2018h\u2019i\u00a0j\U0001f600"
    assert s.encode("ascii", ERROR_HANDLER) == b"a*b...c-d-e\"f\"g'h'i j\\U0001f600"
    assert "\u2022".encode("utf-8", ERROR_HANDLER) == "\u2022".encode()


def test_demo_help_explains_scenarios() -> None:
    out = run_cli("demo", "--help").stdout.decode()
    assert "Build a complete AP2 v0.2 demo transaction" in out
    for line in (
        "amount      the agent validly signs USD 250.00",
        "receipt     a validly signed receipt that belongs to a different mandate",
        "disclosure  an allowed-merchant entry is swapped after the mandate was issued",
        "key         the closed payment mandate is signed by a key other than the one",
    ):
        assert line in out


def test_overwrite_behaviour_is_documented_in_help() -> None:
    verify_help = " ".join(run_cli("verify", "--help").stdout.decode().split())
    assert verify_help.count("replaced if it exists") >= 2
    assert "existing reports are not replaced unless --force" in verify_help
    pack_help = " ".join(run_cli("pack", "--help").stdout.decode().split())
    assert "not replaced unless --force" in pack_help
