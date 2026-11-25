"""Batch ``verify``: several bundles or folders, summary formats and the worst exit code."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
from pathlib import Path

import pytest

from ap2_evidence import batch
from helpers import EXAMPLE, ROOT, run_cli

FX = ROOT / "tests" / "fixtures" / "upstream-sdk"
CARD_KEYS = str(FX / "card" / "trusted_keys.json")
_card = json.loads((FX / "card" / "bundle.json").read_text(encoding="utf-8"))
_card.pop("payment_receipt")
INCOMPLETE = json.dumps(_card).encode()  # card without its payment receipt


def _schema() -> dict[str, object]:
    return json.loads(
        (ROOT / "src/ap2_evidence/schemas/batch-summary.schema.json").read_text(encoding="utf-8")
    )


def _mk(tmp: Path, names: dict[str, Path | bytes]) -> Path:
    d = tmp / "in"
    d.mkdir()
    for name, src in names.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        if isinstance(src, bytes):
            (d / name).write_bytes(src)
        else:
            shutil.copy(src, d / name)
    return d


def test_single_bundle_unchanged() -> None:
    """One bundle path: same stdout and exit code as verifying it in-process."""
    from ap2_evidence.bundle import parse_bundle_text
    from ap2_evidence.verify import verify_bundle

    p = run_cli("verify", str(EXAMPLE), "--format", "json")
    r = json.loads(p.stdout)
    ref = verify_bundle(parse_bundle_text(EXAMPLE.read_text(encoding="utf-8"))).to_dict()
    r.pop("generated_at", None)
    ref.pop("generated_at", None)
    assert r == json.loads(json.dumps(ref))
    assert p.returncode == 3
    text = run_cli("verify", str(EXAMPLE)).stdout
    assert text.startswith(b"AP2 evidence report") or b"VERDICT: INCOMPLETE" in text
    assert b"bundle(s):" not in text


@pytest.mark.parametrize(
    ("files", "code"),
    [
        ({"a.json": FX / "card" / "bundle.json"}, 0),
        ({"a.json": FX / "card" / "bundle.json", "b.json": INCOMPLETE}, 3),
        ({"a.json": INCOMPLETE, "b.json": FX / "tamper" / "K1_amount_over_cap" / "bundle.json"}, 1),
        ({"a.json": FX / "card" / "bundle.json", "z.json": b"{broken"}, 2),
        (
            {
                "a.json": FX / "tamper" / "K1_amount_over_cap" / "bundle.json",
                "z.json": b"\xff\xfe\xfd",
            },
            2,
        ),
    ],
)
def test_worst_exit_code(tmp_path: Path, files: dict[str, Path | bytes], code: int) -> None:
    d = _mk(tmp_path, files)
    p = run_cli("verify", str(d), "--trusted-keys", CARD_KEYS)
    assert p.returncode == code, p.stdout
    assert b"Traceback" not in p.stderr
    assert f"(exit code {code})".encode() in p.stdout


def test_json_summary_validates(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    d = _mk(
        tmp_path,
        {
            "a.json": FX / "card" / "bundle.json",
            "b.json": INCOMPLETE,
            "c.json": FX / "tamper" / "K1_amount_over_cap" / "bundle.json",
            "keys.json": FX / "card" / "trusted_keys.json",
            "bad.json": b"[1,",
        },
    )
    p = run_cli("verify", str(d), "--trusted-keys", CARD_KEYS, "--format", "json")
    assert p.returncode == 2
    s = json.loads(p.stdout)
    jsonschema.validate(s, _schema())
    rows = {Path(r["file"]).name: r for r in s["bundles"]}
    assert set(rows) == {"a.json", "b.json", "c.json", "bad.json"}
    assert rows["a.json"]["verdict"] == "VERIFIED" and rows["a.json"]["key_trust"] == "pinned"
    assert rows["c.json"]["failing_checks"] == ["PM32", "XC01"]
    assert rows["b.json"]["verdict"] == "INCOMPLETE" and rows["b.json"]["unverified_checks"]
    assert rows["bad.json"]["verdict"] == "ERROR" and "line 1" in rows["bad.json"]["error"]
    assert [Path(x["file"]).name for x in s["skipped"]] == ["keys.json"]  # a key file, not a bundle
    assert s["counts"] == {"VERIFIED": 1, "INCOMPLETE": 1, "FAILED": 1, "ERROR": 1}
    bad = dict(s, extra=1)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, _schema())


def test_out_dir_and_csv(tmp_path: Path) -> None:
    d = _mk(
        tmp_path,
        {
            "x/bundle.json": FX / "card" / "bundle.json",
            "y/bundle.json": FX / "tamper" / "K2_payee_changed" / "bundle.json",
            "top.json": INCOMPLETE,
        },
    )
    out = tmp_path / "reports"
    csv_path = tmp_path / "s.csv"
    p = run_cli(
        "verify",
        str(d),
        "--recursive",
        "--trusted-keys",
        CARD_KEYS,
        "--out-dir",
        str(out),
        "--summary-csv",
        str(csv_path),
        "--format",
        "md",
    )
    assert p.returncode == 1, p.stderr
    names = sorted(f.name for f in out.iterdir())
    assert names == ["top.report.md", "x__bundle.report.md", "y__bundle.report.md"]
    assert (out / "y__bundle.report.md").read_text(encoding="utf-8").startswith("# AP2 evidence")
    rows = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8"))))
    assert [r["verdict"] for r in rows] == ["INCOMPLETE", "VERIFIED", "FAILED"]
    assert rows[2]["failing_checks"] == "PM33 XC02"
    assert tuple(rows[0]) == batch.CSV_COLUMNS
    # without --recursive only top.json is found
    p = run_cli("verify", str(d), "--format", "json")
    assert [Path(r["file"]).name for r in json.loads(p.stdout)["bundles"]] == ["top.json"]


def test_several_files_and_trusted_keys_apply_to_all(tmp_path: Path) -> None:
    files = [
        str(FX / "card" / "bundle.json"),
        str(FX / "tamper" / "K1_amount_over_cap" / "bundle.json"),
    ]
    p = run_cli("verify", *files, "--trusted-keys", CARD_KEYS, "--format", "json")
    s = json.loads(p.stdout)
    assert p.returncode == 1
    assert [r["key_trust"] for r in s["bundles"]] == ["pinned", "pinned"]
    assert [r["file"] for r in s["bundles"]] == files


def test_batch_usage_errors(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    for args, msg in (
        (["verify", str(empty)], b"no .json files"),
        (["verify", str(EXAMPLE), "-"], b"stdin"),
        (["verify", str(EXAMPLE), str(EXAMPLE), "--expect-payment-nonce", "x"], b"nonce"),
        (["verify", str(EXAMPLE), "--recursive"], b"--recursive"),
        (["verify", str(EXAMPLE), str(tmp_path / "missing.json")], b"file not found"),
    ):
        p = run_cli(*args)
        assert p.returncode == 2, args
        assert msg in p.stderr + p.stdout, (args, p.stderr)
        assert b"Traceback" not in p.stderr
    (empty / "keys.json").write_text("{}", encoding="utf-8")
    p = run_cli("verify", str(empty))
    assert p.returncode == 2 and b"no evidence bundles" in p.stderr


def test_many_files_and_hostile_entries(tmp_path: Path) -> None:
    d = tmp_path / "many"
    d.mkdir()
    data = (FX / "tamper" / "K1_amount_over_cap" / "bundle.json").read_bytes()
    for i in range(300):
        (d / f"b{i:04}.json").write_bytes(data)
    (d / "big.json").write_bytes(b" " * (9 * 1024 * 1024))
    (d / "folder.json").mkdir()  # a folder named like a bundle is ignored
    (d / "bin.json").write_bytes(bytes(range(256)) * 10)
    p = run_cli("verify", str(d), "--format", "json")
    s = json.loads(p.stdout)
    assert p.returncode == 2
    assert s["counts"]["FAILED"] == 300 and s["counts"]["ERROR"] == 2
    errors = {Path(r["file"]).name: r["error"] for r in s["bundles"] if r["verdict"] == "ERROR"}
    assert "larger than" in errors["big.json"] and "binary" in errors["bin.json"]


def test_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ap2_evidence.bundle import InputError

    d = tmp_path / "d"
    d.mkdir()
    for i in range(5):
        (d / f"{i}.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(batch, "MAX_BATCH_FILES", 3)
    with pytest.raises(InputError, match="more than 3"):
        batch.collect([str(d)], False)
    deep = tmp_path / "deep"
    cur = deep
    for i in range(5):
        cur = cur / f"l{i}"
    cur.mkdir(parents=True)
    monkeypatch.setattr(batch, "MAX_DIR_DEPTH", 2)
    with pytest.raises(InputError, match="nested deeper"):
        batch.collect([str(deep)], True)


def _link_dir(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":  # a junction needs no privilege on Windows
        import subprocess

        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
        )
        if r.returncode == 0:
            return
    pytest.skip("cannot create directory links here")


def test_link_loop_terminates(tmp_path: Path) -> None:
    d = tmp_path / "loop"
    (d / "sub").mkdir(parents=True)
    shutil.copy(FX / "card" / "bundle.json", d / "sub" / "b.json")
    _link_dir(d, d / "sub" / "back")
    items = batch.collect([str(d)], True)
    assert [Path(i.path).name for i in items] == ["b.json"]
    p = run_cli("verify", str(d), "--recursive", "--trusted-keys", CARD_KEYS)
    assert p.returncode == 0, p.stderr


def test_missing_paths_write_nothing(tmp_path: Path) -> None:
    out, csv_path = tmp_path / "reports", tmp_path / "summary.csv"
    p = run_cli(
        "verify",
        str(tmp_path / "evidence-folder"),
        "--out-dir",
        str(out),
        "--summary-csv",
        str(csv_path),
    )
    assert p.returncode == 2 and p.stdout == b""
    err = p.stderr.decode("utf-8", "replace").strip().splitlines()
    assert len(err) == 1 and "not found" in err[0]
    assert not out.exists() and not csv_path.exists()
    # only unreadable files: also nothing written
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "x.json").write_text("{broken", encoding="utf-8")
    p = run_cli("verify", str(bad), "--out-dir", str(out), "--summary-csv", str(csv_path))
    assert p.returncode == 2 and b"no evidence bundle could be read" in p.stderr
    assert not out.exists() and not csv_path.exists()
    # one missing among real bundles: ERROR row, the rest is reported
    p = run_cli(
        "verify",
        str(FX / "card" / "bundle.json"),
        str(tmp_path / "nope.json"),
        "--out-dir",
        str(out),
    )
    assert p.returncode == 2 and b"ERROR" in p.stdout and out.is_dir()


def test_explicit_non_bundle_in_batch_is_error(tmp_path: Path) -> None:
    p = run_cli("verify", str(FX / "card" / "bundle.json"), CARD_KEYS, "--format", "json")
    rows = json.loads(p.stdout)["bundles"]
    assert rows[1]["verdict"] == "ERROR" and "looks like a key file" in rows[1]["error"]


def test_outcome_shown_only_for_verified() -> None:
    files = [
        str(FX / "card" / "bundle.json"),
        str(FX / "tamper" / "K4b_payment_receipt_ref_random" / "bundle.json"),
    ]
    text = run_cli("verify", *files, "--trusted-keys", CARD_KEYS).stdout.decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln.startswith(("VERIFIED", "FAILED"))]
    assert lines[0].split()[1] == "success"
    assert lines[1].split()[:2] == ["FAILED", "-"]
    s = json.loads(
        run_cli("verify", *files, "--trusted-keys", CARD_KEYS, "--format", "json").stdout
    )
    assert s["bundles"][1]["verdict"] == "FAILED" and s["bundles"][1]["outcome"] is not None
