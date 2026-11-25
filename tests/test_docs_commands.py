"""Every command shown in docs/getting-evidence-in.md runs and gives the exit code it states."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import ROOT, SRC

DOC = ROOT / "docs" / "getting-evidence-in.md"
_BLOCK = re.compile(r"```bash\n(.*?)```", re.DOTALL)
_EXIT = re.compile(r"\s+#\s*exit\s+(\d)\s*$")


def commands() -> list[tuple[list[str], int]]:
    out = []
    for block in _BLOCK.findall(DOC.read_text(encoding="utf-8")):
        for line in block.splitlines():
            if not line.strip():
                continue
            m = _EXIT.search(line)
            assert m, f"command without '# exit N' in {DOC.name}: {line}"
            argv = shlex.split(line[: m.start()])
            assert argv[0] == "ap2-evidence", line
            out.append((argv[1:], int(m.group(1))))
    return out


def test_doc_has_commands() -> None:
    cmds = commands()
    assert len(cmds) >= 9
    used = {a[0] for a, _ in cmds}
    assert {"pack", "verify", "explain"} <= used


def test_doc_commands_run(tmp_path: Path) -> None:
    shutil.copytree(
        ROOT / "tests" / "fixtures" / "upstream-sdk",
        tmp_path / "tests" / "fixtures" / "upstream-sdk",
    )
    shutil.copytree(ROOT / "examples", tmp_path / "examples")
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    for argv, code in commands():
        p = subprocess.run(
            [sys.executable, "-m", "ap2_evidence", *argv],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            timeout=120,
            check=False,
        )
        assert b"Traceback" not in p.stderr, (argv, p.stderr)
        assert p.returncode == code, (argv, p.returncode, p.stderr.decode(errors="replace"))
        if argv[0] == "pack":
            assert b"next:\n  ap2-evidence verify" in p.stdout.replace(b"\r\n", b"\n")
    names = {f.name for f in (tmp_path / "reports").iterdir()}
    # same file name in four folders: the parent folder tells the reports apart (F8)
    assert names == {
        "card__bundle.report.txt",
        "K1_amount_over_cap__bundle.report.txt",
        "K4b_payment_receipt_ref_random__bundle.report.txt",
        "K7_error_receipt__bundle.report.txt",
    }
    assert (tmp_path / "summary.csv").read_text(encoding="utf-8").startswith("file,verdict")


def test_doc_text_samples_match_real_output(tmp_path: Path) -> None:
    """Every ```text sample in getting-evidence-in.md that follows a command is real output."""
    shutil.copytree(
        ROOT / "tests" / "fixtures" / "upstream-sdk",
        tmp_path / "tests" / "fixtures" / "upstream-sdk",
    )
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    text = DOC.read_text(encoding="utf-8")
    m = re.search(r"The first command prints:\n\n```text\n(.*?)```", text, re.DOTALL)
    assert m, "batch sample missing"
    argv, _code = next(c for c in commands() if "--summary-csv" in c[0])
    p = subprocess.run(
        [sys.executable, "-m", "ap2_evidence", *argv],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    out = p.stdout.decode("utf-8").replace("\r\n", "\n").replace("\\", "/")
    assert out == m.group(1)


@pytest.mark.parametrize("name", ["bundle-format.md", "getting-evidence-in.md"])
def test_doc_links(name: str) -> None:
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([a-z-]+\.md)(?:#[a-z-]+)?\)", text):
        assert (ROOT / "docs" / target).is_file(), target
