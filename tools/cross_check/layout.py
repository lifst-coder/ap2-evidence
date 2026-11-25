"""Where the comparison reads and writes inside this repository."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "third-party"
RESULTS = Path(__file__).resolve().parent / "results.json"
PAGE = ROOT / "docs" / "cross-implementation.md"
FORMAT = "ap2-evidence-cross-check/1"
REGENERATE = "python tools/cross_check run --src <directory with the pinned clones>"


def dump(path: Path, value: Any) -> None:
    """Write JSON with a stable layout (UTF-8, LF, 1-space indent, trailing newline)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def write_text(path: Path, text: str) -> None:
    """Write text with LF line endings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
