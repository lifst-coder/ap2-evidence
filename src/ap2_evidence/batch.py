"""Batch verification: many bundle files or directories in one ``verify`` run.

The summary has a fixed JSON form (``schemas/batch-summary.schema.json``, documented in
``docs/bundle-format.md``). The exit code is the worst over all bundles: 2 if any file
could not be read, else 1 if any is FAILED, else 3 if any is INCOMPLETE, else 0.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._version import __version__
from .bundle import InputError, parse_bundle_text, require_bundle_object
from .fileio import decode_text, long_path, make_dir, os_error_reason, read_bytes, write_text
from .report import Report

MAX_BATCH_FILES = 10_000
"""Refuse a batch run over more files than this."""

MAX_DIR_DEPTH = 32
"""Maximum folder depth followed with ``--recursive``."""

SUMMARY_VERSION = "1"

ERROR = "ERROR"
VERDICT_ORDER = ("VERIFIED", "INCOMPLETE", "FAILED", ERROR)
_EXIT = {"VERIFIED": 0, "FAILED": 1, "INCOMPLETE": 3, ERROR: 2}
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _clean(text: str, limit: int = 300) -> str:
    out = _UNSAFE.sub("?", text)
    if len(out) <= limit:
        return out
    # keep the end, where a path has its file name
    return out[:100] + "..." + out[-(limit - 103) :]


@dataclass
class Item:
    """One file to verify."""

    path: str
    display: str
    rel: str
    from_dir: bool


@dataclass
class Row:
    """Summary of one bundle's verification."""

    file: str
    verdict: str
    key_trust: str | None = None
    outcome: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    failing: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)
    report: str | None = None
    error: str | None = None

    @property
    def exit_code(self) -> int:
        """Exit code this bundle alone would have (2 also when its report could not be written)."""
        return 2 if self.error is not None else _EXIT[self.verdict]

    def to_dict(self) -> dict[str, Any]:
        """JSON form (see the batch summary schema)."""
        return {
            "file": self.file,
            "verdict": self.verdict,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "key_trust": self.key_trust,
            "pass": self.counts.get("pass", 0),
            "fail": self.counts.get("fail", 0),
            "warn": self.counts.get("warn", 0),
            "skip": self.counts.get("skip", 0),
            "failing_checks": self.failing,
            "unverified_checks": self.unverified,
            "report": self.report,
            "error": self.error,
        }


@dataclass
class Batch:
    """Result of a batch run."""

    rows: list[Row]
    skipped: list[dict[str, str]]

    @property
    def exit_code(self) -> int:
        """Worst exit code: 2 unreadable > 1 FAILED > 3 INCOMPLETE > 0 VERIFIED."""
        codes = {r.exit_code for r in self.rows}
        for code in (2, 1, 3):
            if code in codes:
                return code
        return 0

    @property
    def write_errors(self) -> int:
        """Rows whose bundle was verified but whose report could not be written."""
        return sum(1 for r in self.rows if r.verdict != ERROR and r.error is not None)

    @property
    def worst(self) -> str:
        """Verdict matching :attr:`exit_code`."""
        return {2: ERROR, 1: "FAILED", 3: "INCOMPLETE", 0: "VERIFIED"}[self.exit_code]

    @property
    def verified_rows(self) -> int:
        """Rows of bundles that could be read and verified (not ERROR)."""
        return sum(1 for r in self.rows if r.verdict != ERROR)

    def counts(self) -> dict[str, int]:
        """Number of bundles per verdict."""
        return {v: sum(1 for r in self.rows if r.verdict == v) for v in VERDICT_ORDER}


def _walk(root: Path, recursive: bool, exclude: Path | None, out: list[tuple[Path, str]]) -> None:
    seen: set[tuple[int, int]] = set()
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    while stack:
        folder, prefix, depth = stack.pop()
        try:
            st = Path(long_path(str(folder))).stat()
            ident = (st.st_dev, st.st_ino)
            if ident in seen and ident != (0, 0):
                continue
            seen.add(ident)
            with os.scandir(long_path(str(folder))) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            reason, hint = os_error_reason(exc)
            raise InputError(f"cannot list folder {folder}: {reason}; {hint}") from None
        subdirs: list[tuple[Path, str, int]] = []
        for e in entries:
            rel = f"{prefix}{e.name}"
            try:
                if e.is_dir():
                    if _is_link(e):
                        continue  # symlinked folders and junctions are never followed
                    if recursive and not (exclude and _same(Path(e.path), exclude)):
                        if depth + 1 > MAX_DIR_DEPTH:
                            raise InputError(
                                f"{e.path} is nested deeper than {MAX_DIR_DEPTH} folders; give a "
                                "folder closer to the bundles"
                            )
                        subdirs.append((Path(e.path), rel + "/", depth + 1))
                    continue
                if e.name.lower().endswith(".json") and e.is_file():
                    out.append((Path(e.path), rel))
            except OSError:
                continue
            if len(out) > MAX_BATCH_FILES:
                raise InputError(
                    f"more than {MAX_BATCH_FILES} .json files under {root}; split the run into "
                    "smaller folders"
                )
        stack.extend(reversed(subdirs))


def _is_link(e: os.DirEntry[str]) -> bool:
    """True for a symbolic link or a Windows junction / other reparse point."""
    try:
        if e.is_symlink():
            return True
        attrs = getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def collect(paths: list[str], recursive: bool, exclude: str | None = None) -> list[Item]:
    """Expand files and folders into the list of files to verify (in a stable order).

    Raises:
        InputError: If a folder cannot be listed, or there are too many files.
    """
    items: list[Item] = []
    excl = Path(exclude) if exclude else None
    for arg in paths:
        p = Path(arg)
        if arg != "-" and p.is_dir():
            found: list[tuple[Path, str]] = []
            _walk(p, recursive, excl, found)
            items += [Item(str(fp), str(p / rel), rel, True) for fp, rel in found]
        else:
            items.append(Item(arg, arg, Path(arg).name, False))
        if len(items) > MAX_BATCH_FILES:
            raise InputError(f"more than {MAX_BATCH_FILES} files in one run; split it up")
    return items


_MAX_PARENTS = 4
"""How many parent folders a report name may borrow to tell same-named bundles apart."""


def _base_name(item: Item, parents: int) -> str:
    """Filesystem-safe report base name for ``item``.

    The path inside the folder argument, plus ``parents`` folder names above it
    (``K1_amount_over_cap__bundle``).
    """
    rel = item.rel.replace("\\", "/")
    stem = rel[:-5] if rel.lower().endswith(".json") else rel
    parts = [p for p in stem.split("/") if p]
    if parents:
        try:
            full = Path(os.path.abspath(item.path)).parts
        except (OSError, ValueError):
            full = ()
        above = list(full[1 : max(len(full) - len(parts), 1)])  # without the drive / root
        parts = above[-parents:] + parts
    base = _NAME_UNSAFE.sub("_", "__".join(parts)).strip("._") or "bundle"
    if len(base) > 150:  # keep both ends: the start of the name and the file name at the end
        base = base[:70] + "_" + base[-79:]
    return base


def _identity(item: Item) -> str:
    try:
        return os.path.normcase(os.path.abspath(item.path))
    except (OSError, ValueError):
        return item.path


def report_names(items: list[Item], ext: str) -> list[str]:
    """The ``--out-dir`` file name of each item's report (stable, collision-free).

    A name is the bundle's path inside its folder argument (``sub__x.report.txt``). When
    several bundles would get the same name (for example ``K1/bundle.json`` and
    ``K2/bundle.json`` given one by one), the names of their parent folders are added
    (``K1__bundle.report.txt``), up to :data:`_MAX_PARENTS` levels; a ``-2``, ``-3``
    suffix is the last resort (for example the same file given twice).
    """
    depth = [0] * len(items)
    bases = [_base_name(it, 0) for it in items]
    for _ in range(_MAX_PARENTS):
        groups: dict[str, list[int]] = {}
        for i, b in enumerate(bases):
            groups.setdefault(b.lower(), []).append(i)
        clashing = [ix for ix in groups.values() if len(ix) > 1]
        if not clashing:
            break
        changed = False
        for ix in clashing:
            if len({_identity(items[i]) for i in ix}) == 1:
                continue  # the same file given twice: only the -2 suffix tells them apart
            for i in ix:
                new = _base_name(items[i], depth[i] + 1)
                if new.lower() != bases[i].lower():
                    depth[i] += 1
                    bases[i] = new
                    changed = True
        if not changed:
            break
    used: set[str] = set()
    names: list[str] = []
    for base in bases:
        name = f"{base}.report.{ext}"
        n = 2
        while name.lower() in used:
            name = f"{base}-{n}.report.{ext}"
            n += 1
        used.add(name.lower())
        names.append(name)
    return names


def existing_reports(items: list[Item], out_dir: Path, ext: str) -> list[Path]:
    """Report files of this run that already exist in ``out_dir``."""
    return [out_dir / n for n in report_names(items, ext) if (out_dir / n).exists()]


def run(
    items: list[Item],
    verify: Callable[[Any], Report],
    render: Callable[[Report], str] | None = None,
    out_dir: Path | None = None,
    ext: str = "txt",
) -> Batch:
    """Verify every item. Unreadable files become ERROR rows; nothing raises per file."""
    rows: list[Row] = []
    skipped: list[dict[str, str]] = []
    names = report_names(items, ext)
    for idx, item in enumerate(items):
        try:
            data = read_bytes(item.path, "bundle")
            where = f"bundle {item.display}"
            bundle = parse_bundle_text(decode_text(data, where), where)
        except InputError as exc:
            rows.append(Row(_clean(item.display), ERROR, error=_clean(str(exc), 500)))
            continue
        if "bundle_version" not in bundle:
            if item.from_dir:
                skipped.append(
                    {
                        "file": _clean(item.display),
                        "reason": "not an evidence bundle (no bundle_version member)",
                    }
                )
            else:
                try:
                    require_bundle_object(bundle, item.display)
                except InputError as exc:
                    rows.append(Row(_clean(item.display), ERROR, error=_clean(str(exc), 500)))
            continue
        try:
            report = verify(bundle)
        except InputError as exc:
            rows.append(Row(_clean(item.display), ERROR, error=_clean(str(exc), 500)))
            continue
        report.source_sha256 = hashlib.sha256(data).hexdigest()
        row = Row(
            _clean(item.display),
            report.verdict,
            key_trust=report.key_trust,
            outcome=report.outcome,
            counts=report.summary(),
            failing=[c.id for c in report.checks if c.status == "FAIL"],
            unverified=[c.id for c in report.checks if c.status == "SKIP" and c.required],
        )
        if out_dir is not None and render is not None:
            target = out_dir / names[idx]
            try:
                make_dir(str(out_dir))  # created only once there is a report to write
                write_text(str(target), render(report))
                row.report = str(target)
            except InputError as exc:
                # The verdict stands; the row records why its report is missing, the run goes
                # on, and the batch exits with 2 at the end.
                row.error = _clean(f"report not written: {exc}", 500)
        rows.append(row)
    return Batch(rows, skipped)


def _ids(ids: list[str], n: int = 5) -> str:
    if not ids:
        return ""
    return ", ".join(ids[:n]) + (f" (+{len(ids) - n})" if len(ids) > n else "")


def render_text(batch: Batch) -> str:
    """Plain-text summary table (terminal-safe)."""
    with_reports = any(r.report or (r.error and r.verdict != ERROR) for r in batch.rows)
    report_col = "  (REPORT)" if with_reports else ""
    lines = [
        f"{'VERDICT':<10}  {'OUTCOME':<11}  {'KEYS':<6}  {'FAIL':>4}  {'SKIP':>4}  "
        f"FILE{report_col}  [CHECKS]"
    ]
    for r in batch.rows:
        notes: list[str] = []
        if r.verdict == ERROR:
            notes.append(f"unreadable: {r.error}")
        elif r.failing:
            notes.append("failed: " + _ids(r.failing))
        elif r.unverified:
            notes.append("not verified: " + _ids(r.unverified))
        if r.verdict != ERROR and r.error:
            notes.append(r.error)
        fail = str(r.counts.get("fail", 0)) if r.counts else "-"
        skip = str(r.counts.get("skip", 0)) if r.counts else "-"
        # the receipts' claim means nothing unless the evidence as a whole is VERIFIED
        outcome = r.outcome if r.verdict == "VERIFIED" and r.outcome else "-"
        line = (
            f"{r.verdict:<10}  {outcome:<11}  {r.key_trust or '-':<6}  {fail:>4}  "
            f"{skip:>4}  {r.file}"
        )
        if r.report:
            line += f"  ({_clean(os.path.basename(r.report))})"
        elif with_reports and r.verdict != ERROR:
            line += "  (no report written)"
        lines.append(f"{line}  [{'; '.join(notes)}]" if notes else line)
    c = batch.counts()
    lines.append("")
    unwritten = (
        f"; {batch.write_errors} report(s) could not be written" if batch.write_errors else ""
    )
    lines.append(
        f"{len(batch.rows)} bundle(s): {c['VERIFIED']} VERIFIED, {c['FAILED']} FAILED, "
        f"{c['INCOMPLETE']} INCOMPLETE, {c[ERROR]} unreadable{unwritten}. Worst: {batch.worst} "
        f"(exit code {batch.exit_code})"
    )
    verified = [r for r in batch.rows if r.verdict == "VERIFIED"]
    declined = sum(1 for r in verified if r.outcome == "declined")
    if declined:
        lines.append(
            f"{declined} VERIFIED bundle(s) with outcome declined: payment declined (per the "
            "payment receipt); the evidence is sound, but the payment did not go through"
        )
    conflicting = sum(1 for r in verified if r.outcome == "conflicting")
    if conflicting:
        lines.append(
            f"{conflicting} VERIFIED bundle(s) with outcome conflicting: the receipts disagree "
            "(both are authentic, one reports success and the other an error); ask the merchant "
            "and the payment processor what happened"
        )
    if batch.skipped:
        shown = ", ".join(s["file"] for s in batch.skipped[:3])
        more = f" and {len(batch.skipped) - 3} more" if len(batch.skipped) > 3 else ""
        lines.append(
            f"skipped {len(batch.skipped)} .json file(s) that are not evidence bundles (no "
            f"bundle_version member): {shown}{more}"
        )
    return "\n".join(lines) + "\n"


def to_dict(batch: Batch) -> dict[str, Any]:
    """JSON summary (fixed by ``schemas/batch-summary.schema.json``)."""
    return {
        "summary_version": SUMMARY_VERSION,
        "tool": {"name": "ap2-evidence", "version": __version__},
        "worst_verdict": batch.worst,
        "exit_code": batch.exit_code,
        "counts": batch.counts(),
        "bundles": [r.to_dict() for r in batch.rows],
        "skipped": batch.skipped,
    }


def render_json(batch: Batch) -> str:
    """JSON summary text (ASCII only)."""
    return json.dumps(to_dict(batch), indent=2, ensure_ascii=True) + "\n"


CSV_COLUMNS = (
    "file",
    "verdict",
    "outcome",
    "exit_code",
    "key_trust",
    "pass",
    "fail",
    "warn",
    "skip",
    "failing_checks",
    "unverified_checks",
    "report",
    "error",
)


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = " ".join(value)
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_csv(batch: Batch) -> str:
    """CSV summary, one row per bundle (spreadsheet formula prefixes neutralised)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in batch.rows:
        d = r.to_dict()
        w.writerow([_csv_cell(d[c]) for c in CSV_COLUMNS])
    return buf.getvalue()
