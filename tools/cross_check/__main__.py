"""Cross-implementation comparison of ap2-evidence against third-party AP2 v0.2 test vectors.

Usage (from the repository root, with ap2-evidence importable)::

    python tools/cross_check sources            # git commands for the pinned clones
    python tools/cross_check run --src DIR      # convert, verify, write fixtures + page
    python tools/cross_check check              # offline: fixtures, manifests, page up to date

Third-party repositories are read as data only: nothing from them is imported or executed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
SRC = HERE.parents[1] / "src"  # compare the verifier of this tree, not an installed copy
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(1, str(SRC))

import check  # noqa: E402
import page  # noqa: E402
import pipeline  # noqa: E402
import sources  # noqa: E402


def _sources() -> int:
    print("# Clone each source at its pinned commit into one directory, then pass it as --src.")
    print("# These commands only fetch data; nothing from the clones is ever executed.")
    for repo in sources.REPOS.values():
        print(f"\n# {repo.name} ({repo.licence})")
        for cmd in sources.commands(repo):
            print(cmd)
    return 0


def _run(src: Path) -> int:
    doc = pipeline.write_all(src)
    for title, key in (("without context", "result"), ("with context", "result_with_context")):
        print(f"\n{title}: vectors / agree / agree (incomplete input) / stricter / disagree")
        for group, c in page.counts(doc, key).items():
            vals = " / ".join(str(v) for v in c.values())
            print(f"  {group:22s} {vals}")
    for line in doc.get("excluded") or []:
        print("excluded:", line)
    left = page.unexplained(doc)
    if left:
        print("\nrows without a reason code (add a rule in reasons.py):")
        for item in left:
            print("  " + item)
        return 1
    return 0


def _check() -> int:
    problems = check.check_all()
    for p in problems:
        print(p)
    if problems:
        print("\n" + check.HOW)
        return 1
    print("cross_check: fixtures, manifests, results.json and the page are consistent")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    ap = argparse.ArgumentParser(prog="cross_check", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sources", help="print git commands for the pinned third-party clones")
    p_run = sub.add_parser("run", help="convert, verify and write fixtures, results and page")
    p_run.add_argument("--src", type=Path, required=True, help="directory holding the clones")
    sub.add_parser("check", help="offline consistency check (also run by the test-suite)")
    args = ap.parse_args(argv)
    if args.cmd == "sources":
        return _sources()
    if args.cmd == "run":
        return _run(args.src)
    return _check()


if __name__ == "__main__":
    sys.exit(main())
