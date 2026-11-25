"""Write the check catalogue (``docs/checks.md``) to stdout or a file.

Usage: ``python -m ap2_evidence.checksdoc [OUTPUT.md]``. Written as UTF-8 with
LF line endings, so redirecting in PowerShell is not needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .checks import checks_markdown


def main(argv: list[str]) -> int:
    """Write the catalogue to ``argv[0]`` if given, else to stdout."""
    text = checks_markdown()
    if argv:
        Path(argv[0]).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
