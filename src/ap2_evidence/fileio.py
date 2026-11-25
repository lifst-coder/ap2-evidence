"""Reading and writing files for the CLI with short, English, code-page-safe error messages.

The operating system's own error text (``OSError.strerror``) is localised on
Windows and arrives in a code page the console may not use, so it shows up as
mojibake ("cannot read bundle x.json: ������"). Every message here is built
from the error class / ``errno`` instead, and says what to check next.
"""

from __future__ import annotations

import codecs
import contextlib
import errno
import os
import sys
from pathlib import Path

from .bundle import MAX_BUNDLE_BYTES, InputError

_WINERROR_INVALID_NAME = 123


def os_error_reason(exc: OSError) -> tuple[str, str]:
    """Return ``(what is wrong, what to check)`` for an ``OSError``, in plain English."""
    code = exc.errno
    if isinstance(exc, FileNotFoundError) or code == errno.ENOENT:
        return "file not found", "check the path and the current directory"
    if isinstance(exc, IsADirectoryError) or code == errno.EISDIR:
        return "it is a directory", "give the path of a file inside it"
    if isinstance(exc, NotADirectoryError) or code == errno.ENOTDIR:
        return "a part of the path is not a directory", "check the path"
    if isinstance(exc, PermissionError) or code in (errno.EACCES, errno.EPERM):
        return (
            "permission denied",
            "check that you may access it and that no other program holds it open",
        )
    if code == errno.ELOOP:
        return "too many levels of symbolic links", "check the links in the path"
    if code == errno.ENAMETOOLONG:
        return "the path is too long", "use a shorter path"
    if code == errno.ENOSPC:
        return "no space left on the device", "free some disk space"
    if code == errno.EINVAL or getattr(exc, "winerror", None) == _WINERROR_INVALID_NAME:
        return "the file name is not valid", "check the path for characters such as * ? < > |"
    label = errno.errorcode.get(code, "") if isinstance(code, int) else ""
    return (
        f"operating-system error {label or type(exc).__name__}",
        "check the path and that the file can be opened",
    )


_WIN_MAX_PATH = 259


def long_path(path: str) -> str:
    r"""On Windows, the ``\\?\`` form of a path longer than MAX_PATH, so it can still be opened."""
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    try:
        full = os.path.abspath(path)
    except (OSError, ValueError):
        return path
    if len(full) <= _WIN_MAX_PATH:
        return path
    if full.startswith("\\\\"):  # UNC share
        return "\\\\?\\UNC\\" + full[2:]
    return "\\\\?\\" + full


def read_bytes(path: str, what: str, limit: int = MAX_BUNDLE_BYTES) -> bytes:
    """Read a regular file (or stdin for ``-``), refusing anything larger than ``limit`` bytes.

    Raises:
        InputError: With a one-line English reason when the file cannot be read.
    """
    if path == "-":
        data = sys.stdin.buffer.read(limit + 1)
        if len(data) > limit:
            raise InputError(f"{what} on stdin is larger than {limit} bytes; split it up")
        return data
    p = Path(long_path(path))
    try:
        if p.is_dir():
            raise InputError(
                f"cannot read {what} {path}: it is a directory; give the path of a file inside it"
            )
        st = p.stat()
        if not p.is_file():
            raise InputError(
                f"cannot read {what} {path}: not a regular file (device, pipe or socket); "
                "give the path of a file"
            )
        if st.st_size > limit:
            raise InputError(
                f"cannot read {what} {path}: larger than {limit} bytes ({st.st_size}); "
                "check that this is the right file"
            )
        with p.open("rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        reason, hint = os_error_reason(exc)
        raise InputError(f"cannot read {what} {path}: {reason}; {hint}") from None
    if len(data) > limit:
        raise InputError(f"cannot read {what} {path}: larger than {limit} bytes")
    return data


def decode_text(data: bytes, what: str) -> str:
    """Decode a text file: UTF-8 (BOM optional), or UTF-16 with a BOM (PowerShell 5.1 ``>``).

    Raises:
        InputError: If the bytes are neither.
    """
    try:
        if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return data.decode("utf-16")
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        binary = b"\x00" in data[:4096]
        kind = "a binary file" if binary else f"not valid UTF-8 (byte {exc.start})"
        raise InputError(
            f"{what} is {kind}, not UTF-8 or UTF-16 (with BOM) text; check that this is the "
            "right file and save it as UTF-8"
        ) from None


def read_text(path: str, what: str, limit: int = MAX_BUNDLE_BYTES) -> str:
    """:func:`read_bytes` followed by :func:`decode_text`."""
    return decode_text(read_bytes(path, what, limit), f"{what} {path}")


def write_text(path: str, text: str, *, overwrite: bool = True) -> None:
    """Write UTF-8 text (no newline translation).

    Raises:
        InputError: With a one-line English reason when the file cannot be written.
    """
    p = Path(long_path(path))
    try:
        if p.is_dir():
            raise InputError(f"cannot write {path}: it is a directory; give a file name")
        if not overwrite and p.exists():
            raise InputError(
                f"cannot write {path}: the file already exists; choose another name or add "
                "--force to replace it"
            )
        with p.open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    except OSError as exc:
        reason, hint = _write_error_reason(path, exc)
        raise InputError(f"cannot write {path}: {reason}; {hint}") from None


def _write_error_reason(path: str, exc: OSError) -> tuple[str, str]:
    """Like :func:`os_error_reason`, for writing: "folder does not exist" only if it is so."""
    if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
        try:
            folder_exists = Path(long_path(os.path.dirname(os.path.abspath(path)))).is_dir()
        except (OSError, ValueError):
            folder_exists = False
        if not folder_exists:
            return "its folder does not exist", "create the folder first"
        return (
            "the file cannot be created there (the path may be too long, or the name may not be "
            "allowed by the file system)",
            "use a shorter folder or file name",
        )
    return os_error_reason(exc)


def make_dir(path: str) -> Path:
    """Create ``path`` (and parents) if needed.

    Raises:
        InputError: If it exists as a file or cannot be created.
    """
    p = Path(long_path(path))
    try:
        if p.exists() and not p.is_dir():
            raise InputError(f"cannot use {path} as output folder: it is a file")
        p.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        reason, hint = os_error_reason(exc)
        raise InputError(f"cannot create output folder {path}: {reason}; {hint}") from None
    return p


CONSOLE_FALLBACKS: dict[str, str] = {
    "•": "*",  # bullet
    "·": ".",  # middle dot
    "…": "...",  # ellipsis
    "–": "-",  # en dash
    "—": "-",  # em dash
    "−": "-",  # minus sign
    "‘": "'",
    "’": "'",
    "‚": "'",
    "“": '"',
    "”": '"',
    "„": '"',
    " ": " ",  # no-break space
    " ": " ",  # narrow no-break space
    " ": " ",  # thin space
}
"""Plain stand-ins for punctuation a narrow console code page cannot encode."""

ERROR_HANDLER = "ap2evidence_console"


def _console_fallback(exc: UnicodeError) -> tuple[str, int]:
    """Codec error handler: transliterate :data:`CONSOLE_FALLBACKS`, else backslash-escape."""
    if not isinstance(exc, UnicodeEncodeError):
        raise exc
    out = []
    for ch in exc.object[exc.start : exc.end]:
        sub = CONSOLE_FALLBACKS.get(ch)
        if sub is None:
            code = ord(ch)
            sub = (
                f"\\x{code:02x}"
                if code <= 0xFF
                else (f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
            )
        out.append(sub)
    return "".join(out), exc.end


codecs.register_error(ERROR_HANDLER, _console_fallback)


def safe_stream_setup() -> None:
    """Never fail on characters the console code page (cp949, ASCII, ...) cannot show.

    Common punctuation is transliterated (bullet to ``*``, curly quotes to straight ones,
    dashes to ``-``); everything else unencodable becomes a backslash escape. Files written
    with ``--out`` are UTF-8 and unaffected.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError, LookupError):
                reconfigure(errors=ERROR_HANDLER)


def same_path(a: str, b: str) -> bool:
    """True if two paths name the same file, also before it exists (case-insensitive on Windows)."""
    if a == "-" or b == "-":
        return False
    try:
        if os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b)):
            return True
    except (OSError, ValueError):
        return False
    return is_same_file(a, b)


def check_distinct(outputs: list[tuple[str, str | None]], inputs: list[tuple[str, str]]) -> None:
    """Refuse when an output path is another output or one of the input files.

    Raises:
        InputError: Naming both flags.
    """
    outs = [(f, p) for f, p in outputs if p]
    for i, (flag, path) in enumerate(outs):
        for flag2, path2 in outs[i + 1 :]:
            if same_path(path, path2):
                raise InputError(
                    f"{flag} and {flag2} name the same file ({path}); give two different files"
                )
        for in_flag, in_path in inputs:
            if same_path(path, in_path):
                raise InputError(
                    f"{flag} {path} is also the input {in_flag}; writing it would destroy the "
                    "input, so choose another output file"
                )


def is_same_file(a: str, b: str) -> bool:
    """True if both paths name the same existing file."""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False
