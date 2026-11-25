"""Command-line interface: ``ap2-evidence demo | verify | pack | inspect | explain``.

Exit codes: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE, 2 usage error or unreadable input.
Bad input never produces a traceback: it ends as FAIL checks in the report or
as a one-line error on stderr with exit code 2.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import batch as batchmod
from . import cliopts, strictjson
from . import explain as explainmod
from ._version import __version__
from .bundle import (
    ARTIFACTS,
    BUNDLE_VERSION,
    CHECK_FILE,
    MAX_BUNDLE_BYTES,
    ROLES,
    InputError,
    KeyStore,
    load_trusted_keys,
    loose_bundle,
    parse_bundle_text,
    require_bundle_object,
)
from .demo import TAMPER_MODES, build_demo_bundle
from .fileio import check_distinct, read_bytes, safe_stream_setup, write_text
from .fileio import decode_text as _decode_text
from .importer import SampleImport, import_sample_db
from .inspector import inspect_input, render_text
from .jose import JoseError, parse_compact
from .keys import ROLE_FLAGS, RoleKeys, collect_role_keys
from .report import Report
from .sdjwt import SdJwtError, parse_chain
from .verify import verify_bundle

EXIT_USAGE = 2
FORMATS = ("text", "md", "json", "issue", "html")
REPORT_EXT = {"text": "txt", "md": "md", "json": "json", "issue": "md", "html": "html"}
_SHELL_SAFE = re.compile(r"[A-Za-z0-9_./:\\=+-]+")

_LOOSE = ("checkout_mandate", "payment_mandate", "checkout_receipt", "payment_receipt")
_ROLE_DEST = {
    "mandate_issuer": "issuer_key",
    "merchant": "merchant_key",
    "payment_processor": "processor_key",
}


def _setup_streams() -> None:
    """Never fail on characters the console code page (e.g. cp949) cannot show."""
    safe_stream_setup()


def _read_bytes(path: str, what: str) -> bytes:
    return read_bytes(path, what, MAX_BUNDLE_BYTES)


def decode_text(data: bytes, what: str) -> str:
    """Decode a text file: UTF-8 (BOM optional), or UTF-16 with a BOM (PowerShell 5.1 ``>``).

    Raises:
        InputError: If the bytes are neither.
    """
    return _decode_text(data, what)


def _read_text(path: str, what: str) -> str:
    return decode_text(_read_bytes(path, what), f"{what} {path}")


def _emit(text: str, out: str | None, verdict: str | None = None) -> None:
    if out is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    write_text(out, text)
    print(f"wrote {out}" + (f" (VERDICT: {verdict})" if verdict else ""), file=sys.stderr)


def _render(report: Report, fmt: str, command: str) -> str:
    if fmt == "json":
        return report.to_json()
    if fmt == "md":
        return report.to_markdown()
    if fmt == "issue":
        return report.to_issue(command)
    if fmt == "html":
        _require_html()
        html: str = report.to_html()  # type: ignore[attr-defined,unused-ignore]
        return html
    return report.to_text()


def _require_html() -> None:
    if not hasattr(Report, "to_html"):
        raise InputError(
            "--format html is not available in this installation (Report.to_html is "
            "missing); use --format md or text"
        )


def _parse_at(value: str | None) -> int | None:
    return cliopts.parse_at(value)


def _role_files(args: argparse.Namespace) -> dict[str, list[str]]:
    return {role: list(getattr(args, dest, None) or []) for role, dest in _ROLE_DEST.items()}


def _note(text: str) -> None:
    print(f"ap2-evidence: note: {text}", file=sys.stderr)


def _trusted(args: argparse.Namespace) -> KeyStore | None:
    store: KeyStore | None = None
    if args.trusted_keys is not None:
        where = f"trusted keys file {args.trusted_keys}"
        data = _read_bytes(args.trusted_keys, "trusted keys file")
        store = load_trusted_keys(decode_text(data, where), where)
    role_keys = collect_role_keys(_role_files(args))
    for note in role_keys.notes():
        _note(note)
    return role_keys.to_keystore(store)


def _expected(args: argparse.Namespace) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for kind in ("checkout", "payment"):
        for claim in ("aud", "nonce"):
            value = getattr(args, f"expect_{kind}_{claim}", None)
            if value is not None:
                out.setdefault(kind, {})[claim] = value
    return out


def _command_summary(args: argparse.Namespace) -> str:
    parts = [args.command]
    if args.command == "demo" and args.tamper:
        parts += ["--tamper", args.tamper]
    if args.command == "verify":
        parts.append("BUNDLE" if args.bundle else "(loose files)")
        for name in ("checkout_mandate", "payment_mandate", "checkout_receipt", "payment_receipt"):
            if getattr(args, name, None):
                parts.append(f"--{name.replace('_', '-')} FILE")
        if args.trusted_keys:
            parts.append("--trusted-keys FILE")
        for role, dest in _ROLE_DEST.items():
            if getattr(args, dest, None):
                parts.append(f"{ROLE_FLAGS[role]} FILE")
        if args.skew != 300:
            parts += ["--skew", str(args.skew)]
        if args.at:
            parts += ["--at", args.at]
        for kind in ("checkout", "payment"):
            for claim in ("aud", "nonce"):
                if getattr(args, f"expect_{kind}_{claim}", None) is not None:
                    parts.append(f"--expect-{kind}-{claim} VALUE")
        if getattr(args, "require_pinned", False):
            parts.append("--require-pinned")
        for name, shown in (
            ("expect_agent_key", "--expect-agent-key FILE"),
            ("expect_checkout_id", "--expect-checkout-id ID"),
            ("expect_merchant_id", "--expect-merchant-id ID"),
            ("expect_total", "--expect-total AMOUNT"),
            ("prior_total", "--prior-total AMOUNT"),
        ):
            if getattr(args, name, None):
                parts.append(shown)
        if getattr(args, "prior_uses", None) is not None:
            parts += ["--prior-uses", str(args.prior_uses)]
        for ctype in getattr(args, "require_constraint", None) or []:
            parts += ["--require-constraint", ctype]
    parts += ["--format", args.format]
    return " ".join(parts)


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the ``demo`` command."""
    bundle = build_demo_bundle(args.tamper)
    scenario = TAMPER_MODES[args.tamper] if args.tamper else "a valid transaction"
    print(f"ap2-evidence demo: {scenario}", file=sys.stderr)
    if args.save_bundle:
        _emit(json.dumps(bundle, indent=2, ensure_ascii=True) + "\n", args.save_bundle)
    report = verify_bundle(bundle)
    _emit(_render(report, args.format, _command_summary(args)), args.out, report.verdict)
    return report.exit_code


def read_loose_files(args: argparse.Namespace) -> dict[str, tuple[str, str]]:
    """Read the ``--checkout-mandate`` ... ``--payment-receipt`` files given on the command line.

    Shared by ``verify`` and ``pack``. Returns ``{member: (path, text)}`` with the text as
    decoded (UTF-8 or UTF-16 with BOM), not yet stripped.
    """
    out: dict[str, tuple[str, str]] = {}
    for name in _LOOSE:
        path = getattr(args, name, None)
        if path is not None:
            out[name] = (path, _read_text(path, name.replace("_", " ")))
    return out


def _input_files(args: argparse.Namespace) -> list[tuple[str, str]]:
    """Every input file named on the command line, with its flag (for overwrite checks)."""
    out: list[tuple[str, str]] = []
    for name in _LOOSE:
        if getattr(args, name, None):
            out.append((f"--{name.replace('_', '-')}", getattr(args, name)))
    if getattr(args, "trusted_keys", None):
        out.append(("--trusted-keys", args.trusted_keys))
    for role, dest in _ROLE_DEST.items():
        out += [(ROLE_FLAGS[role], f) for f in getattr(args, dest, None) or []]
    if getattr(args, "expect_agent_key", None):
        out.append(("--expect-agent-key", args.expect_agent_key))
    for b in getattr(args, "bundle", None) or []:
        if b != "-" and not Path(b).is_dir():
            out.append(("BUNDLE", b))
    return out


def _is_batch(args: argparse.Namespace) -> bool:
    paths: list[str] = args.bundle
    if len(paths) > 1 or args.out_dir or args.summary_csv:
        return True
    return bool(paths) and paths[0] != "-" and Path(paths[0]).is_dir()


def cmd_verify(args: argparse.Namespace) -> int:
    """Run the ``verify`` command (one bundle, loose token files, or a batch)."""
    loose_given = [n for n in _LOOSE if getattr(args, n) is not None]
    if args.bundle and loose_given:
        raise InputError(
            "give either a bundle file or --checkout-mandate/--payment-mandate files, not both"
        )
    if not args.bundle and not loose_given:
        raise InputError(
            "nothing to verify: give a bundle file (or '-' for stdin), a folder of bundles, or "
            "loose token files; 'ap2-evidence pack' builds a bundle from loose files"
        )
    if args.skew < 0:
        raise InputError("--skew must not be negative")
    if args.recursive and not args.bundle:
        raise InputError("--recursive needs a folder of bundles")
    check_distinct([("--out", args.out), ("--summary-csv", args.summary_csv)], _input_files(args))
    at = _parse_at(args.at)
    if args.bundle and _is_batch(args):
        return _verify_batch(args, at)
    if args.recursive:
        raise InputError("--recursive needs a folder of bundles, not a single file")
    opts = cliopts.verifier_options(args)
    trusted = _trusted(args)
    bundle: Any
    source: str | None = None
    if args.bundle:
        path = args.bundle[0]
        data = _read_bytes(path, "bundle")
        source = hashlib.sha256(data).hexdigest()
        where = "bundle on stdin" if path == "-" else f"bundle {path}"
        bundle = parse_bundle_text(decode_text(data, where), where)
        require_bundle_object(bundle, "stdin" if path == "-" else path)
    else:
        loose = read_loose_files(args)
        bundle = loose_bundle({n: text for n, (_p, text) in loose.items()})
    report = verify_bundle(bundle, trusted_keys=trusted, skew=args.skew, at=at, **opts)
    report.source_sha256 = source
    _emit(_render(report, args.format, _command_summary(args)), args.out, report.verdict)
    return report.exit_code


def _verify_batch(args: argparse.Namespace, at: int | None) -> int:
    if "-" in args.bundle:
        raise InputError("'-' (stdin) can only be used for a single bundle, not in a batch")
    expected = _expected(args)
    if any("nonce" in v for v in expected.values()):
        raise InputError(
            "--expect-checkout-nonce/--expect-payment-nonce cannot be used in a batch run: a "
            "nonce belongs to one transaction; put it into each bundle's expected member"
        )
    for name in cliopts.BATCH_ONLY_ONE:
        if getattr(args, name, None) is not None:
            raise InputError(
                f"--{name.replace('_', '-')} describes one transaction and cannot be used in a "
                "batch run; verify that bundle on its own"
            )
    opts = cliopts.verifier_options(args)
    if args.format == "html":
        _require_html()
    trusted = _trusted(args)
    missing = [b for b in args.bundle if not Path(b).exists()]
    if missing and len(missing) == len(args.bundle):
        shown = ", ".join(missing[:5]) + (
            f" and {len(missing) - 5} more" if len(missing) > 5 else ""
        )
        raise InputError(
            f"nothing to verify: {shown} not found; check the path and the current directory"
        )
    if args.out_dir and Path(args.out_dir).exists() and not Path(args.out_dir).is_dir():
        raise InputError(f"cannot use {args.out_dir} as output folder: it is a file")
    out_dir = Path(args.out_dir) if args.out_dir else None
    items = batchmod.collect(args.bundle, args.recursive, args.out_dir)
    if not items:
        raise InputError(
            f"no .json files found in {', '.join(args.bundle)}"
            + ("" if args.recursive else "; add --recursive to look into subfolders")
        )
    if out_dir is not None and not args.force:
        clash = batchmod.existing_reports(items, out_dir, REPORT_EXT[args.format])
        if clash:
            more = f" and {len(clash) - 1} more" if len(clash) > 1 else ""
            raise InputError(
                f"--out-dir {args.out_dir} already holds {clash[0].name}{more}; use an empty "
                "folder, or add --force to replace existing reports"
            )
    command = _command_summary(args)

    def run_one(bundle: Any) -> Report:
        return verify_bundle(bundle, trusted_keys=trusted, skew=args.skew, at=at, **opts)

    result = batchmod.run(
        items,
        run_one,
        lambda r: _render(r, args.format, command),
        out_dir,
        REPORT_EXT[args.format],
    )
    if not result.rows:
        raise InputError(
            "no evidence bundles found (every .json file lacked bundle_version): "
            + "; ".join(s["file"] for s in result.skipped[:5])
        )
    if not result.verified_rows:
        first = result.rows[0].error or ""
        more = f" (and {len(result.rows) - 1} more unreadable)" if len(result.rows) > 1 else ""
        raise InputError(f"no evidence bundle could be read: {first}{more}")
    summary = (
        batchmod.render_json(result) if args.format == "json" else batchmod.render_text(result)
    )
    if args.summary_csv:
        write_text(args.summary_csv, batchmod.render_csv(result))
        print(f"wrote {args.summary_csv}", file=sys.stderr)
    if out_dir is not None:
        print(
            f"wrote {sum(1 for r in result.rows if r.report)} report(s) to {out_dir}"
            + (
                f"; {result.write_errors} could not be written (see the summary)"
                if result.write_errors
                else ""
            ),
            file=sys.stderr,
        )
    _emit(summary, args.out, result.worst)
    return result.exit_code


# ---------------------------------------------------------------------------------------- pack


def _shell_arg(value: str) -> str:
    if _SHELL_SAFE.fullmatch(value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


UNPARSED = "unparsed"
"""Marker ``pack``'s summary shows for an input that does not parse as the token it should be."""


def _check_mandate(name: str, path: str, text: str) -> tuple[str, list[str]]:
    """Return a description of a mandate chain and warnings (it is packed unchanged)."""
    if text.startswith("{"):
        raise InputError(
            f"{name.replace('_', ' ')} file {path} holds JSON, not an SD-JWT mandate chain; if "
            "it is an evidence bundle, run 'ap2-evidence verify' on it directly"
        )
    try:
        segs = parse_chain(text)
    except SdJwtError as exc:
        return UNPARSED, [
            f"{name} file {path} does not look like an SD-JWT mandate chain ({exc.where}: {exc}); "
            "it was packed as it is, and 'ap2-evidence verify' will report it"
        ]
    return f"{len(segs)} segment(s)", []


def _check_receipt(name: str, path: str, text: str) -> tuple[Any, str, list[str]]:
    """Return what to store for a receipt (the token text, or an unsigned receipt's object)."""
    kind = "checkout" if name.startswith("checkout") else "payment"
    signer = "merchant" if kind == "checkout" else "payment processor"
    value: Any = None
    if text.startswith(("{", '"')):
        try:
            value = strictjson.loads(text, max_bytes=MAX_BUNDLE_BYTES)
            if isinstance(value, str) and value.lstrip().startswith("{"):
                value = strictjson.loads(value, max_bytes=MAX_BUNDLE_BYTES)
        except strictjson.StrictJsonError:
            pass
    if isinstance(value, dict):
        unsigned = (
            f"this flow produced no signed {kind} receipt: {path} holds a plain JSON object, "
            f"not a JWT signed by the {signer}. It was stored as an object so the report can "
            f"show it, but an unsigned receipt proves nothing: the {kind} receipt checks will "
            "be SKIP (unsigned_receipt) and the verdict INCOMPLETE"
        )
        return value, "unsigned JSON object, proves nothing", [unsigned]
    if text.startswith('"'):
        raise InputError(
            f"{name.replace('_', ' ')} file {path} holds a JSON-quoted string; save the bare "
            "token (header.payload.signature) without the quotes"
        )
    if "~" in text:
        swapped = (
            f"{name} file {path} contains '~' like an SD-JWT; receipts are plain JWTs, so "
            "check that the files are not swapped. It was packed as it is, and "
            "'ap2-evidence verify' will report it"
        )
        return text, UNPARSED, [swapped]
    try:
        parse_compact(text)
    except JoseError as exc:
        return (
            text,
            UNPARSED,
            [
                f"{name} file {path} does not look like a signed receipt, which is a JWS "
                f"({exc}); it was packed as it is, and 'ap2-evidence verify' will report it"
            ],
        )
    return text, "JWT", []


def _pack_keys(args: argparse.Namespace, imp: SampleImport | None) -> RoleKeys:
    keys = collect_role_keys(_role_files(args))
    if args.trusted_keys is not None:
        text = _read_text(args.trusted_keys, "trusted keys file")
        # validates and refuses private keys
        load_trusted_keys(text, f"trusted keys file {args.trusted_keys}")
        value = strictjson.loads(text, max_bytes=MAX_BUNDLE_BYTES)
        keys.add_role_map(value, f"--trusted-keys {Path(args.trusted_keys).name}")
    if imp is not None:
        for role, items in imp.keys.keys.items():
            keys.add(role, items)
    return keys


def cmd_pack(args: argparse.Namespace) -> int:
    """Run the ``pack`` command: assemble a bundle file from loose pieces."""
    slots: dict[str, Any] = {}
    described: dict[str, str] = {}
    warnings: list[str] = []  # about the inputs: printed once each on stderr
    notes: list[str] = []
    imp: SampleImport | None = None
    check_distinct([("--out", args.out), ("--keys-out", args.keys_out)], _input_files(args))
    if args.from_ap2_sample_db:
        if args.checkout_mandate or args.payment_mandate:
            raise InputError(
                "--from-ap2-sample-db takes the mandate chains from the sample directory; do not "
                "also give --checkout-mandate/--payment-mandate (use --checkout/--payment ID to "
                "choose chains there)"
            )
        imp = import_sample_db(args.from_ap2_sample_db, args.checkout, args.payment)
        for chain, member in ((imp.checkout, "checkout_mandate"), (imp.payment, "payment_mandate")):
            if chain is not None:
                slots[member] = chain.text
                _desc, warn = _check_mandate(member, chain.path.name, chain.text)
                described[member] = f"{chain.path.name} ({_desc})"
                warnings += warn
        warnings += imp.warnings
        notes += imp.notes
    elif args.checkout or args.payment:
        raise InputError("--checkout/--payment choose chains inside --from-ap2-sample-db DIR")
    for name, (path, raw) in read_loose_files(args).items():
        text = raw.strip()
        if not text:
            shown = "on stdin" if path == "-" else f"file {path}"
            raise InputError(f"{name.replace('_', ' ')} {shown} is empty; {CHECK_FILE}")
        stored: Any = text
        if name.endswith("_mandate"):
            desc, warn = _check_mandate(name, path, text)
        else:
            stored, desc, warn = _check_receipt(name, path, text)
        warnings += warn
        slots[name] = stored
        described[name] = f"{path} ({desc})" if desc else path
    if not slots:
        raise InputError(
            "nothing to pack: give --checkout-mandate/--payment-mandate (and receipt) files, or "
            "--from-ap2-sample-db DIR"
        )
    keys = _pack_keys(args, imp)
    notes += keys.notes()
    if keys.count() and not (args.keys_out or args.embed_keys):
        raise InputError(
            f"{keys.count()} public key(s) were given or found but would be dropped: add "
            "--keys-out FILE to write them to a trusted-keys file (recommended), or "
            "--embed-keys to put them into the bundle as self-asserted keys"
        )

    expected: dict[str, dict[str, str]] = {}
    sources: list[str] = []
    if imp is not None:
        expected = {k: dict(v) for k, v in imp.expected.items()}
        sources += imp.expected_sources
    for kind, vals in _expected(args).items():
        for claim, value in vals.items():
            expected.setdefault(kind, {})[claim] = value
            sources.append(f"expected.{kind}.{claim}: from --expect-{kind}-{claim}")
    bundle: dict[str, Any] = {"bundle_version": BUNDLE_VERSION}
    for member in ARTIFACTS:
        if member in slots:
            bundle[member] = slots[member]
    if args.embed_keys and keys.count():
        bundle["keys"] = keys.role_map()
    if expected:
        bundle["expected"] = expected
    note = args.note
    if imp is not None:
        auto = (
            f"imported by ap2-evidence pack from an AP2 sample temp-db "
            f"({imp.checkout.id if imp.checkout else 'no checkout'}, "
            f"{imp.payment.id if imp.payment else 'no payment'}); expected values come from the "
            "sample itself"
        )
        note = f"{note} | {auto}" if note else auto
    if note is not None:
        bundle["note"] = note
    write_text(
        args.out, json.dumps(bundle, indent=2, ensure_ascii=True) + "\n", overwrite=args.force
    )
    if args.keys_out and keys.count():
        write_text(
            args.keys_out,
            json.dumps(keys.role_map(), indent=2, ensure_ascii=True) + "\n",
            overwrite=args.force,
        )
    for w in warnings:
        print(f"ap2-evidence: warning: {w}", file=sys.stderr)
    if args.embed_keys and keys.count():
        print(
            f"ap2-evidence: warning: --embed-keys put {keys.count()} public key(s) into the "
            "bundle. Keys inside a bundle are self-asserted: whoever passes the bundle on can "
            "replace them, so a verifier should pin keys from a source they trust with "
            "--trusted-keys.",
            file=sys.stderr,
        )
    sys.stdout.write(_pack_summary(args, described, keys, expected, sources, notes))
    return 0


def _pack_summary(
    args: argparse.Namespace,
    described: dict[str, str],
    keys: RoleKeys,
    expected: dict[str, dict[str, str]],
    sources: list[str],
    notes: list[str],
) -> str:
    lines = [f"wrote {args.out} (bundle_version {BUNDLE_VERSION})"]
    lines.append("included:")
    for member in ARTIFACTS:
        if member in described:
            lines.append(f"  {member:<17} {described[member]}")
    missing = [m for m in ARTIFACTS if m not in described]
    if missing:
        lines.append("missing (the verdict will be INCOMPLETE until they are added):")
        lines += [f"  {m}" for m in missing]
    if not keys.count():
        where = "none given"
    elif args.embed_keys:
        where = "embedded in the bundle (self-asserted)"
        if args.keys_out:
            where += f" and written to {args.keys_out}"
    else:
        where = f"written to {args.keys_out}, not copied into the bundle; pin them at verify time"
    lines.append(f"public keys ({where}):")
    for role in ROLES:
        count = len(keys.keys[role])
        lines.append(f"  {role:<17} {count or 'none: signature checks for this role will be SKIP'}")
    if expected:
        lines.append("expected values (stored in the bundle, so self-asserted):")
        for kind, vals in expected.items():
            for claim, value in vals.items():
                lines.append(f"  {kind + '.' + claim:<17} {value}")
        lines += [f"  source: {s}" for s in sources]
    else:
        lines.append("expected values: none (aud/nonce checks will be SKIP and not required)")
    for n in notes:
        lines.append(f"note: {n}")
    cmd = ["ap2-evidence", "verify", _shell_arg(args.out)]
    if args.keys_out and keys.count():
        cmd += ["--trusted-keys", _shell_arg(args.keys_out)]
    lines.append("next:")
    lines.append("  " + " ".join(cmd))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------- inspect, explain


def cmd_inspect(args: argparse.Namespace) -> int:
    """Run the ``inspect`` command."""
    text = _read_text(args.input, "input")
    if not text.strip():
        where = "input on stdin" if args.input == "-" else f"input {args.input}"
        raise InputError(f"{where} is empty; {CHECK_FILE}")
    info = inspect_input(text)
    if info.get("kind") == "unreadable":
        raise InputError(f"cannot decode input: {info.get('error')}")
    if args.format == "json":
        out = json.dumps(info, indent=2, ensure_ascii=True) + "\n"
    else:
        out = render_text(info)
    _emit(out, args.out)
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    """Run the ``explain`` command."""
    if args.list:
        if args.check_id:
            raise InputError("give either a check ID or --list, not both")
        sys.stdout.write(explainmod.render_list())
        return 0
    if not args.check_id:
        raise InputError("give a check ID such as PM32, or --list to see all checks")
    sys.stdout.write(explainmod.render(explainmod.find(args.check_id)))
    return 0


# ---------------------------------------------------------------------------------------- parser


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # one line, exit 2
        self.exit(EXIT_USAGE, f"ap2-evidence: error: {message} (see --help)\n")


_LOOSE_HELP = (
    "text file holding the {} (UTF-8 or UTF-16 with BOM; surrounding whitespace is ignored)"
)


def _add_loose(p: argparse.ArgumentParser, suffix: str) -> None:
    for flag, what in (
        ("--checkout-mandate", "checkout mandate chain (open~~closed SD-JWT)"),
        ("--payment-mandate", "payment mandate chain (open~~closed SD-JWT)"),
        ("--checkout-receipt", "checkout receipt JWT signed by the merchant"),
        ("--payment-receipt", "payment receipt JWT signed by the payment processor"),
    ):
        p.add_argument(
            flag,
            dest=flag[2:].replace("-", "_"),
            metavar="FILE",
            help=_LOOSE_HELP.format(what) + suffix,
        )


def _add_keys(
    p: argparse.ArgumentParser | argparse._ArgumentGroup,
    effect: str = "they take precedence over keys in the bundle",
) -> None:
    p.add_argument(
        "--trusted-keys",
        metavar="FILE",
        help='keys you trust, as {"mandate_issuer": [JWK...], "merchant": [...], '
        f'"payment_processor": [...]}}; {effect}',
    )
    for role, flag in ROLE_FLAGS.items():
        p.add_argument(
            flag,
            dest=_ROLE_DEST[role],
            action="append",
            metavar="FILE",
            help=f"public key of the {role.replace('_', ' ')} (repeatable): a JWK, a JWKS, a PEM "
            "public key or a PEM X.509 certificate (its chain is not validated); EC P-256 only",
        )


def _add_expect(p: argparse.ArgumentParser, where: str) -> None:
    for kind in ("checkout", "payment"):
        for claim in ("aud", "nonce"):
            p.add_argument(
                f"--expect-{kind}-{claim}",
                dest=f"expect_{kind}_{claim}",
                metavar="VALUE",
                help=f"the {claim} the closed {kind} mandate must carry ({where})",
            )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = _Parser(
        prog="ap2-evidence",
        description="Offline verifier for AP2 v0.2 payment evidence (mandates and receipts).",
        epilog="Exit codes: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE, 2 usage error or unreadable input.",
    )
    parser.add_argument("--version", action="version", version=f"ap2-evidence {__version__}")
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)

    fmt_help = (
        "output format (default: text); 'issue' is a short Markdown block to paste into a "
        "GitHub issue; 'html' is a standalone page"
    )
    demo = sub.add_parser(
        "demo",
        help="build a demo transaction with fresh keys and verify it",
        description="Build a complete AP2 v0.2 demo transaction (checkout and payment mandates "
        "and\n"
        "both receipts, in the upstream wire format) with freshly generated keys, and verify it.\n"
        "With --tamper, one dispute scenario is applied first, so you can see how the report\n"
        "names the broken link.",
        epilog="--tamper scenarios:\n"
        "  amount      the agent validly signs USD 250.00 when the user allowed at most USD "
        "200.00 and\n"
        "              the checkout total is USD 199.00; every signature is valid\n"
        "  receipt     a validly signed receipt that belongs to a different mandate\n"
        "  disclosure  an allowed-merchant entry is swapped after the mandate was issued\n"
        "  key         the closed payment mandate is signed by a key other than the one the "
        "user bound\n\n"
        "Exit codes: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE, 2 usage error.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    demo.add_argument(
        "--tamper",
        choices=sorted(TAMPER_MODES),
        help="apply a dispute scenario (see below)",
    )
    demo.add_argument("--format", choices=FORMATS, default="text", help=fmt_help)
    demo.add_argument(
        "--out", metavar="FILE", help="write the report to FILE (UTF-8; replaced if it exists)"
    )
    demo.add_argument(
        "--save-bundle",
        metavar="FILE",
        help="also write the demo bundle to FILE (replaced if it exists)",
    )
    demo.set_defaults(func=cmd_demo)

    ver = sub.add_parser(
        "verify",
        help="verify an evidence bundle, loose token files, or many bundles",
        description="Verify one evidence bundle, loose token files, or a batch of bundles. "
        "Several BUNDLE paths or a folder start a batch run: one summary line per bundle and "
        "the worst exit code over all of them (2 unreadable > 1 FAILED > 3 INCOMPLETE > 0).",
        epilog="Exit codes: 0 VERIFIED, 1 FAILED, 3 INCOMPLETE, 2 usage error or unreadable input.",
    )
    ver.add_argument(
        "bundle",
        nargs="*",
        metavar="BUNDLE",
        help="bundle JSON file, '-' for stdin, or a folder (all *.json bundles in it)",
    )
    _add_loose(ver, "; use instead of a bundle")
    _add_keys(ver)
    _add_expect(ver, "takes precedence over expected in the bundle")
    ver.add_argument(
        "--skew", type=int, default=300, metavar="SECONDS", help="clock skew (default 300)"
    )
    ver.add_argument(
        "--at",
        metavar="UNIX_TS|ISO8601",
        help="also check that the mandates were valid at this time: Unix seconds, an RFC 3339 "
        "date-time with time zone (2026-04-28T02:30:00Z) or a date (2026-04-28, midnight UTC)",
    )
    ver.add_argument("--format", choices=FORMATS, default="text", help=fmt_help)
    ver.add_argument(
        "--out",
        metavar="FILE",
        help="write the report (in a batch: the summary) to FILE (UTF-8; replaced if it exists)",
    )
    cliopts.add_arguments(ver)
    batch = ver.add_argument_group("batch runs")
    batch.add_argument(
        "--recursive", action="store_true", help="also look into subfolders of a folder"
    )
    batch.add_argument(
        "--out-dir",
        metavar="DIR",
        help="write one report per bundle into DIR, in --format (text, md, json, issue, html); "
        "created when there is a report to write; existing reports are not replaced unless "
        "--force is given",
    )
    batch.add_argument(
        "--summary-csv",
        metavar="FILE",
        help="also write the summary table as CSV to FILE (replaced if it exists)",
    )
    batch.add_argument("--force", action="store_true", help="replace existing reports in --out-dir")
    ver.set_defaults(func=cmd_verify)

    pack = sub.add_parser(
        "pack",
        help="assemble a bundle file from token files, key files or an AP2 sample temp-db",
        description="Assemble an evidence bundle from loose pieces, so you never write bundle "
        "JSON by hand. Tokens are copied byte for byte (only surrounding whitespace is removed). "
        "Public keys are NOT put into the bundle unless you ask: they go to a separate "
        "trusted-keys file (--keys-out) that you pin at verify time.",
        epilog="Example: ap2-evidence pack --checkout-mandate chk.txt --payment-mandate pay.txt "
        "--issuer-key issuer.pem --merchant-key merchant.pem --keys-out keys.json --out "
        "bundle.json",
    )
    pack.add_argument(
        "--out",
        required=True,
        metavar="FILE",
        help="bundle file to write (an existing file is not replaced unless --force is given)",
    )
    pack.add_argument(
        "--force", action="store_true", help="replace --out / --keys-out if they exist"
    )
    _add_loose(pack, "")
    src = pack.add_argument_group("AP2 sample import")
    src.add_argument(
        "--from-ap2-sample-db",
        metavar="DIR",
        help="take the mandate chains, public keys and payment nonce from the directory the "
        "official AP2 Python samples write (TEMP_DB_DIR, default .temp-db); receipts are not "
        "stored there, give them with the receipt flags",
    )
    src.add_argument(
        "--checkout", metavar="ID", help="with --from-ap2-sample-db: the chk_... chain to use"
    )
    src.add_argument(
        "--payment", metavar="ID", help="with --from-ap2-sample-db: the pay_... chain to use"
    )
    keys = pack.add_argument_group("keys")
    _add_keys(keys, "copied to --keys-out (or embedded with --embed-keys)")
    keys.add_argument(
        "--keys-out",
        metavar="FILE",
        help="write the public keys to FILE as a trusted-keys file for verify --trusted-keys "
        "(an existing file is not replaced unless --force is given)",
    )
    keys.add_argument(
        "--embed-keys",
        action="store_true",
        help="also put the public keys into the bundle (they are then self-asserted: whoever "
        "holds the bundle can replace them)",
    )
    _add_expect(pack, "stored in the bundle's expected member")
    pack.add_argument("--note", metavar="TEXT", help="free text stored in the bundle")
    pack.set_defaults(func=cmd_pack)

    ins = sub.add_parser(
        "inspect", help="decode a token, chain, receipt or bundle without judging it"
    )
    ins.add_argument("input", metavar="TOKEN_OR_BUNDLE_FILE", help="file, or '-' for stdin")
    ins.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    ins.add_argument("--out", metavar="FILE", help="write the output to FILE (UTF-8)")
    ins.set_defaults(func=cmd_inspect)

    exp = sub.add_parser(
        "explain",
        help="explain what a check ID (such as PM32) verifies",
        description="Explain one check: what it verifies, why it matters, whether it is "
        "required, the worst status it can produce, and the upstream spec reference.",
    )
    exp.add_argument("check_id", nargs="?", metavar="CHECK_ID", help="for example PM32 or cr04")
    exp.add_argument("--list", action="store_true", help="list all checks")
    exp.set_defaults(func=cmd_explain)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``ap2-evidence`` command; returns the exit code."""
    _setup_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        code: int = args.func(args)
    except InputError as exc:
        print(f"ap2-evidence: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except MemoryError:  # pragma: no cover
        print("ap2-evidence: error: out of memory; the input is too large", file=sys.stderr)
        return EXIT_USAGE
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
