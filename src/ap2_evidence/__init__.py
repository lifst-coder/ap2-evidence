"""ap2-evidence: offline verifier for AP2 v0.2 payment evidence.

Library API::

    from ap2_evidence import verify_bundle, inspect_token
    report = verify_bundle(bundle_dict, trusted_keys=None, skew=300, at=None)
    print(report.verdict)          # VERIFIED / FAILED / INCOMPLETE
    print(report.to_text())        # or to_markdown() / to_json()

    from ap2_evidence.demo import build_demo_bundle
    bundle = build_demo_bundle(tamper="amount")
"""

from ._version import __version__
from .bundle import InputError, KeyStore, load_trusted_keys
from .inspector import inspect_input, inspect_token
from .report import CheckResult, Report
from .verify import verify_bundle

__all__ = [
    "CheckResult",
    "InputError",
    "KeyStore",
    "Report",
    "__version__",
    "inspect_input",
    "inspect_token",
    "load_trusted_keys",
    "verify_bundle",
]
