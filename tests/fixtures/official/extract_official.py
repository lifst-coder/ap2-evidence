"""Extract the six official AP2 v0.2 sample tokens from an upstream clone.

Usage (run from the repository root; the clone is only read, nothing in it is executed):

    python tests/fixtures/official/extract_official.py PATH/TO/AP2-CLONE

Writes the tokens next to this script and rebuilds
examples/official-ap2-v0.2-docs.bundle.json from the two chain tokens.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"

SOURCES = [
    ("open_checkout.txt", "docs/ap2/checkout_mandate.md", 244),
    ("closed_checkout.txt", "docs/ap2/checkout_mandate.md", 328),
    ("checkout_chain.txt", "docs/ap2/checkout_mandate.md", 494),
    ("open_payment.txt", "docs/ap2/payment_mandate.md", 351),
    ("closed_payment.txt", "docs/ap2/payment_mandate.md", 408),
    ("payment_chain.txt", "docs/ap2/payment_mandate.md", 534),
]

TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.~]+$")


def main(clone: Path) -> int:
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    tokens: dict[str, str] = {}
    for name, rel, line in SOURCES:
        lines = (clone / rel).read_text(encoding="utf-8").splitlines()
        token = lines[line - 1].strip()
        if not token.startswith("eyJ") or not TOKEN_RE.match(token):
            print(f"{rel}:{line} does not look like a token", file=sys.stderr)
            return 1
        tokens[name] = token
        (here / name).write_text(token + "\n", encoding="utf-8", newline="\n")
        print(f"{name}: {rel}:{line} ({len(token)} chars)")
    for kind in ("checkout", "payment"):
        joined = tokens[f"open_{kind}.txt"].removesuffix("~") + "~~" + tokens[f"closed_{kind}.txt"]
        same = joined == tokens[f"{kind}_chain.txt"]
        print(f"{kind}: chain line equals open[:-1] + '~~' + closed: {same}")
    bundle = {
        "bundle_version": "ap2-evidence/1",
        "checkout_mandate": tokens["checkout_chain.txt"],
        "payment_mandate": tokens["payment_chain.txt"],
        "expected": {
            "checkout": {"aud": "merchant", "nonce": "b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4"},
            "payment": {"aud": "credential-provider", "nonce": "a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3"},
        },
        "note": (
            "The two mandate chains published in the AP2 v0.2 documentation "
            "(github.com/google-agentic-commerce/AP2 at commit "
            f"{COMMIT}: docs/ap2/checkout_mandate.md:494 and docs/ap2/payment_mandate.md:534; "
            "Apache-2.0). Upstream publishes neither the agent-provider (mandate issuer) key nor "
            "the merchant key, and no receipt, so this bundle can only be INCOMPLETE. The expected "
            "aud/nonce values are the ones shown in the same documents."
        ),
    }
    out = root / "examples" / "official-ap2-v0.2-docs.bundle.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(root)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
