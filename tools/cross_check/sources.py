"""The third-party repositories compared, pinned by commit, and how to obtain them.

Nothing here clones or downloads anything: ``commands()`` only prints git commands for the
person running the comparison. The clones are read as data; no file in them is executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"


@dataclass(frozen=True)
class Repo:
    """A pinned third-party repository."""

    key: str
    name: str
    url: str
    commit: str
    licence: str
    directory: str
    licence_files: tuple[str, ...] = ("LICENSE",)
    fetch_ref: str = ""

    def short(self) -> str:
        """Seven-character commit."""
        return self.commit[:7]


REPOS: dict[str, Repo] = {
    r.key: r
    for r in (
        Repo(
            "goodmeta",
            "goodmeta/ap2-conformance",
            "https://github.com/goodmeta/ap2-conformance",
            "41dff653dea4a3025ca6e1d5339121cd8a1623a5",
            "Apache-2.0 (with NOTICE)",
            "goodmeta_ap2-conformance",
            ("LICENSE", "NOTICE"),
        ),
        Repo(
            "kya-bench",
            "NagaYu/kya-bench",
            "https://github.com/NagaYu/kya-bench",
            "689c379361956de88ad3d1b6ec37e2f85f4a6fcb",
            "Apache-2.0",
            "NagaYu_kya-bench",
        ),
        Repo(
            "cuichangquan",
            "cuichangquan/ap2-mandate-verifier",
            "https://github.com/cuichangquan/ap2-mandate-verifier",
            "0b591ffe7595c933e3d878b28ea328333d1ec931",
            "MIT",
            "cuichangquan_ap2-mandate-verifier",
        ),
        Repo(
            "amep",
            "stafordtituss/amep",
            "https://github.com/stafordtituss/amep",
            "c1d3ab77958afff7cee2abcc6442e1caa17de9fb",
            "Apache-2.0 for code (LICENSE-CODE), separate specification licence, NOTICE, "
            "trademark restrictions (TRADEMARKS.md)",
            "stafordtituss_amep",
            (),
        ),
        Repo(
            "pulse",
            "shibutatsu/pulse-ap2-x402-conformance",
            "https://github.com/shibutatsu/pulse-ap2-x402-conformance",
            "f0982ac9567ed509521688eb89fe1d5ea44d66f8",
            "Apache-2.0 (with NOTICE)",
            "shibutatsu_pulse-ap2-x402-conformance",
            (),
        ),
        Repo(
            "evidence-pack",
            "robertolocatelli81-dev/ap2-evidence-pack",
            "https://github.com/robertolocatelli81-dev/ap2-evidence-pack",
            "0a6de915d943086c13349c1911aa671c61c785b6",
            "Apache-2.0 (with NOTICE)",
            "robertolocatelli81-dev_ap2-evidence-pack",
            ("LICENSE", "NOTICE"),
        ),
        Repo(
            "agent-payment-chain",
            "robertolocatelli81-dev/agent-payment-chain",
            "https://github.com/robertolocatelli81-dev/agent-payment-chain",
            "2fdf1289ea5e641a15a75ad7160d38032c8fcc8f",
            "Apache-2.0 (with NOTICE)",
            "robertolocatelli81-dev_agent-payment-chain",
            (),
        ),
        Repo(
            "ap2-pr369",
            "google-agentic-commerce/AP2 pull requests #369 / #371 (closed, not merged)",
            "https://github.com/google-agentic-commerce/AP2",
            "433b092",
            "not stated in the repository; only in the closed pull request's text",
            "AP2-pr369",
            (),
            "pull/369/head pull/371/head",
        ),
    )
}


@dataclass(frozen=True)
class Group:
    """One row of the results table: a set of vectors converted the same way."""

    key: str
    repo: str
    title: str
    redistribute: bool
    resigned: bool
    scope: str


GROUPS: tuple[Group, ...] = (
    Group(
        "goodmeta",
        "goodmeta",
        "goodmeta token vectors",
        True,
        False,
        "`vectors/chain.json`, `vectors/receipts.json`, `vectors/hash-pairs.json`",
    ),
    Group(
        "goodmeta-decoded",
        "goodmeta",
        "goodmeta decoded payloads (re-signed)",
        False,
        True,
        "`vectors/payment-constraints.json`, `checkout-constraints.json`, "
        "`mandate-semantics.json`, `linkage.json` (`checkoutChains`)",
    ),
    Group(
        "kya-bench",
        "kya-bench",
        "kya-bench AP2 bundles",
        True,
        False,
        "`fixtures/vectors/*.json` with `protocol: ap2`",
    ),
    Group(
        "cuichangquan",
        "cuichangquan",
        "cuichangquan O2-O5 cases",
        True,
        False,
        "`research/stage11/inputs/O2O5_PUBLIC_CASES.json`",
    ),
    Group(
        "evidence-pack",
        "evidence-pack",
        "ap2-evidence-pack SDK chains",
        True,
        False,
        "`spec/vectors/ap2_chains/sdk_*`",
    ),
    Group(
        "agent-payment-chain",
        "agent-payment-chain",
        "agent-payment-chain corpus",
        False,
        False,
        "the one AP2 mandate chain embedded in `corpus/MANIFEST.json`",
    ),
    Group(
        "amep",
        "amep",
        "AMEP AP2 fixtures",
        False,
        False,
        "`packages/conformance/test/fixtures/ap2/*.json`, verdicts from `interop/ap2/`",
    ),
    Group(
        "pulse",
        "pulse",
        "Pulse AP2/x402 cases",
        False,
        False,
        "`fixtures/v0.3/cases.json` (AP2 part only)",
    ),
    Group(
        "ap2-pr369",
        "ap2-pr369",
        "AP2 PR #369/#371 corpus",
        False,
        False,
        "`contrib/mandate-corpus/vectors/*.json`",
    ),
)

GROUP_BY_KEY = {g.key: g for g in GROUPS}


def commands(repo: Repo) -> list[str]:
    """Git commands that put ``repo`` at its pinned commit under ``<root>/<directory>``."""
    d = repo.directory
    if repo.fetch_ref:
        return [
            f"git clone --filter=blob:none --no-checkout {repo.url} {d}",
            f"git -C {d} fetch origin {repo.fetch_ref}",
            f"git -C {d} checkout {repo.commit}",
        ]
    return [
        f"git clone --filter=blob:none --no-checkout {repo.url} {d}",
        f"git -C {d} checkout {repo.commit}",
    ]


def head_commit(clone: Path) -> str | None:
    """Commit checked out in ``clone``, read from ``.git`` files (git is not run)."""
    git = clone / ".git"
    if git.is_file():  # worktree: "gitdir: <path>"
        git = Path(git.read_text(encoding="utf-8").split(":", 1)[1].strip())
    head = git / "HEAD"
    if not head.is_file():
        return None
    text = head.read_text(encoding="utf-8").strip()
    if not text.startswith("ref:"):
        return text
    ref = text.split(":", 1)[1].strip()
    loose = git / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip()
    packed = git / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return line.split(" ", 1)[0]
    return None
