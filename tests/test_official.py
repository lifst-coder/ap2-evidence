"""The six official AP2 v0.2 sample tokens (docs at upstream commit e1ea56d)."""

from __future__ import annotations

import json

import pytest

from ap2_evidence.bundle import loose_bundle
from ap2_evidence.inspector import inspect_token
from ap2_evidence.jose import hash_b64
from ap2_evidence.sdjwt import parse_chain, resolve
from helpers import EXAMPLE, OFFICIAL, statuses, verify


def token(name: str) -> str:
    return (OFFICIAL / name).read_text(encoding="utf-8").strip()


# inventory section 5.3: (SHA-256 of issuer JWT, SHA-256 of <jwt>~<discs>~)
VECTORS = {
    "open_checkout.txt": (
        "LBvDGEXRJEiOTP8lLaU-Zsn1cn5kGyZBj8fHQwd9HY0",
        "FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8",
    ),
    "closed_checkout.txt": (
        "rnRgJajceWQxIiWDMsUwPQbhb9jzhwjPZNGQ44ihOcs",
        "zZPwwLfIbw9WsLz6XBg_UbQy56DqRucwTXWv10MGUF8",
    ),
    "open_payment.txt": (
        "dE4u8BXuoebSO1V1hcsiRPU_hT6GP5wa-VD35uJlNcA",
        "uixoHemmfrrCSbPREo9j-ziLuMkqExsPeWrwA-PK0Ck",
    ),
    "closed_payment.txt": (
        "wS1mjZomc9ofFgSgpPHmcQZ9QqtJLpP_YysOVroxgog",
        "O_nUGStNvVsjejIJCNWEN2ERGQ_ha0BTvWtaZ8mycDw",
    ),
}


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_hash_vectors(name: str) -> None:
    (seg,) = parse_chain(token(name))
    assert hash_b64(seg.issuer_jwt) == VECTORS[name][0]
    assert seg.sd_hash_form() == VECTORS[name][1]


def test_disclosure_digests_and_checkout_hash() -> None:
    (oc,) = parse_chain(token("open_checkout.txt"))
    assert [d.digest("sha-256") for d in oc.disclosures] == [
        "y3aocAD2rhYpJQOUMN016faDFGkTBGEDVl1R1TRHdbw",
        "a5UMAdxCk_MRayyVdRhpIAZ0ZhjVLEq1g2BWyrwKUwg",
        "QtXTJtWqg999CmUWGjHFTWMkRPguDfeK3wGSaInd-dw",
    ]
    (cc,) = parse_chain(token("closed_checkout.txt"))
    res = resolve(cc)
    assert not res.errors
    mandate = res.payload["delegate_payload"][0]
    assert mandate["checkout_hash"] == "NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8"
    assert hash_b64(mandate["checkout_jwt"]) == mandate["checkout_hash"]
    (cp,) = parse_chain(token("closed_payment.txt"))
    assert resolve(cp).payload["delegate_payload"][0]["transaction_id"] == mandate["checkout_hash"]
    (op,) = parse_chain(token("open_payment.txt"))
    ref = resolve(op).payload["delegate_payload"][0]["constraints"][2]
    assert ref["conditional_transaction_id"] == oc.sd_hash_form()


@pytest.mark.parametrize("kind", ["checkout", "payment"])
def test_chain_file_is_open_plus_closed(kind: str) -> None:
    joined = token(f"open_{kind}.txt").removesuffix("~") + "~~" + token(f"closed_{kind}.txt")
    assert joined == token(f"{kind}_chain.txt")


def test_example_bundle_is_built_from_the_chain_tokens() -> None:
    b = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert b["checkout_mandate"] == token("checkout_chain.txt")
    assert b["payment_mandate"] == token("payment_chain.txt")
    assert "keys" not in b and "checkout_receipt" not in b and "payment_receipt" not in b


MUST_PASS = [
    "CM08", "PM08",  # key-binding signatures
    "CM09", "PM09",  # sd_hash
    "CM04", "CM10", "PM04", "PM10",  # disclosures
    "CM05", "CM11", "PM05", "PM11",  # vct
    "CM31",  # checkout_hash
    "PM30",  # transaction_id
    "PM31",  # payment.reference
    "PM32",  # amount_range
    "PM33",  # allowed_payees
    "CM34",  # allowed_merchants
    "CM35",  # line_items
    "XC01", "XC02",  # amount / payee cross-checks
    "CM14", "CM15", "PM14", "PM15", "CM16", "PM16",
]  # fmt: skip
MUST_SKIP = ["CM03", "PM03", "CM32"] + [f"{p}{i:02d}" for p in ("CR", "PR") for i in range(1, 8)]


def test_official_bundle() -> None:
    report = verify(json.loads(EXAMPLE.read_text(encoding="utf-8")))
    st = statuses(report)
    assert [c for c, s in st.items() if s == "FAIL"] == []
    for cid in MUST_PASS:
        assert st[cid] == "PASS", cid
    for cid in MUST_SKIP:
        assert st[cid] == "SKIP", cid
    assert report.verdict == "INCOMPLETE"
    assert report.exit_code == 3
    assert "INCOMPLETE" in report.conclusion


def test_official_loose_files() -> None:
    bundle = loose_bundle(
        {
            "checkout_mandate": token("checkout_chain.txt"),
            "payment_mandate": token("payment_chain.txt"),
        }
    )
    st = statuses(verify(bundle))
    assert "FAIL" not in st.values()
    assert st["CM14"] == "SKIP" and st["CM08"] == "PASS"


def test_inspect_official_chain() -> None:
    info = inspect_token(token("checkout_chain.txt"))
    assert info["kind"].startswith("sd-jwt chain")
    seg1, seg2 = info["segments"]
    assert seg1["hashes"]["sha256_of_issuer_jwt"] == VECTORS["open_checkout.txt"][0]
    assert seg1["hashes"]["sha-256_of_sd_hash_form"] == VECTORS["open_checkout.txt"][1]
    assert seg1["mandate"]["vct"] == "mandate.checkout.open.1"
    assert seg2["checkout_jwt"]["header"]["kid"] == "merchant-key-1"
    assert all(d["referenced_at"] for d in seg1["disclosures"] + seg2["disclosures"])
