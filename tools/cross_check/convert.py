"""Convert each source's vectors to ``ap2-evidence/1`` bundles plus per-vector verifier options.

Every converter reads JSON / text files of a pinned clone as data. For each vector it records
the author's expected outcome, where it came from, the options that represent the author's
setting (``context``), and every transformation that was needed (``notes``).
"""

from __future__ import annotations

import copy
import glob
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import mint
from wire import (
    b64e,
    closed_amount,
    jws_payload,
    load_json,
    new_bundle,
    pem_to_jwk,
    public_jwk,
    sha_b64,
    slot_for,
)

ACCEPT, REJECT, INDETERMINATE = "accept", "reject", "indeterminate"


@dataclass
class Vector:
    """One third-party vector after conversion."""

    group: str
    vid: str
    origin: str
    bundle: dict[str, Any]
    expected: str
    detail: str
    at: int | None = None
    context: dict[str, Any] = field(default_factory=dict)
    resigned: bool = False
    notes: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def options(self, with_context: bool) -> dict[str, Any]:
        """Keyword arguments for ``verify_bundle``."""
        opts: dict[str, Any] = {} if self.at is None else {"at": self.at}
        if with_context:
            opts.update(copy.deepcopy(self.context))
        return opts


def _one_line(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _history(ctx: dict[str, Any], currency: str | None) -> dict[str, Any]:
    hist: dict[str, Any] = {}
    if "total_amount" in ctx and currency:
        hist["prior_total"] = {"amount": int(ctx["total_amount"]), "currency": currency}
    if "total_uses" in ctx:
        hist["prior_uses"] = int(ctx["total_uses"])
    return hist


# --------------------------------------------------------------------------- goodmeta tokens

GOODMETA_CLOCK = 1780000000  # goodmeta VECTORS.md:7-10, "the canonical clock"


def goodmeta(root: Path) -> list[Vector]:
    """goodmeta/ap2-conformance token vectors (chain, receipts, hash-pairs)."""
    vdir = root / "vectors"
    out: list[Vector] = []
    for v in load_json(vdir / "chain.json"):
        b = new_bundle("goodmeta chain.json " + v["name"])
        slot = slot_for(v["chain"]) or "payment_mandate"
        b[slot] = v["chain"]
        if v.get("rootKey"):
            b["keys"]["mandate_issuer"] = [public_jwk(v["rootKey"])]
        kind = "checkout" if slot == "checkout_mandate" else "payment"
        b["expected"] = {kind: {"aud": v["expectedAud"], "nonce": v["expectedNonce"]}}
        notes = []
        if v.get("kind") == "x5c":
            notes.append(
                f"root key given as an x5c chain with {len(v.get('x5cTrustedRoots') or [])} "
                "trusted root certificate(s); not representable (no x5c support)"
            )
        hard = " [hardening]" if v.get("hardening") else ""
        out.append(
            Vector(
                "goodmeta",
                "chain." + v["name"],
                f"vectors/chain.json name={v['name']}",
                b,
                ACCEPT if v["expect"] == "valid" else REJECT,
                _one_line((v.get("reason") or "valid") + hard),
                at=GOODMETA_CLOCK,
                notes=notes,
            )
        )
    for v in load_json(vdir / "receipts.json"):
        b = new_bundle("goodmeta receipts.json " + v["name"])
        chain = v["mandateChain"]
        b[slot_for(chain) or f"{v['kind']}_mandate"] = chain
        role = "payment_processor" if v["kind"] == "payment" else "merchant"
        b[f"{v['kind']}_receipt"] = v["receiptJwt"]
        b["keys"][role] = [public_jwk(v["issuerPublicKey"])]
        out.append(
            Vector(
                "goodmeta",
                "receipts." + v["name"],
                f"vectors/receipts.json name={v['name']}",
                b,
                v["expect"],
                _one_line(f"{v['ap2Result']}: {v['rule']}"),
                at=GOODMETA_CLOCK,
                notes=["the vector ships no key for the mandate chain's root"],
            )
        )
    hp = load_json(vdir / "hash-pairs.json")
    chain = "~~".join(hp["rawSplitOnDoubleTilde"])
    b = new_bundle("goodmeta hash-pairs.json chain")
    b[slot_for(chain) or "payment_mandate"] = chain
    out.append(
        Vector(
            "goodmeta",
            "hash-pairs.chain",
            "vectors/hash-pairs.json rawSplitOnDoubleTilde",
            b,
            ACCEPT,
            "reference chain for the per-segment hash values",
            at=GOODMETA_CLOCK,
            notes=["the vector ships no key"],
        )
    )
    return out


# ------------------------------------------------------------------ goodmeta decoded payloads

GOODMETA_IAT = 1780000000


class _Resigner:
    """Deterministic keys for one re-signed vector."""

    def __init__(self, vid: str) -> None:
        self.vid = vid
        self.issuer = mint.Key("issuer-1")
        self.agent = mint.Key("agent-1")
        self.merchant = mint.Key("merchant-1")

    def keys(self, b: dict[str, Any]) -> None:
        b["keys"]["mandate_issuer"] = [self.issuer.jwk]
        b["keys"]["merchant"] = [self.merchant.jwk]

    def with_agent(self, open_obj: dict[str, Any]) -> dict[str, Any]:
        o = copy.deepcopy(open_obj)
        if "cnf" in o:
            o["cnf"] = {"jwk": self.agent.public_no_kid()}
        return o

    def chain(
        self, open_obj: dict[str, Any], closed: dict[str, Any], aud: str, nonce: str, tag: str
    ) -> tuple[str, str]:
        label = f"{self.vid}/{tag}"
        root = mint.root_sdjwt(self.issuer, self.with_agent(open_obj), label)
        kb = mint.kb_sdjwt(self.agent, root, closed, aud, nonce, GOODMETA_IAT, label)
        return mint.join(root, kb), root

    def resign_checkout(self, closed: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        c = copy.deepcopy(closed)
        notes: list[str] = []
        jwt = c.get("checkout_jwt")
        if isinstance(jwt, str) and jwt.count(".") == 2:
            hash_matched = c.get("checkout_hash") == sha_b64(jwt)
            c["checkout_jwt"] = self.merchant.sign_jwt(jws_payload(jwt))
            if hash_matched:
                c["checkout_hash"] = sha_b64(c["checkout_jwt"])
            elif "checkout_hash" in c:
                notes.append("original checkout_hash did not match the original checkout_jwt: kept")
            notes.append("checkout_jwt re-signed with a generated merchant key")
        return c, notes


def goodmeta_decoded(root: Path) -> list[Vector]:
    """Decoded-payload vectors of goodmeta, re-wrapped into signed chains with generated keys."""
    vdir = root / "vectors"
    out: list[Vector] = []

    def add(name: str, file: str, b: dict[str, Any], exp: str, det: str, **kw: Any) -> None:
        out.append(
            Vector(
                "goodmeta-decoded",
                name,
                f"vectors/{file} name={name.split('.', 1)[1]}",
                b,
                exp,
                _one_line(det),
                resigned=True,
                **kw,
            )
        )

    for v in load_json(vdir / "payment-constraints.json"):
        vid = "payment-constraints." + v["name"]
        rs = _Resigner(vid)
        b = new_bundle(f"goodmeta payment-constraints {v['name']} (re-signed)")
        rs.keys(b)
        op, cl = copy.deepcopy(v["open"]), copy.deepcopy(v["closed"])
        notes = ["cnf.jwk placeholder replaced by a generated agent key"]
        refs = [c for c in op.get("constraints", []) if c.get("type") == "payment.reference"]
        if refs and v.get("openCheckoutHash"):
            co = {
                "id": "co_1",
                "merchant": cl.get("payee"),
                "line_items": [],
                "status": "completed",
                "currency": cl["payment_amount"]["currency"],
                "totals": [{"type": "total", "amount": cl["payment_amount"]["amount"]}],
                "links": [],
            }
            jwt = rs.merchant.sign_jwt(co)
            closed_co = {
                "vct": "mandate.checkout.1",
                "checkout_jwt": jwt,
                "checkout_hash": sha_b64(jwt),
            }
            open_co = {"vct": "mandate.checkout.open.1", "cnf": {"jwk": {}}}
            b["checkout_mandate"], croot = rs.chain(open_co, closed_co, "merchant", "n-2", "co")
            for c in refs:
                if c.get("conditional_transaction_id") == v["openCheckoutHash"]:
                    c["conditional_transaction_id"] = mint.sd_hash(croot)
                    notes.append("conditional_transaction_id set to the minted open checkout hash")
                else:
                    notes.append("conditional_transaction_id kept (differs from openCheckoutHash)")
            cl["transaction_id"] = sha_b64(jwt)
            notes.append("checkout mandate minted to match the payment; transaction_id set to it")
        context: dict[str, Any] = {}
        if v.get("context"):
            hist = _history(v["context"], (cl.get("payment_amount") or {}).get("currency"))
            if hist:
                context["history"] = hist
            notes.append(f"author context {v['context']} supplied as history")
        if v.get("requiredConstraints"):
            context["expected"] = {"require_constraints": list(v["requiredConstraints"])}
            notes.append("requiredConstraints supplied as expected.require_constraints")
        b["payment_mandate"], _ = rs.chain(op, cl, "credential-provider", "n-1", "pm")
        exp = REJECT if (v["ap2Violations"] or v.get("hardening")) else ACCEPT
        det = " | ".join(v["ap2Violations"]) or "no violation"
        if v.get("hardening"):
            det += " [hardening: must report >=1]"
        add(vid, "payment-constraints.json", b, exp, det, context=context, notes=notes)

    for v in load_json(vdir / "checkout-constraints.json"):
        vid = "checkout-constraints." + v["name"]
        rs = _Resigner(vid)
        b = new_bundle(f"goodmeta checkout-constraints {v['name']} (re-signed)")
        rs.keys(b)
        jwt = rs.merchant.sign_jwt(v["checkout"])
        closed = {"vct": "mandate.checkout.1", "checkout_jwt": jwt, "checkout_hash": sha_b64(jwt)}
        b["checkout_mandate"], _ = rs.chain(v["open"], closed, "merchant", "n-2", "co")
        exp = REJECT if v["ap2Violations"] else ACCEPT
        add(
            vid,
            "checkout-constraints.json",
            b,
            exp,
            " | ".join(v["ap2Violations"]) or "no violation",
            notes=["cnf replaced; checkout signed with a generated merchant key"],
        )

    for v in load_json(vdir / "mandate-semantics.json"):
        vid = "mandate-semantics." + v["name"]
        rs = _Resigner(vid)
        b = new_bundle(f"goodmeta mandate-semantics {v['name']} (re-signed)")
        rs.keys(b)
        notes = ["cnf replaced"]
        if v["mandate"] == "payment":
            b["payment_mandate"], _ = rs.chain(
                v["open"], v["closed"], "credential-provider", "n-1", "pm"
            )
        else:
            cl, more = rs.resign_checkout(v["closed"])
            notes += more
            b["checkout_mandate"], _ = rs.chain(v["open"], cl, "merchant", "n-2", "co")
        hard = " [hardening]" if v.get("hardening") else ""
        add(
            vid,
            "mandate-semantics.json",
            b,
            v["expect"],
            f"ap2Outcome={v['ap2Outcome']}; {v['rule']}{hard}",
            notes=notes,
        )

    for v in load_json(vdir / "linkage.json")["checkoutChains"]:
        vid = "linkage." + v["name"]
        rs = _Resigner(vid)
        b = new_bundle(f"goodmeta linkage {v['name']} (re-signed)")
        rs.keys(b)
        cl, more = rs.resign_checkout(v["closed"])
        b["checkout_mandate"], _ = rs.chain(v["open"], cl, "merchant", "n-2", "co")
        exp = REJECT if (v["ap2Violations"] or v["tamperHash"]) else ACCEPT
        det = " | ".join(v["ap2Violations"]) or "no violation"
        if v["tamperHash"]:
            det += " [tamperHash: hardening]"
        add(vid, "linkage.json", b, exp, det, notes=["cnf replaced", *more])
    for vec in out:
        vec.origin = vec.origin.replace("linkage.json name=", "linkage.json checkoutChains name=")
    return out


# --------------------------------------------------------------------------- kya-bench


def kya_bench(root: Path) -> list[Vector]:
    """NagaYu/kya-bench vectors with ``protocol: ap2``; keys from ``fixtures/jwks.json``."""
    fdir = root / "fixtures"
    jwks: dict[str, Any] = load_json(fdir / "jwks.json")
    # The trust list also holds an RSA key used by kya-bench's non-AP2 vectors; AP2 is ES256.
    trust = [
        public_jwk(k)
        for doc in jwks.values()
        for k in (doc.get("keys") or [])
        if k.get("kty") == "EC" and k.get("crv") == "P-256"
    ]
    out: list[Vector] = []
    for path in sorted(glob.glob(str(fdir / "vectors" / "*.json"))):
        p = Path(path)
        if p.name == "manifest.json":
            continue
        v = load_json(p)
        if v.get("protocol") != "ap2":
            continue
        src = v["bundle"]
        b = new_bundle("kya-bench " + v["id"])
        issuers: set[str] = set()
        for slot in ("checkout_mandate", "payment_mandate"):
            if isinstance(src.get(slot), str):
                b[slot] = src[slot]
                payload = jws_payload(src[slot].split("~")[0])
                if isinstance(payload, dict) and isinstance(payload.get("iss"), str):
                    issuers.add(payload["iss"])
        keys: list[dict[str, Any]] = []
        for iss in sorted(issuers):
            for k in (jwks.get(iss) or {}).get("keys", []):
                if public_jwk(k) not in keys:
                    keys.append(public_jwk(k))
        b["keys"]["mandate_issuer"] = keys
        e = src.get("expected") or {}
        exp: dict[str, dict[str, str]] = {}
        for kind in ("checkout", "payment"):
            pair = {c: e[f"{kind}_{c}"] for c in ("aud", "nonce") if e.get(f"{kind}_{c}")}
            if pair:
                exp[kind] = pair
        if exp:
            b["expected"] = exp
        notes = []
        context: dict[str, Any] = {"trusted_keys": {"mandate_issuer": trust}}
        ctx = src.get("mandate_context")
        if ctx:
            amount = closed_amount(src.get("payment_mandate") or "")
            hist = _history(ctx, (amount or {}).get("currency"))
            if hist:
                context["history"] = hist
            notes.append(f"mandate_context {ctx} supplied as history")
            if "last_used_date" in ctx:
                notes.append("last_used_date has no counterpart in the history option")
        if not keys:
            notes.append("root iss not in jwks.json: no mandate_issuer key in the bundle")
        notes.append("context: the whole jwks.json trust list pinned as mandate_issuer keys")
        out.append(
            Vector(
                "kya-bench",
                v["id"],
                f"fixtures/vectors/{p.name}",
                b,
                {"accept": ACCEPT, "reject": REJECT}.get(v["expected_verdict"], INDETERMINATE),
                _one_line(
                    ",".join(v.get("expected_reason_codes") or [])
                    + " | "
                    + v.get("description", "")
                ),
                at=v.get("now"),
                context=context,
                notes=notes,
            )
        )
    return out


# --------------------------------------------------------------------------- cuichangquan

CUI_FILE = "research/stage11/inputs/O2O5_PUBLIC_CASES.json"


def cuichangquan(root: Path) -> list[Vector]:
    """cuichangquan/ap2-mandate-verifier public O2-O5 cases (checkout-only bundles)."""
    data = load_json(root / CUI_FILE)
    obs = data["gem_observations"]
    out: list[Vector] = []
    for name, c in data["cases"].items():
        rootp = c["root_presentation"]
        term = c["terminal_jws"]
        chain = (rootp if rootp.endswith("~") else rootp + "~") + "~" + term
        chain += "" if term.endswith("~") else "~"
        b = new_bundle("cuichangquan O2O5 " + name)
        b["checkout_mandate"] = chain
        b["keys"]["mandate_issuer"] = [pem_to_jwk(c["trusted_issuer_public_key_pem"])]
        b["keys"]["merchant"] = [pem_to_jwk(c["trusted_merchant_public_key_pem"])]
        aud_nonce = {"aud": c["expected_aud"], "nonce": c["expected_nonce"]}
        b["expected"] = {"checkout": dict(aud_nonce)}
        o = obs[name]
        exp = ACCEPT if o["code"] == "scoped_constraints_verified_only" else REJECT
        notes = []
        inner = None
        payload = jws_payload(term.split("~")[0]) or {}
        for item in payload.get("delegate_payload") or []:
            if isinstance(item, dict) and "checkout_jwt" in item:
                inner = item["checkout_jwt"]
        if inner is not None and inner != c["host_checkout_jws"]:
            notes.append(
                "host_checkout_jws differs from the checkout_jwt inside the terminal token; "
                "a bundle holds only the one inside the mandate"
            )
        context = {
            "skew": 0,
            "expected": {
                "checkout": dict(aud_nonce),
                "agent_key": pem_to_jwk(c["expected_agent_public_key_pem"]),
                "checkout_id": c["expected_checkout_id"],
                "merchant_id": c["expected_merchant_id"],
                "total": {"amount": c["expected_total_minor"], "currency": c["expected_currency"]},
            },
        }
        notes.append(
            "context: expected agent key, checkout id, merchant id and total supplied; skew 0 "
            "(the author's profile has no implicit skew)"
        )
        out.append(
            Vector(
                "cuichangquan",
                "O2O5." + name,
                f"{CUI_FILE} cases.{name}",
                b,
                exp,
                f"{o['status']}/{o['code']}",
                at=c["verified_at"],
                context=context,
                notes=notes,
            )
        )
    return out


# --------------------------------------------------------------------------- evidence-pack


def evidence_pack(root: Path) -> list[Vector]:
    """robertolocatelli81-dev/ap2-evidence-pack chains emitted with the upstream SDK."""
    d = root / "spec" / "vectors" / "ap2_chains"

    def txt(name: str) -> str:
        return (d / name).read_text(encoding="utf-8").strip()

    iss = public_jwk(load_json(d / "sdk_issuer_pub.json"))
    mpp = public_jwk(load_json(d / "sdk_mpp_pub.json"))
    cases = (
        ("sdk_chainA", ACCEPT, "SDK-emitted chain A with receipt A", True),
        ("sdk_chainA_noreceipt", ACCEPT, "SDK-emitted chain A", False),
        ("sdk_chainB", ACCEPT, "SDK-emitted chain B", False),
        ("sdk_chain_mixed", REJECT, "open of A + closed of B; the SDK refuses (sd_hash)", False),
    )
    out: list[Vector] = []
    for name, exp, det, with_receipt in cases:
        fn = name.replace("_noreceipt", "") + ".txt"
        chain = txt(fn)
        b = new_bundle("ap2-evidence-pack " + name)
        b[slot_for(chain) or "payment_mandate"] = chain
        b["keys"]["mandate_issuer"] = [iss]
        origin = f"spec/vectors/ap2_chains/{fn}"
        if with_receipt:
            b["payment_receipt"] = txt("sdk_receiptA.jwt")
            b["keys"]["payment_processor"] = [mpp]
            origin += " + sdk_receiptA.jwt"
        out.append(
            Vector(
                "evidence-pack",
                name,
                origin,
                b,
                exp,
                det,
                notes=["no expected aud/nonce published with the vector"],
            )
        )
    return out


# --------------------------------------------------------------------------- agent-payment-chain


def agent_payment_chain(root: Path) -> list[Vector]:
    """robertolocatelli81-dev/agent-payment-chain: the AP2 chain embedded in the corpus manifest."""
    m = load_json(root / "corpus" / "MANIFEST.json")
    out: list[Vector] = []
    seen: set[str] = set()
    for i, bb in enumerate(m["bundles"]):
        mand = (bb.get("ours") or {}).get("mandate")
        if not mand or mand["chain"] in seen:
            continue
        seen.add(mand["chain"])
        b = new_bundle(f"agent-payment-chain MANIFEST bundles[{i}]")
        b["payment_mandate"] = mand["chain"]
        arts = mand["pack"]["artifacts"]
        b["keys"]["mandate_issuer"] = [public_jwk(arts[0]["key"]["jwk"])]
        ok = all(bool((a.get("verified_at_build") or {}).get("signature_ok")) for a in arts)
        out.append(
            Vector(
                "agent-payment-chain",
                f"manifest.bundles{i}",
                f"corpus/MANIFEST.json bundles[{i}].ours.mandate",
                b,
                ACCEPT if ok else REJECT,
                _one_line(f"verdict={bb.get('verdict')}; signatures verified at build: {ok}"),
            )
        )
    return out


# --------------------------------------------------------------------------- AMEP

AMEP_FIX = "packages/conformance/test/fixtures/ap2"


def _sdk_reference(chain: str) -> str:
    last = chain.split("~~")[-1]
    return b64e(hashlib.sha256(last.split("~")[0].encode()).digest())


def amep(root: Path) -> list[Vector]:
    """stafordtituss/amep AP2 fixtures: one bundle per payment chain of each family."""
    ver = load_json(root / "interop" / "ap2" / "verdicts.json")["families"]
    ver.update(load_json(root / "interop" / "ap2" / "verdicts-checkout.json")["families"])
    outcome = {"preserved": ACCEPT, "violated": REJECT, "unresolved": INDETERMINATE}
    out: list[Vector] = []
    for fname, fam in (
        ("sdk-bundles.json", "sdk"),
        ("bundles.json", "synthetic"),
        ("sdk-bundles-v2.json", "sdk-checkout"),
    ):
        d = load_json(root / AMEP_FIX / fname)
        tr = d["trust"]
        for name, fb in d["bundles"].items():
            vv = ver[fam]["vectors"][name]
            pays = vv["payments"]
            used: set[int] = set()
            # open mandate (first segment) -> (spend, uses) of earlier settled payments, or None
            # when an earlier payment has no receipt (its outcome, hence the history, is unknown)
            ledger: dict[str, tuple[int, int] | None] = {}
            chains = fb["chains"]
            for i, chain in enumerate(chains):
                opened = chain.split("~~")[0]
                known = ledger.get(opened, (0, 0))
                b = new_bundle(f"AMEP {fname} {name} payment {i + 1}")
                b["payment_mandate"] = chain
                b["keys"]["mandate_issuer"] = [public_jwk(tr["userJwk"])]
                b["keys"]["payment_processor"] = [public_jwk(tr["processorJwk"])]
                if "merchantJwk" in tr:
                    b["keys"]["merchant"] = [public_jwk(tr["merchantJwk"])]
                cks = fb.get("checkouts") or []
                if cks:
                    b["checkout_mandate"] = cks[i] if i < len(cks) else cks[0]
                rec = None
                ref = _sdk_reference(chain)
                for j, r in enumerate(fb["receipts"]):
                    if j not in used and (jws_payload(r) or {}).get("reference") == ref:
                        rec = j
                        break
                if rec is None and len(fb["receipts"]) == len(chains) and i not in used:
                    rec = i
                if rec is not None:
                    used.add(rec)
                    b["payment_receipt"] = fb["receipts"][rec]
                p = pays[i] if i < len(pays) else pays[-1]
                amount = closed_amount(chain) or {}
                currency = amount.get("currency")
                context: dict[str, Any] = {}
                if known is None:
                    notes = ["context: no history (an earlier payment's outcome is unknown)"]
                else:
                    prior_total, prior_uses = known
                    if isinstance(currency, str):
                        context["history"] = {
                            "prior_total": {"amount": prior_total, "currency": currency},
                            "prior_uses": prior_uses,
                        }
                    notes = [
                        "context: history = earlier successful payments of this family under the "
                        f"same open mandate (prior_total {prior_total}, prior_uses {prior_uses})"
                    ]
                if len(chains) > 1 and chains[0] == chains[-1]:
                    notes.append("the same chain, byte for byte, is presented twice in this family")
                status = (jws_payload(b.get("payment_receipt", "")) or {}).get("status")
                spent = amount.get("amount")
                if known is None or status is None:
                    ledger[opened] = None
                elif status == "Success" and isinstance(spent, int):
                    ledger[opened] = (known[0] + spent, known[1] + 1)
                gaps = [g["need"] for g in p.get("gaps", [])]
                det = f"{p['outcome']} {p.get('invariant')} gaps={gaps}"
                out.append(
                    Vector(
                        "amep",
                        f"{fam}.{name}.p{i + 1}",
                        f"{AMEP_FIX}/{fname} bundles.{name} chains[{i}]",
                        b,
                        outcome[p["outcome"]],
                        _one_line(det),
                        context=context,
                        notes=notes,
                    )
                )
    return out


# --------------------------------------------------------------------------- Pulse

PULSE_FILE = "fixtures/v0.3/cases.json"


def pulse(root: Path) -> list[Vector]:
    """shibutatsu/pulse-ap2-x402-conformance: the AP2 evidence of each case (x402 dropped)."""
    cases = load_json(root / PULSE_FILE)["cases"]
    valid_tokens: dict[tuple[str, str], str] = {}
    by_id = {c["id"]: c for c in cases}
    for c in cases:
        ev = c["ap2"]["verification"]["cryptographicEvidence"]
        if c["expected"].get("consistent"):
            valid_tokens.setdefault((ev["mandateChain"], ev["paymentReceiptJwt"]), c["id"])

    def differing(a: Any, b: Any, path: str, depth: int) -> list[str]:
        if a == b:
            return []
        if depth == 0 or not (isinstance(a, dict) and isinstance(b, dict)):
            return [path]
        keys = sorted(set(a) | set(b))
        return [p for k in keys for p in differing(a.get(k), b.get(k), f"{path}.{k}", depth - 1)]

    out: list[Vector] = []
    for c in cases:
        ev = c["ap2"]["verification"]["cryptographicEvidence"]
        b = new_bundle("pulse v0.3 " + c["id"])
        b["payment_mandate"] = ev["mandateChain"]
        b["payment_receipt"] = ev["paymentReceiptJwt"]
        b["keys"]["mandate_issuer"] = [public_jwk(ev["trustedRootPublicJwk"])]
        b["keys"]["payment_processor"] = [public_jwk(ev["trustedReceiptPublicJwk"])]
        b["expected"] = {"payment": {"aud": ev["expectedAudience"], "nonce": ev["expectedNonce"]}}
        e = c["expected"]
        same = valid_tokens.get((ev["mandateChain"], ev["paymentReceiptJwt"]))
        notes = ["x402 payload, EIP-3009 authorisation and settlement record are not representable"]
        facts: dict[str, Any] = {"signed_tokens_as_valid_case": same}
        if same and same != c["id"]:
            twin = {k: v for k, v in by_id[same].items() if k not in ("id", "expected")}
            mine = {k: v for k, v in c.items() if k not in ("id", "expected")}
            diff = [p.lstrip(".") for p in differing(twin, mine, "", 3)]
            facts["differs_from_valid_in"] = diff
            notes.append(
                f"signed AP2 tokens byte-identical to those of valid case {same}; the case "
                f"differs from it only in: {', '.join(diff) or '(nothing)'}"
            )
        out.append(
            Vector(
                "pulse",
                c["id"],
                f"{PULSE_FILE} id={c['id']}",
                b,
                ACCEPT if e.get("consistent") else REJECT,
                _one_line("codes=" + ",".join(e.get("failureCodes") or [])),
                at=c["nowEpochSeconds"],
                notes=notes,
                facts=facts,
            )
        )
    return out


# --------------------------------------------------------------------------- AP2 PR #369/#371

PR_DIR = "contrib/mandate-corpus/vectors"


def ap2_pr369(root: Path) -> list[Vector]:
    """Corpus of the closed AP2 pull requests #369 / #371 (identical vectors in both)."""
    out: list[Vector] = []
    for e in load_json(root / PR_DIR / "index.json"):
        v = load_json(root / PR_DIR / e["file"])
        rootp, kb = v["root_sd_jwt"], v["kb_sd_jwt"]
        chain = (rootp[:-1] if rootp.endswith("~") else rootp) + "~~" + kb
        b = new_bundle("AP2 PR #369 corpus " + v["id"])
        b["payment_mandate"] = chain
        b["keys"]["mandate_issuer"] = [public_jwk(v["issuance"]["issuer_jwk"])]
        b["expected"] = {"payment": {"aud": v["issuance"]["aud"], "nonce": v["issuance"]["nonce"]}}
        out.append(
            Vector(
                "ap2-pr369",
                v["id"],
                f"{PR_DIR}/{e['file']}",
                b,
                ACCEPT,
                "chain valid, cnf = agent key (author's verify_fixtures.py)",
                notes=["second hop is a kb+sd-jwt+kb token carrying an open payment mandate"],
            )
        )
    return out


CONVERTERS: dict[str, Callable[[Path], list[Vector]]] = {
    "goodmeta": goodmeta,
    "goodmeta-decoded": goodmeta_decoded,
    "kya-bench": kya_bench,
    "cuichangquan": cuichangquan,
    "evidence-pack": evidence_pack,
    "agent-payment-chain": agent_payment_chain,
    "amep": amep,
    "pulse": pulse,
    "ap2-pr369": ap2_pr369,
}

SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")
