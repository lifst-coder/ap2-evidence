"""Tamper with the upstream-minted card bundle (out/card) in many ways.

N* = naive edits by someone holding no key. K* = forgeries by a party holding one real key
(agent, merchant or processor), re-signed with the upstream SDK so only the semantic link breaks.
usage: python tamper.py BASEDIR OTHERDIR OUTDIR
"""
import base64, copy, json, sys, uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.utils import compute_sha256_b64url

base, other, outdir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
B = json.loads((base / "bundle.json").read_text(encoding="utf-8"))
T = json.loads((base / "trusted_keys.json").read_text(encoding="utf-8"))
K = {k: JWK.from_json(json.dumps(v)) for k, v in
     json.loads((base / "private_keys.json").read_text(encoding="utf-8")).items()}
O = json.loads((other / "bundle.json").read_text(encoding="utf-8"))
open_payment = (base / "open_payment_as_issued.txt").read_text(encoding="utf-8")
open_checkout = (base / "open_checkout_as_issued.txt").read_text(encoding="utf-8")
mc = MandateClient()


def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jwt_payload(t): return json.loads(b64d(t.split(".")[1]))
def ref(chain): return compute_sha256_b64url(mc.get_closed_mandate_jwt(chain))


def closed_payload(chain):
    seg = chain.split("~~")[-1].rstrip("~").split("~")
    for d in seg[1:]:
        v = json.loads(b64d(d))
        if len(v) == 2 and isinstance(v[1], dict) and "vct" in v[1]:
            return v[1]


def checkout_jwt_of(chain):
    for d in chain.split("~~")[-1].rstrip("~").split("~")[1:]:
        v = json.loads(b64d(d))
        if len(v) == 3 and v[1] == "checkout_jwt":
            return v[2]


cpay = closed_payload(B["payment_mandate"])
pay_nonce = B["expected"]["payment"]["nonce"]; chk_nonce = B["expected"]["checkout"]["nonce"]
cjwt = checkout_jwt_of(B["checkout_mandate"]); chash = compute_sha256_b64url(cjwt)


def present_payment(**changes):
    p = dict(cpay); p.update(changes)
    p.pop("vct", None)
    pm = PaymentMandate(**p)
    return mc.present(holder_key=K["agent"], mandate_token=open_payment, payloads=[pm],
                      nonce=pay_nonce, aud="credential-provider")


def sign_payment_receipt(chain, **over):
    pl = jwt_payload(B["payment_receipt"]); pl["reference"] = ref(chain); pl.update(over)
    return create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-payment-processor-key-1"}, pl, K["mpp"])


def sign_checkout_receipt(chain=None, **over):
    pl = jwt_payload(B["checkout_receipt"])
    if chain: pl["reference"] = ref(chain)
    pl.update(over)
    return create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, pl, K["merchant"])


cases = {}


def case(cid, desc, bundle=None, trusted=None, extra_args=None):
    cases[cid] = {"desc": desc, "bundle": bundle or B, "trusted": trusted or T, "args": extra_args or []}


def mod(**kv):
    b = copy.deepcopy(B); b.update(kv); return b


# ---------------- naive edits ----------------
seg = B["payment_mandate"].split("~~")
closed = seg[1].rstrip("~").split("~")
for i, d in enumerate(closed[1:], 1):
    v = json.loads(b64d(d))
    if isinstance(v[1], dict) and "payment_amount" in v[1]:
        v[1]["payment_amount"]["amount"] = 1
        closed[i] = b64e(json.dumps(v).encode())
case("N1_amount_disclosure_edit", "closed payment disclosure amount 9998 -> 1, re-encoded, not re-signed",
     mod(payment_mandate=seg[0] + "~~" + "~".join(closed) + "~"))

o = seg[0].split("~")
o2 = [x for x in o if not (x and x.count(".") == 0 and "merchant_1" in b64d(x).decode(errors="ignore")
                           and "vct" not in b64d(x).decode(errors="ignore"))]
case("N2_drop_payee_disclosure", "allowed_payees entry disclosure removed from open payment segment (no re-sign)",
     mod(payment_mandate="~".join(o2) + "~~" + seg[1]))

cs = B["checkout_mandate"].split("~~"); cc = cs[1].rstrip("~").split("~")
cc2 = [cc[0]] + [d for d in cc[1:] if json.loads(b64d(d))[1] != "checkout_jwt"]
case("N3_drop_checkout_jwt_disclosure", "checkout_jwt disclosure removed from closed checkout segment",
     mod(checkout_mandate=cs[0] + "~~" + "~".join(cc2) + "~"))

h, p, s = B["checkout_receipt"].split("."); pl = json.loads(b64d(p)); pl["reference"] = ref(B["payment_mandate"])
case("N4_receipt_reference_edit", "checkout receipt reference edited, signature not redone",
     mod(checkout_receipt=f"{h}.{b64e(json.dumps(pl).encode())}.{s}"))
case("N5_receipts_swapped", "checkout_receipt and payment_receipt swapped",
     mod(checkout_receipt=B["payment_receipt"], payment_receipt=B["checkout_receipt"]))
case("N6_payment_from_other_txn", "payment mandate + receipt replaced with those of another upstream-minted txn",
     mod(payment_mandate=O["payment_mandate"], payment_receipt=O["payment_receipt"]))

# ---------------- forgeries with a real key ----------------
pc = present_payment(payment_amount=Amount(amount=20000, currency="USD"))
case("K1_amount_over_cap", "agent re-signs payment for 20000 (cap 15000, checkout 9998); processor receipt re-signed",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))
pc = present_payment(payment_amount=Amount(amount=10000, currency="USD"))
case("K1b_amount_within_cap_not_total", "agent re-signs payment for 10000 (within cap, checkout says 9998)",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))
pc = present_payment(payee=Merchant(id="merchant_2", name="Other", website="https://other.example"))
case("K2_payee_changed", "agent re-signs payment to payee merchant_2", mod(payment_mandate=pc,
     payment_receipt=sign_payment_receipt(pc)))
pc = present_payment(transaction_id=compute_sha256_b64url("some other checkout"))
case("K3_transaction_id_changed", "agent re-signs payment with transaction_id of another checkout",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))
cc_forged = mc.present(holder_key=K["agent"], mandate_token=open_checkout,
                       payloads=[CheckoutMandate(checkout_jwt=cjwt, checkout_hash=compute_sha256_b64url("x"))],
                       nonce=chk_nonce, aud="merchant")
case("K3b_checkout_hash_wrong", "agent re-signs closed checkout with checkout_hash not matching checkout_jwt",
     mod(checkout_mandate=cc_forged, checkout_receipt=sign_checkout_receipt(cc_forged)))
cpl = jwt_payload(cjwt); cpl["totals"] = [{"type": "subtotal", "amount": 5000}, {"type": "total", "amount": 5000}]
cjwt2 = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, cpl, K["merchant"])
cc2c = mc.present(holder_key=K["agent"], mandate_token=open_checkout,
                  payloads=[CheckoutMandate(checkout_jwt=cjwt2, checkout_hash=compute_sha256_b64url(cjwt2))],
                  nonce=chk_nonce, aud="merchant")
case("K3c_checkout_replaced", "merchant+agent produce a new consistent checkout (total 5000); payment unchanged",
     mod(checkout_mandate=cc2c, checkout_receipt=sign_checkout_receipt(cc2c)))
case("K4_receipt_reference_other_mandate", "merchant signs checkout receipt whose reference is the payment mandate's",
     mod(checkout_receipt=sign_checkout_receipt(B["payment_mandate"])))
case("K4b_payment_receipt_ref_random", "processor signs payment receipt with a random reference",
     mod(payment_receipt=sign_payment_receipt(B["payment_mandate"], reference=compute_sha256_b64url("random"))))

fresh = lambda kid=None: JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
t = copy.deepcopy(T); t["merchant"] = [dict(json.loads(fresh().export_public()), kid="merchant-key-1")]
case("K5_trusted_merchant_key_swapped", "pinned merchant key is a different key (same kid)", trusted=t)
t = copy.deepcopy(T); t["mandate_issuer"] = [dict(json.loads(fresh().export_public()), kid="agent-provider-key-1")]
case("K5b_trusted_issuer_key_swapped", "pinned mandate-issuer key is a different key (same kid)", trusted=t)
rogue = fresh(); p = dict(cpay); p.pop("vct")
pc = mc.present(holder_key=rogue, mandate_token=open_payment, payloads=[PaymentMandate(**p)],
                nonce=pay_nonce, aud="credential-provider")
case("K5c_closed_payment_signed_by_rogue_agent", "closed payment signed by a key other than cnf.jwk",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))
# K5d: attacker re-issues the open payment mandate (raised cap) under their own issuer key, same kid
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
fake_issuer = JWK.from_json(json.dumps(dict(json.loads(fresh().export()), kid="agent-provider-key-1")))
op = None
for d in open_payment.rstrip("~").split("~")[1:]:
    v = json.loads(b64d(d))
    if len(v) == 2 and isinstance(v[1], dict) and v[1].get("vct") == "mandate.payment.open.1":
        op = v[1]
op = json.loads(json.dumps(op))
def resolve(x, discs):  # plug array-element disclosures back in so the SDK model validates
    if isinstance(x, list):
        return [resolve(discs.get(e["..."], e) if isinstance(e, dict) and "..." in e else e, discs) for e in x]
    if isinstance(x, dict):
        return {k: resolve(v, discs) for k, v in x.items()}
    return x
discs = {compute_sha256_b64url(d): json.loads(b64d(d))[-1] for d in open_payment.rstrip("~").split("~")[1:]}
op = resolve(op, discs)
for c in op["constraints"]:
    if c["type"] == "payment.amount_range":
        c["max"] = 10_000_000
forged_open = mc.create(payloads=[OpenPaymentMandate.model_validate(op)], issuer_key=fake_issuer)
p = dict(cpay); p.pop("vct")
pc = mc.present(holder_key=K["agent"], mandate_token=forged_open, payloads=[PaymentMandate(**p)],
                nonce=pay_nonce, aud="credential-provider")
case("K5d_open_payment_reissued_by_fake_issuer", "open payment mandate re-issued with raised cap under an attacker key (kid copied)",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))

# K6: agent drops the allowed_payees entry disclosure and signs sd_hash over the redacted form (upstream present())
p = dict(cpay); p.pop("vct")
pc = mc.present(holder_key=K["agent"], mandate_token=open_payment, payloads=[PaymentMandate(**p)],
                claims_to_disclose={k: True for k in p}, nonce=pay_nonce, aud="credential-provider")
case("K6_payee_disclosure_withheld_resigned", "agent presents open payment without the allowed_payees entry (SDK claims_to_disclose)",
     mod(payment_mandate=pc, payment_receipt=sign_payment_receipt(pc)))

case("K7_error_receipt", "processor signs a status=Error payment receipt",
     mod(payment_receipt=sign_payment_receipt(B["payment_mandate"], status="Error", error="declined",
                                              error_description="card declined", psp_confirmation_id=None,
                                              network_confirmation_id=None)))
case("K8_wrong_expected_nonce", "verifier pins a different payment nonce", extra_args=["--expect-payment-nonce", "deadbeef"])

for cid, c in cases.items():
    d = outdir / cid; d.mkdir(parents=True, exist_ok=True)
    (d / "bundle.json").write_text(json.dumps(c["bundle"], indent=2), encoding="utf-8")
    (d / "trusted_keys.json").write_text(json.dumps(c["trusted"], indent=2), encoding="utf-8")
    (d / "args.txt").write_text(" ".join(c["args"]), encoding="utf-8")
    (d / "desc.txt").write_text(c["desc"], encoding="utf-8")
print("\n".join(cases))
