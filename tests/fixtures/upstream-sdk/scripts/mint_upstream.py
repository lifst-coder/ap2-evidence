"""Mint a complete AP2 v0.2 HNP transaction using ONLY the upstream AP2 Python SDK.

Mirrors the upstream sample code paths (commit e1ea56d):
  shopping_agent_v2/shopping_agent/mandate_tools.py  (open mandates, closed presentations)
  merchant_agent_mcp/server.py                       (checkout_jwt, checkout receipt)
  merchant_payment_processor_mcp/server.py           (payment receipt)
but without ADK/MCP/A2A plumbing. Every token is produced by an upstream SDK function
(MandateClient.create / .present, jwt_helper.create_jwt, ReceiptClient.create_*).
This script only generates keys, chooses demo values, and writes the bundle.

usage: python mint_upstream.py OUTDIR [card|x402]
"""
import json
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants, Item as OItem, LineItemRequirements, LineItems, OpenCheckoutMandate,
)
from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees, AllowedPaymentInstruments, AmountRange, OpenPaymentMandate, PaymentReference,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.sdjwt import compute_sd_hash, parse_token
from ap2.sdk.utils import compute_sha256_b64url

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
flow = sys.argv[2] if len(sys.argv) > 2 else "card"


def gen_key(kid=None):
    # same construction as mandate_tools._get_agent_provider_signing_key
    key = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    if kid:
        d = json.loads(key.export()); d["kid"] = kid; key = JWK.from_json(json.dumps(d))
    return key


agent_provider_key = gen_key("agent-provider-key-1")   # mandate issuer
agent_key = gen_key()                                   # shopping agent (no kid, as sample)
merchant_key = gen_key("merchant-key-1")
mpp_key = gen_key("merchant-payment-processor-key-1")

DEMO_MERCHANT = Merchant(id="merchant_1", name="Demo Merchant", website="https://demo-merchant.example")
MERCHANT_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FACILITATOR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
if flow == "x402":
    INSTRUMENT = PaymentInstrument(type="x402", id="x402-base-sepolia-usdc",
                                   description=f"{MERCHANT_ADDR[:6]}...{MERCHANT_ADDR[-4:]}",
                                   payee_address=MERCHANT_ADDR, facilitator=FACILITATOR)
else:
    INSTRUMENT = PaymentInstrument(type="card", id="stub", description="Card ••••4242")

client = MandateClient()
now = int(time.time()); ttl = 3600
item_id, item_name, unit_price, qty = "sku_red_shoe", "Red Shoe", 4999, 2
total_amount = unit_price * qty
price_cap = 150.00

# ---- 1. open checkout mandate (mandate_tools._build_open_checkout_mandate) ----
agent_pub = JWK.from_json(agent_key.export_public())
cnf = {"jwk": json.loads(agent_pub.export_public())}
open_checkout_model = OpenCheckoutMandate(
    constraints=[
        LineItems(items=[LineItemRequirements(id="line_1",
                  acceptable_items=[OItem(id=item_id, title=item_name)], quantity=qty)]),
        AllowedMerchants(allowed=[DEMO_MERCHANT]),
    ],
    cnf=cnf, iat=now, exp=now + ttl,
)
open_checkout = client.create(payloads=[open_checkout_model], issuer_key=agent_provider_key)
checkout_reference = compute_sd_hash(parse_token(open_checkout))

# ---- 2. open payment mandate (mandate_tools._build_open_payment_mandate) ----
constraints = [
    AmountRange(currency="USD", min=0, max=int(round(price_cap * 100))),
    AllowedPayees(allowed=[DEMO_MERCHANT]),
    PaymentReference(conditional_transaction_id=checkout_reference),
]
if flow == "x402":
    constraints.append(AllowedPaymentInstruments(allowed=[INSTRUMENT]))
open_payment_model = OpenPaymentMandate(constraints=constraints, cnf=cnf, iat=now, exp=now + ttl)
open_payment = client.create(payloads=[open_payment_model], issuer_key=agent_provider_key)

# ---- 3. merchant checkout JWT (merchant_agent_mcp/server.py create_checkout) ----
line_sub = unit_price * qty
checkout = Checkout(
    id="cart_" + uuid.uuid4().hex[:12], merchant=DEMO_MERCHANT,
    line_items=[LineItem(id="li_0", item=Item(id=item_id, title=item_name, price=unit_price),
                         quantity=qty, totals=[Total(type="subtotal", amount=line_sub),
                                               Total(type="total", amount=line_sub)])],
    status=Status.incomplete, currency="USD",
    totals=[Total(type="subtotal", amount=line_sub), Total(type="total", amount=total_amount)],
    links=[Link(type="privacy_policy", url="https://demo-merchant.example/privacy"),
           Link(type="terms_of_service", url="https://demo-merchant.example/tos")],
)
checkout_payload = checkout.model_dump(mode="json", exclude_none=True)
if flow == "x402":
    checkout_payload["accepted_payment_methods"] = [
        {"type": "x402", "address": MERCHANT_ADDR, "network": "base-sepolia", "facilitator": FACILITATOR}]
checkout_jwt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"},
                          payload=checkout_payload, private_key=merchant_key)
checkout_hash = compute_sha256_b64url(checkout_jwt)

# ---- 4. closed checkout mandate (mandate_tools.create_checkout_presentation) ----
checkout_nonce = uuid.uuid4().hex
checkout_chain = client.present(holder_key=agent_key, mandate_token=open_checkout,
                                payloads=[CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash)],
                                nonce=checkout_nonce, aud="merchant")

# ---- 5. closed payment mandate (mandate_tools.create_payment_presentation) ----
payment_nonce = uuid.uuid4().hex
payment_chain = client.present(holder_key=agent_key, mandate_token=open_payment,
                               payloads=[PaymentMandate(transaction_id=checkout_hash, payee=DEMO_MERCHANT,
                                                        payment_amount=Amount(amount=total_amount, currency="USD"),
                                                        payment_instrument=INSTRUMENT)],
                               nonce=payment_nonce, aud="credential-provider")

# ---- 6. checkout receipt (merchant_agent_mcp/server.py complete_checkout) ----
order_id = "order_" + uuid.uuid4().hex[:12]
cr_content = ReceiptClient().create_checkout_receipt(
    merchant=DEMO_MERCHANT.website,
    reference=compute_sha256_b64url(client.get_closed_mandate_jwt(checkout_chain)), order_id=order_id)
checkout_receipt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"},
                              payload=cr_content.model_dump(), private_key=merchant_key)

# ---- 7. upstream SDK self-verification (merchant / processor code paths) ----
sdk = {}
def pubfn(k):
    return lambda _t: JWK.from_json(k.export_public())
try:
    p = client.verify(token=checkout_chain, key_or_provider=pubfn(agent_provider_key),
                      expected_aud="merchant", expected_nonce=checkout_nonce)
    sdk["checkout_chain_violations"] = CheckoutMandateChain.parse(p).verify(
        expected_checkout_hash=checkout_hash, checkout_jwt=checkout_jwt)
except Exception as e:
    sdk["checkout_chain_error"] = repr(e)
pay_chain_obj = None
try:
    p = client.verify(token=payment_chain, key_or_provider=pubfn(agent_provider_key),
                      expected_aud="credential-provider", expected_nonce=payment_nonce)
    pay_chain_obj = PaymentMandateChain.parse(p)
    sdk["payment_chain_violations"] = pay_chain_obj.verify(
        expected_transaction_id=checkout_hash,
        expected_open_checkout_hash=compute_sd_hash(parse_token(checkout_chain.split("~~")[0] + "~")))
except Exception as e:
    sdk["payment_chain_error"] = repr(e)

# ---- 8. payment receipt (merchant_payment_processor_mcp/server.py initiate_payment) ----
closed_pm = pay_chain_obj.closed_mandate if pay_chain_obj else PaymentMandate(
    transaction_id=checkout_hash, payee=DEMO_MERCHANT,
    payment_amount=Amount(amount=total_amount, currency="USD"), payment_instrument=INSTRUMENT)
pr_content = ReceiptClient().create_payment_receipt(
    payment_mandate_content=closed_pm,
    reference=compute_sha256_b64url(client.get_closed_mandate_jwt(payment_chain)))
payment_receipt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": mpp_key.kid},
                             payload=pr_content.model_dump(), private_key=mpp_key)

refs = {compute_sha256_b64url(client.get_closed_mandate_jwt(checkout_chain)),
        compute_sha256_b64url(client.get_closed_mandate_jwt(payment_chain))}
for name, tok, k, isp in (("checkout_receipt", checkout_receipt, merchant_key, False),
                          ("payment_receipt", payment_receipt, mpp_key, True)):
    for kname, kk in (("jwk", JWK.from_json(k.export_public())),
                      ("pyca_ec", JWK.from_json(k.export_public()).get_op_key("verify"))):
        try:
            sdk[f"{name}_verify_{kname}"] = ReceiptClient().verify_receipt(
                tok, kk, has_reference_in_store_cb=lambda r: r in refs, is_payment_receipt=isp)
        except Exception as e:
            sdk[f"{name}_verify_{kname}"] = "EXC " + repr(e)

pub = lambda k: json.loads(k.export_public())
trusted = {"mandate_issuer": [pub(agent_provider_key)], "merchant": [pub(merchant_key)],
           "payment_processor": [pub(mpp_key)]}
bundle = {
    "bundle_version": "ap2-evidence/1",
    "checkout_mandate": checkout_chain, "payment_mandate": payment_chain,
    "checkout_receipt": checkout_receipt, "payment_receipt": payment_receipt,
    "expected": {"checkout": {"aud": "merchant", "nonce": checkout_nonce},
                 "payment": {"aud": "credential-provider", "nonce": payment_nonce}},
    "note": f"minted by upstream AP2 SDK e1ea56d, flow={flow}",
}
(out / "bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
(out / "trusted_keys.json").write_text(json.dumps(trusted, indent=2), encoding="utf-8")
(out / "private_keys.json").write_text(json.dumps({
    "agent_provider": json.loads(agent_provider_key.export()), "agent": json.loads(agent_key.export()),
    "merchant": json.loads(merchant_key.export()), "mpp": json.loads(mpp_key.export())}, indent=2), encoding="utf-8")
(out / "sdk_self_verify.json").write_text(json.dumps(sdk, indent=2, default=str), encoding="utf-8")
(out / "open_checkout_as_issued.txt").write_text(open_checkout, encoding="utf-8")
(out / "open_payment_as_issued.txt").write_text(open_payment, encoding="utf-8")
print(json.dumps(sdk, indent=2, default=str))
print("written", out)
