"""Variant transactions minted with the upstream AP2 SDK (e1ea56d), exercising SDK options
the samples' default path does not use. Every token comes from an upstream SDK function.

usage: python mint_variants.py OUTDIR key=value ...
  flow=card|x402            payment instrument (as mandate_tools.py)
  hash_mode=sd_hash|issuer_jwt_hash   MandateClient.present(hash_mode=...)
  extras=1                  add budget / agent_recurrence / execution_date / allowed_pisps constraints,
                            a pisp and execution_date in the closed payment mandate, preset payee
  currency=USD|JPY|KWD      currency of the transaction
  redact=1                  closed checkout presented with claims_to_disclose={'checkout_jwt':...}
  hp=1                      human-present: closed mandates signed directly by the user key (shopping_agent/tools.py)
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
    AgentRecurrence, AllowedPayees, AllowedPaymentInstruments, AllowedPisps, AmountRange, Budget,
    ExecutionDate, Frequency, OpenPaymentMandate, PaymentReference,
)
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.pisp import PISP
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.sdjwt import compute_sd_hash, parse_token
from ap2.sdk.utils import compute_sha256_b64url

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
opt = dict(a.split("=", 1) for a in sys.argv[2:])
flow = opt.get("flow", "card"); hash_mode = opt.get("hash_mode", "sd_hash")
extras = opt.get("extras") == "1"; cur = opt.get("currency", "USD")
redact = opt.get("redact") == "1"; hp = opt.get("hp") == "1"
log = {"options": opt}


def gen_key(kid=None):
    key = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    if kid:
        d = json.loads(key.export()); d["kid"] = kid; key = JWK.from_json(json.dumps(d))
    return key


issuer_key = gen_key("user-key-1" if hp else "agent-provider-key-1")
agent_key = gen_key()
merchant_key = gen_key("merchant-key-1")
mpp_key = gen_key("merchant-payment-processor-key-1")

DEMO_MERCHANT = Merchant(id="merchant_1", name="Demo Merchant", website="https://demo-merchant.example")
PSP = PISP(legal_name="Demo PSP Ltd", brand_name="DemoPay", domain_name="pay.demo-psp.example")
MERCHANT_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
FACILITATOR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
INSTRUMENT = (PaymentInstrument(type="x402", id="x402-base-sepolia-usdc", description="0x7099...79C8",
                                payee_address=MERCHANT_ADDR, facilitator=FACILITATOR)
              if flow == "x402" else PaymentInstrument(type="card", id="stub", description="Card 4242"))

client = MandateClient()
now = int(time.time()); ttl = 3600
item_id, item_name, qty = "sku_red_shoe", "Red Shoe", 2
unit_price = {"USD": 4999, "JPY": 4999, "KWD": 15250}[cur]   # minor units
total_amount = unit_price * qty
cap_major = {"USD": 150.0, "JPY": 15000.0, "KWD": 40.0}[cur]
cap_minor = {"USD": 15000, "JPY": 15000, "KWD": 40000}[cur]

# ---- merchant checkout JWT ----
checkout_payload = Checkout(
    id="cart_" + uuid.uuid4().hex[:12], merchant=DEMO_MERCHANT,
    line_items=[LineItem(id="li_0", item=Item(id=item_id, title=item_name, price=unit_price), quantity=qty,
                         totals=[Total(type="subtotal", amount=total_amount), Total(type="total", amount=total_amount)])],
    status=Status.incomplete, currency=cur,
    totals=[Total(type="subtotal", amount=total_amount), Total(type="total", amount=total_amount)],
    links=[Link(type="privacy_policy", url="https://demo-merchant.example/privacy"),
           Link(type="terms_of_service", url="https://demo-merchant.example/tos")],
).model_dump(mode="json", exclude_none=True)
checkout_jwt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"},
                          payload=checkout_payload, private_key=merchant_key)
checkout_hash = compute_sha256_b64url(checkout_jwt)

exec_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 60))
closed_payment = PaymentMandate(
    transaction_id=checkout_hash, payee=DEMO_MERCHANT, payment_amount=Amount(amount=total_amount, currency=cur),
    payment_instrument=INSTRUMENT, **({"pisp": PSP, "execution_date": exec_date} if extras else {}),
    **({"iat": now, "exp": now + ttl} if hp else {}))
closed_checkout = CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash,
                                  **({"iat": now, "exp": now + ttl} if hp else {}))
checkout_nonce = uuid.uuid4().hex; payment_nonce = uuid.uuid4().hex

if hp:
    # shopping_agent/tools.py create_checkout_mandate / create_payment_mandate
    checkout_chain = client.create(payloads=[closed_checkout], issuer_key=issuer_key)
    payment_chain = client.create(payloads=[closed_payment], issuer_key=issuer_key)
else:
    cnf = {"jwk": json.loads(agent_key.export_public())}
    open_checkout = client.create(payloads=[OpenCheckoutMandate(
        constraints=[LineItems(items=[LineItemRequirements(id="line_1",
                     acceptable_items=[OItem(id=item_id, title=item_name), OItem(id="sku_blue_shoe", title="Blue Shoe")],
                     quantity=qty)]),
                     AllowedMerchants(allowed=[DEMO_MERCHANT, Merchant(id="merchant_2", name="Other",
                                                                        website="https://other.example")])],
        cnf=cnf, iat=now, exp=now + ttl)], issuer_key=issuer_key)
    checkout_reference = compute_sd_hash(parse_token(open_checkout))
    cons = [AmountRange(currency=cur, min=0, max=cap_minor), AllowedPayees(allowed=[DEMO_MERCHANT]),
            PaymentReference(conditional_transaction_id=checkout_reference)]
    if flow == "x402":
        cons.append(AllowedPaymentInstruments(allowed=[INSTRUMENT]))
    preset = {}
    if extras:
        cons += [Budget(max=cap_major, currency=cur),
                 AgentRecurrence(frequency=Frequency.MONTHLY, max_occurrences=3),
                 ExecutionDate(not_before=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 60)),
                               not_after=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + ttl))),
                 AllowedPisps(allowed=[PSP])]
        preset = {"payee": DEMO_MERCHANT}
    try:
        open_payment = client.create(payloads=[OpenPaymentMandate(constraints=cons, cnf=cnf, iat=now,
                                                                  exp=now + ttl, **preset)], issuer_key=issuer_key)
    except Exception as e:
        log["open_payment_create_error"] = repr(e)
        # upstream create() failed (e.g. Enum claim); retry with the enum given as its string value
        cons = [c if not isinstance(c, AgentRecurrence) else
                AgentRecurrence.model_construct(type="payment.agent_recurrence", frequency="MONTHLY", max_occurrences=3)
                for c in cons]
        open_payment = client.create(payloads=[OpenPaymentMandate.model_construct(
            vct="mandate.payment.open.1", constraints=cons, cnf=cnf, iat=now, exp=now + ttl, **preset)],
            issuer_key=issuer_key)
        log["open_payment_workaround"] = "AgentRecurrence passed via model_construct with frequency='MONTHLY'"
    present_kw = {}
    if redact:
        present_kw["claims_to_disclose"] = {"checkout_jwt": True, "checkout_hash": True}
    checkout_chain = client.present(holder_key=agent_key, mandate_token=open_checkout, payloads=[closed_checkout],
                                    nonce=checkout_nonce, aud="merchant", hash_mode=hash_mode, **present_kw)
    payment_chain = client.present(holder_key=agent_key, mandate_token=open_payment, payloads=[closed_payment],
                                   nonce=payment_nonce, aud="credential-provider", hash_mode=hash_mode)
    (out / "open_checkout_as_issued.txt").write_text(open_checkout, encoding="utf-8")
    (out / "open_payment_as_issued.txt").write_text(open_payment, encoding="utf-8")

cr = ReceiptClient().create_checkout_receipt(
    merchant=DEMO_MERCHANT.website, reference=compute_sha256_b64url(client.get_closed_mandate_jwt(checkout_chain)),
    order_id="order_" + uuid.uuid4().hex[:12])
checkout_receipt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"},
                              payload=cr.model_dump(), private_key=merchant_key)
pr = ReceiptClient().create_payment_receipt(
    payment_mandate_content=closed_payment,
    reference=compute_sha256_b64url(client.get_closed_mandate_jwt(payment_chain)))
payment_receipt = create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": mpp_key.kid},
                             payload=pr.model_dump(), private_key=mpp_key)

# ---- upstream SDK self-verification ----
pk = lambda _t: JWK.from_json(issuer_key.export_public())
try:
    if hp:
        ipub = JWK.from_json(issuer_key.export_public())
        log["sdk_checkout_verify"] = str(client.verify(token=checkout_chain, key_or_provider=ipub,
                                                       payload_type=CheckoutMandate))[:200]
        log["sdk_payment_verify"] = str(client.verify(token=payment_chain, key_or_provider=ipub,
                                                      payload_type=PaymentMandate))[:200]
    else:
        p = client.verify(token=checkout_chain, key_or_provider=pk, expected_aud="merchant", expected_nonce=checkout_nonce)
        log["sdk_checkout_violations"] = CheckoutMandateChain.parse(p).verify(expected_checkout_hash=checkout_hash,
                                                                             checkout_jwt=checkout_jwt)
except Exception as e:
    log["sdk_checkout_error"] = repr(e)
if not hp:
    try:
        p = client.verify(token=payment_chain, key_or_provider=pk, expected_aud="credential-provider",
                          expected_nonce=payment_nonce)
        log["sdk_payment_violations"] = PaymentMandateChain.parse(p).verify(
            expected_transaction_id=checkout_hash,
            expected_open_checkout_hash=compute_sd_hash(parse_token(checkout_chain.split("~~")[0] + "~")))
    except Exception as e:
        log["sdk_payment_error"] = repr(e)

pub = lambda k: json.loads(k.export_public())
trusted = {"mandate_issuer": [pub(issuer_key)], "merchant": [pub(merchant_key)], "payment_processor": [pub(mpp_key)]}
bundle = {"bundle_version": "ap2-evidence/1", "checkout_mandate": checkout_chain, "payment_mandate": payment_chain,
          "checkout_receipt": checkout_receipt, "payment_receipt": payment_receipt,
          "note": f"minted by upstream AP2 SDK e1ea56d, options={opt}"}
if not hp:
    bundle["expected"] = {"checkout": {"aud": "merchant", "nonce": checkout_nonce},
                          "payment": {"aud": "credential-provider", "nonce": payment_nonce}}
(out / "bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
(out / "trusted_keys.json").write_text(json.dumps(trusted, indent=2), encoding="utf-8")
(out / "private_keys.json").write_text(json.dumps({"issuer": json.loads(issuer_key.export()),
    "agent": json.loads(agent_key.export()), "merchant": json.loads(merchant_key.export()),
    "mpp": json.loads(mpp_key.export())}, indent=2), encoding="utf-8")
(out / "sdk_self_verify.json").write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")
print(json.dumps(log, indent=2, default=str))
