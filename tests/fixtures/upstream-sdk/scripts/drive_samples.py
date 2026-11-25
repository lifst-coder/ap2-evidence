"""Drive the upstream HNP *card* sample roles in-process, without an LLM and without HTTP.

Calls the real tool functions of:
  shopping_agent_v2/shopping_agent/mandate_tools.py  assemble_and_sign_mandates, create_checkout_presentation,
                                                     create_payment_presentation
  merchant_agent_mcp/server.py                        check_product, assemble_cart, create_checkout, complete_checkout
  credentials_provider_mcp/server.py                  issue_payment_credential, verify_payment_receipt
  merchant_payment_processor_mcp/server.py            initiate_payment
Glue written here (not upstream): the LLM's role of passing values between tools, a fake ADK ToolContext,
a trigger-state file that puts the item in stock, and two monkeypatches that replace the HTTP hops
(merchant -> processor, processor -> credentials provider) with direct calls.

usage: python drive_samples.py UPSTREAM_CLONE OUTDIR
"""
import asyncio, importlib.util, json, os, sys, uuid
from pathlib import Path

clone, out = Path(sys.argv[1]), Path(sys.argv[2])
temp_db = out / "temp-db"; temp_db.mkdir(parents=True, exist_ok=True)
os.environ.update({"TEMP_DB_DIR": str(temp_db), "FLOW": "card", "LOGS_DIR": str(out / "logs"),
                   "AP2_TOKEN_STORE_PATH": str(temp_db / "ap2_token_store.json"),
                   "MERCHANT_TRIGGER_STATE_PATH": str(temp_db / "merchant_trigger_state.json")})
src = clone / "code" / "samples" / "python" / "src"
sys.path.insert(0, str(src))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, src / rel)
    m = importlib.util.module_from_spec(spec); sys.modules[name] = m; spec.loader.exec_module(m); return m


def fn(t):  # fastmcp @mcp.tool() may wrap the function
    return getattr(t, "fn", t)


mt = load("sa_mandate_tools", "roles/shopping_agent_v2/shopping_agent/mandate_tools.py")
merchant = load("merchant_server", "roles/merchant_agent_mcp/server.py")
cp = load("cp_server", "roles/credentials_provider_mcp/server.py")
mpp = load("mpp_server", "roles/merchant_payment_processor_mcp/server.py")


class Ctx:  # stands in for google.adk ToolContext
    def __init__(self): self.state = {}


log = {}
captured = {}


async def fake_initiate(payment_token, checkout_jwt_hash, open_checkout_hash):
    return await fn(mpp.initiate_payment)(payment_token, checkout_jwt_hash, open_checkout_hash)


async def fake_send(receipt):
    captured["payment_receipt"] = receipt


merchant._initiate_payment_with_payment_processor = fake_initiate
mpp._send_payment_receipt_to_credentials_provider = fake_send


async def main():
    item_id = "red_running_shoe_0"
    prod = fn(merchant.check_product)(item_id, 150.0); log["check_product"] = prod
    (temp_db / "merchant_trigger_state.json").write_text(json.dumps({item_id: {"price": prod["price"], "stock": 5}}))
    cart = fn(merchant.assemble_cart)(item_id, 1); log["cart"] = cart
    mand = mt.assemble_and_sign_mandates({"item_id": item_id, "item_name": "Red running shoe",
                                          "price_cap": 150.0, "qty": 1}); log["mandates"] = mand
    ctx = Ctx(); ctx.state["app:open_checkout_mandate_id"] = mand["open_checkout_mandate"]
    ctx.state["app:open_payment_mandate_id"] = mand["open_payment_mandate"]
    chk = fn(merchant.create_checkout)(cart["cart_id"], mand["open_checkout_mandate"])
    log["create_checkout"] = {k: (v[:40] + "...") if isinstance(v, str) else v for k, v in chk.items()}
    checkout_nonce = uuid.uuid4().hex; payment_nonce = uuid.uuid4().hex
    cpres = mt.create_checkout_presentation(chk["checkout_jwt"], chk["checkout_jwt_hash"], checkout_nonce,
                                            tool_context=ctx); log["checkout_presentation"] = cpres
    ppres = mt.create_payment_presentation(chk["checkout_jwt_hash"], cart["total"], payment_nonce,
                                           payee_json=json.dumps({"id": "merchant_1", "name": "Demo Merchant",
                                                                  "website": "https://demo-merchant.example"}),
                                           tool_context=ctx); log["payment_presentation"] = ppres
    cred = fn(cp.issue_payment_credential)(ppres["payment_mandate_chain_id"] if "payment_mandate_chain_id" in ppres
                                           else ppres.get("payment_mandate"), chk["open_checkout_hash"],
                                           chk["checkout_jwt_hash"], payment_nonce)
    log["issue_payment_credential"] = cred
    done = await fn(merchant.complete_checkout)(cred["payment_token"], cpres["checkout_mandate_chain_id"],
                                                checkout_nonce)
    log["complete_checkout"] = {k: (v[:40] + "...") if isinstance(v, str) else v for k, v in done.items()}
    log["cp_verify_payment_receipt"] = fn(cp.verify_payment_receipt)(captured["payment_receipt"])

    rd = lambda p: (temp_db / p).read_text(encoding="ascii").strip()
    pub = lambda p: json.loads((temp_db / p).read_text(encoding="utf-8"))
    bundle = {"bundle_version": "ap2-evidence/1",
              "checkout_mandate": rd(cpres["checkout_mandate_chain_id"] + ".sdjwt"),
              "payment_mandate": rd(ppres["payment_mandate_chain_id"] + ".sdjwt"),
              "checkout_receipt": done["checkout_receipt"], "payment_receipt": captured["payment_receipt"],
              "expected": {"checkout": {"aud": "merchant", "nonce": checkout_nonce},
                           "payment": {"aud": "credential-provider", "nonce": payment_nonce}},
              "note": "produced by upstream HNP card sample role functions (e1ea56d), driven in-process"}
    trusted = {"mandate_issuer": [pub("agent_provider_signing_key.pub")],
               "merchant": [pub("merchant_signing_key.pub")],
               "payment_processor": [pub("merchant_payment_processor_signing_key.pub")]}
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    (out / "trusted_keys.json").write_text(json.dumps(trusted, indent=2), encoding="utf-8")


try:
    asyncio.run(main())
finally:
    (out / "drive_log.json").write_text(json.dumps(log, indent=2, default=str), encoding="utf-8")
    print(json.dumps(log, indent=2, default=str))
