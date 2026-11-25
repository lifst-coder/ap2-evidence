"""Extra probes built from upstream outputs (base = out/card).

P1/P2/P3: payment "receipts" in the shapes other upstream sample flows actually emit:
  P1 x402_psp_mcp/server.py:331-339  -> unsigned {"transaction_id","status":"SETTLED","settled_at"} object
  P2 merchant_payment_processor_agent/tools.py:203-218 -> unsigned PaymentReceipt.model_dump() dict
  P3 same as P2 but serialized to a JSON string
P4: three-segment chain via MandateClient.present() with an intermediate open hop (SDK README: arbitrary depth)
usage: python probes.py BASEDIR OUTDIR
"""
import base64, copy, json, sys, uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.utils import compute_sha256_b64url

base, outdir = Path(sys.argv[1]), Path(sys.argv[2])
B = json.loads((base / "bundle.json").read_text(encoding="utf-8"))
T = json.loads((base / "trusted_keys.json").read_text(encoding="utf-8"))
K = {k: JWK.from_json(json.dumps(v)) for k, v in
     json.loads((base / "private_keys.json").read_text(encoding="utf-8")).items()}
open_payment = (base / "open_payment_as_issued.txt").read_text(encoding="utf-8")
mc = MandateClient()
b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
pr_payload = json.loads(b64d(B["payment_receipt"].split(".")[1]))
out = {}

b = copy.deepcopy(B); b["payment_receipt"] = {"transaction_id": "0x" + uuid.uuid4().hex, "status": "SETTLED",
                                              "settled_at": pr_payload["iat"]}
out["P1_x402_psp_receipt_object"] = b
b = copy.deepcopy(B); b["payment_receipt"] = pr_payload; out["P2_unsigned_receipt_dict"] = b
b = copy.deepcopy(B); b["payment_receipt"] = json.dumps(pr_payload); out["P3_unsigned_receipt_json_string"] = b

# P4: user -> agent A (intermediate, open payload with cnf of agent B) -> agent B closes
log = {}
try:
    agent_b = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    disc = [json.loads(b64d(d)) for d in open_payment.rstrip("~").split("~")[1:]]
    om = next(v[1] for v in disc if isinstance(v[1], dict) and v[1].get("vct") == "mandate.payment.open.1")
    digests = {compute_sha256_b64url(d): json.loads(b64d(d))[-1] for d in open_payment.rstrip("~").split("~")[1:]}
    def res(x):
        if isinstance(x, list):
            return [res(digests.get(e["..."], e) if isinstance(e, dict) and "..." in e else e) for e in x]
        if isinstance(x, dict):
            return {k: res(v) for k, v in x.items()}
        return x
    om = res(om); om["cnf"] = {"jwk": json.loads(agent_b.export_public())}
    hop1 = mc.present(holder_key=K["agent"], mandate_token=open_payment, payloads=[OpenPaymentMandate.model_validate(om)],
                      nonce="n1", aud="agent-b")
    cp = next(json.loads(b64d(d))[1] for d in B["payment_mandate"].split("~~")[-1].rstrip("~").split("~")[1:]
              if isinstance(json.loads(b64d(d))[1], dict))
    cp.pop("vct")
    hop2 = mc.present(holder_key=agent_b, mandate_token=hop1, payloads=[PaymentMandate(**cp)],
                      nonce=B["expected"]["payment"]["nonce"], aud="credential-provider")
    pk = JWK.from_json(K["agent_provider"].export_public())
    try:
        log["sdk_verify_3hop"] = str(mc.verify(token=hop2, key_or_provider=lambda _t: pk,
                                               expected_aud="credential-provider",
                                               expected_nonce=B["expected"]["payment"]["nonce"]))[:300]
    except Exception as e:
        log["sdk_verify_3hop_error"] = repr(e)
    pl = dict(pr_payload); pl["reference"] = compute_sha256_b64url(mc.get_closed_mandate_jwt(hop2))
    b = copy.deepcopy(B); b["payment_mandate"] = hop2
    b["payment_receipt"] = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-payment-processor-key-1"},
                                      pl, K["mpp"])
    out["P4_three_hop_payment_chain"] = b
    log["segments"] = len(hop2.split("~~"))
except Exception as e:
    log["P4_mint_error"] = repr(e)

for cid, bb in out.items():
    d = outdir / cid; d.mkdir(parents=True, exist_ok=True)
    (d / "bundle.json").write_text(json.dumps(bb, indent=2), encoding="utf-8")
    (d / "trusted_keys.json").write_text(json.dumps(T, indent=2), encoding="utf-8")
    (d / "args.txt").write_text("", encoding="utf-8"); (d / "desc.txt").write_text(cid, encoding="utf-8")
(outdir / "probes_log.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
print(json.dumps(log, indent=2))
