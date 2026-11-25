# Evidence minted by the official AP2 SDK and samples

Everything here was produced by the official AP2 Python SDK and sample code from
<https://github.com/google-agentic-commerce/AP2> at commit `e1ea56d` (v0.2.0, Apache-2.0), with
**throwaway keys generated for the run**. No production key, token or person is involved. The
private keys of the run are not in this folder (they were written to a scratch folder and
discarded); `tests/test_upstream_sdk.py` fails if any file here holds private key material.

| Folder | What it is |
| --- | --- |
| `samples_hnp_card/` | The human-not-present card flow of the official samples (`code/samples/python`), driven in-process by `scripts/drive_samples.py`: the real tool functions of the shopping agent, merchant, credentials provider and payment processor, with only the LLM and the HTTP hops replaced. `bundle.json` was assembled by hand from their outputs; `checkout_receipt.jwt` / `payment_receipt.jwt` are the receipts the merchant and processor returned. |
| `samples_hnp_card/temp-db/` | The folder the samples wrote (`TEMP_DB_DIR`), exactly as written except that the `*.pem` files (the samples' private JWKs) were not copied and line endings of the JSON files were normalised. Used by the `pack --from-ap2-sample-db` test. |
| `card/`, `x402/` | A full transaction minted with SDK calls only (`MandateClient.create/present`, `jwt_helper.create_jwt`, `ReceiptClient`) along the sample code paths, by `scripts/mint_upstream.py`. |
| `v_issuerhash/`, `v_extras_usd/`, `v_extras_jpy/`, `v_extras_kwd/`, `v_hp/`, `v_redact/` | Variants by `scripts/mint_variants.py`: receipt `reference` as issuer-JWT hash, extra checkout fields in three currencies (2, 0 and 3 decimals), the human-present one-segment flow, and open mandates presented with constraints redacted (`claims_to_disclose`). |
| `tamper/` | 21 dispute scenarios by `scripts/tamper.py`, built from `card/` (and `x402/` as "another transaction") with the run's keys: re-signed forgeries (K*) and edits without re-signing (N*). `desc.txt` says what was done; `args.txt` holds the extra `verify` arguments the case needs (only K8: a pinned nonce). |
| `probes/` | The unsigned receipt shapes other sample flows return, put into a bundle (`scripts/probes.py`). |
| `loose/` | The `card/` transaction as separate token files plus its public keys as PEM, and the x402 PSP's unsigned settlement object, for the `pack` examples in `docs/getting-evidence-in.md`. Written by `scripts/collect_fixtures.py`. |

Each case folder has `bundle.json` and `trusted_keys.json` (the run's public keys by role). The
expected verdicts and failing check IDs are in `tests/test_upstream_sdk.py`.

## Regenerating

Needs a clone of the AP2 repository at `e1ea56d` and a virtual environment with the upstream SDK
and the samples' dependencies installed (`pip install -e code/sdk/python`, plus the samples'
requirements). Then, from this folder:

```powershell
powershell -File scripts\regenerate.ps1 -Upstream C:\src\AP2 -SdkPython C:\venvs\ap2sdk\Scripts\python.exe -Out C:\tmp\ap2-interop-out
```

`regenerate.ps1` runs the minting scripts into `-Out` (which receives the throwaway private keys:
keep it outside the repository and delete it afterwards) and then `collect_fixtures.py`, which
copies only public material here and stops if a file holds private key material. New keys,
nonces and timestamps are generated on every run, so the files change, but the verdicts in
`tests/test_upstream_sdk.py` must not.

The `.py` minting scripts in `scripts/` are kept exactly as they were run and are excluded from
linting (`scripts/ruff.toml`). `regenerate.ps1` replaces the two local driver scripts of the
original run, which held machine-specific paths.
