# Output formats

`ap2-evidence verify` and `ap2-evidence demo` take `--format text|md|json|issue|html`
(default `text`). `--out FILE` writes the output as UTF-8 and prints one line on stderr:
`wrote FILE (VERDICT: ...)`.

## text, md and html

All three follow the same reading order, written for a payment-dispute analyst who does not
need to know SD-JWT:

1. **Verdict** with where the keys came from (see below).
2. **Conclusion**:
   - *Finding*: one or two short sentences that lead with the facts, e.g. "The agent paid
     USD 250.00 to Demo Merchant for checkout 'demo-checkout-0001'. The user's mandate allowed
     at most USD 200.00, and the merchant's signed checkout was for USD 199.00." The merchant is
     named as in the merchant-signed checkout; if the agent-signed payment mandate describes
     the payee differently, the finding says so. "Paid" is used only when an authentic Success
     Payment Receipt for this payment mandate exists; otherwise the finding says the agent
     approved a payment and that nothing in the bundle shows it was processed. When the agent's
     signature on the payment approval does not verify (PM08), the payment is not attributed
     to the agent: "The payment concerned: USD 199.00 to Demo Merchant for checkout '...',
     approved with a key that is not the agent key the user authorised." A VERIFIED
     finding with warnings says so ("..., with 2 warnings to review: ...").
   - *What this means* for the evidence: for FAILED, that the bundle cannot be used to show the
     payment was authorised and, where the failing check makes it clear, whose claim it
     undermines; for VERIFIED, what was shown and what was not (who the keys belong to,
     delivery, other payments) plus one sentence per warning; for INCOMPLETE, which things
     could not be checked and what is already shown ("nothing contradicts the claim" is not
     said when a required check could not run because a link does not match, e.g. PM31
     `reference_unverifiable_withheld`). A result that rests on history figures given with
     `--prior-total` / `--prior-uses` says so.
   - *What to do next*: concrete steps derived from the failing, not-verified and warning
     results (each reason code has one, see `docs/checks.md`; unknown codes get a generic
     line).
   - *About the keys*: the key-trust caveat in plain words.
   The conclusion names no key thumbprints and no check IDs; the evidence chain lists every key
   once with its full thumbprint and what it verified (and, for an agent key, which closed
   mandate it did NOT sign). Hints shown to the reader name command-line options
   (`--issuer-key`, `--expect-total`, `--prior-total`, ...); the JSON `hint` keeps the
   original text, which may name API arguments.
3. **Broken links**: every FAIL, each with a plain sentence first ("What is wrong"), then the
   technical detail, where to look, what the check is for and the reason code. Nothing in the
   conclusion or a broken-link entry is truncated. Failures that follow from another failure
   (see *Root causes* below) are listed under it as consequences.
4. **Not verified and warnings**: required SKIPs (grouped by cause: checks that could not run
   because an earlier check failed or was incomplete are listed on one line) and WARNs, again
   plain sentence first.
5. **Evidence chain** in plain words.
6. **All checks** (in HTML a technical appendix on its own page, with the `inspect` pointer).
7. **Limits** of the tool.
8. **Glossary** containing only the terms that occur in that report (open / closed mandate,
   segment, disclosure, key binding, pinned key, checkout_hash, receipt reference, ...).

The first lines of the text report (here of `ap2-evidence demo`, 86 checks) are:

```text
AP2 evidence report (ap2-evidence 0.1.0, AP2 v0.2)
==================================================
VERDICT: VERIFIED (keys: supplied in bundle, not pinned)
Checks: pass 74, fail 0, warn 0, skip 12
```

The part in parentheses says where the keys that verified the mandate issuer's, merchant's
and payment processor's signatures came from:

| Text | JSON `key_trust` | Meaning |
| --- | --- | --- |
| `keys: pinned` | `pinned` | Every role signature that was checked used a key from `--trusted-keys`. |
| `keys: supplied in bundle, not pinned` | `bundle` | Every one used a key from inside the bundle (self-asserted by whoever assembled it). |
| `keys: mixed - pinned for ...; supplied in bundle for ...` | `mixed` | Some roles pinned, some not. |
| `keys: none used, ...` | `none` | No role signature was checked (no keys supplied). |

The verdict is followed by ` - PAYMENT DECLINED` or ` - RECEIPTS DISAGREE` when the receipts
say so (JSON `outcome`, the verdict and exit code are unchanged). A receipt *counts* only when
its signature, required fields, reference and time checks passed (payment receipt PR02, PR03,
PR04, PR06; checkout receipt CR02, CR03, CR04, CR06). Both accepted receipt forms count the same
way: a receipt in the AP2 prose form (`result: success|error`) passes PR03/CR03 with the
`prose_receipt_form` warning, and because that form defines no `iat`, its PR06/CR06 is not
applicable instead of passed. The issuer plausibility checks PR07/CR07 are warnings only and do
not decide whether a receipt counts (a receipt's `iss` is self-declared; what matters is which
key signed it); a PR07/CR07 warning is listed in the finding like any other warning. When the
outcome is `declined` or `conflicting`, the decline is the headline of the finding and is not
listed again as a warning to review.

| JSON `outcome` | When |
| --- | --- |
| `success` | The Payment Receipt counts and says Success, and the Checkout Receipt is absent or counts and says Success. |
| `declined` | The Payment Receipt counts and says the payment was declined (and the Checkout Receipt does not say otherwise). |
| `conflicting` | Both receipts count and one says success while the other reports an error. |
| `unknown` | Anything else, e.g. no counting Payment Receipt, or a Checkout Receipt that is present but does not count. |

The agent key always comes from the open mandate's `cnf.jwk` and is not counted here.

### Root causes

One manipulation often makes several checks fail. A failed check is shown as a consequence of
another (JSON: `caused_by`) only under these rules (`CAUSE_RULES` in `report.py`):

| Primary failure | Primary reasons | Failures marked as its consequences |
| --- | --- | --- |
| CM04 | `unreferenced_disclosure`, `duplicate_disclosure` | CM09, CM17, CM18, CM21, CM22, CM34, CM35, PM31 |
| PM04 | same | PM09, PM17, PM18, PM21, PM22, PM31-PM38 |
| CM10 | same | CM11-CM13, CM18, CM30-CM35, PM30, XC01, XC02 |
| PM10 | same | PM11-PM13, PM18, PM30, PM32-PM38, XC01, XC02 |
| CM31 | `hash_mismatch` | PM30 |

The primary reasons prove that the data the dependent checks read was altered after it was
signed (the open or closed mandate as presented is not the one issued; or checkout_hash
differs from the checkout JWT, so PM30 cannot pass), so their results are about altered data.
Signature failures are never primaries, because a wrong key does not alter content. A check
that failed with a violation found in its own data (over the limit, payee not allowed, amount
or payee mismatch, ...) is never shown as a consequence, even when it is listed under a rule:
both failures are then primary, and the conclusion names both parties. Anything not covered by
a rule is shown as an independent failure. Consequences are still listed in
full and counted, and the JSON report still lists every failed check.

### Untrusted values

Text output escapes control characters (ANSI sequences, bidirectional overrides), collapses
runs of whitespace and caps the length of every value taken from a token; when it shortens a
value it cuts at a word boundary and appends `...`. Only headings and the verdict line start
at column 0, all body text is indented, and a wrapped continuation line that would start like
one of the report's own labels (`VERDICT`, `Finding:`, `[FAIL]`, `- `, ...) is prefixed with
`| `. The bundle's free-text `note` is shown, quoted and labelled as not verified. Markdown output escapes Markdown metacharacters and
puts URLs and e-mail addresses from the data in code spans (trailing punctuation such as a
closing parenthesis stays outside) so they are not rendered as links.

### html

`--format html` writes one self-contained page for a dispute file or for printing to PDF from
a browser: inline CSS only, no JavaScript, no external fonts, images or links, and a
Content-Security-Policy (`default-src 'none'`) so that nothing is loaded even if the file is
opened from a web server. It respects `prefers-color-scheme`, is readable on a phone, and
prints on A4 or Letter without dark backgrounds (sections avoid page breaks inside entries;
the check table is a plain technical appendix that starts on a new page). Every
value from the bundle is escaped (control characters made visible, then HTML-escaped), never
placed in an attribute, and never turned into a link. The footer gives the tool version, the
AP2 version, the generation time (UTC), the SHA-256 of each artifact as supplied, and the
SHA-256 of the input bundle file when the caller set `Report.source_sha256`.

## json

Fixed by `src/ap2_evidence/schemas/report.schema.json` (installed with the package). Top-level
members: `schema_version`, `tool`, `ap2_spec`, `generated_at`, `verdict`, `outcome`,
`key_trust`,
`summary`, `conclusion`, `finding`, `meaning`, `next_steps`, `broken_links`, `not_verified`,
`warnings`, `evidence`, `checks`, `limits`, `inputs`, `options`.

`conclusion` is one string: the verdict, the finding, what it means and the key-trust caveat.
`finding` and `meaning` are those parts on their own, and `next_steps` is the list of steps.
Each `broken_links` entry has `id`, `title`, `reason`, `what`, `why` (what the check is for),
`where` and `caused_by` (the root failure's check ID, or `null` when the failure is
independent; see *Root causes*). The evidence section may contain `keys`: every key that
was used, with its role, full thumbprint, what it verified (`used_for`), what it was expected
to but did not verify (`failed_for`) and where it came from; and `note`, the bundle's free text.
Every check object has `id`, `group`, `title`, `status`, `required`, `detail`, `hint`,
`expected`, `actual`, `spec_ref`, `blocked_by`, `key_provenance` and `reason`.

`reason` is `null` for PASS and a short snake_case code otherwise. Codes are stable; new ones
may be added. Generic codes:

| Code | Meaning |
| --- | --- |
| `blocked` | SKIP because the check named in `blocked_by` did not pass. |
| `missing_artifact` | SKIP because the artifact is not in the bundle. |
| `not_applicable` | SKIP, not required: the check does not apply to this input. |
| `no_key` / `x5c_unsupported` | SKIP: no key of the role was supplied (or only an x5c chain). |
| `internal_error` | FAIL: the check could not be evaluated on this input (please report). |

Check-specific codes (see `docs/checks.md` for the checks and for the plain wording and next
step of every code): `parse_error`,
`alg_not_allowed`, `signature_invalid`, `unreferenced_disclosure`, `duplicate_disclosure`,
`digest_reused`, `disclosure_kind_mismatch`, `claim_collision`, `bad_digest`,
`sd_not_array`, `nested_too_deep`, `unsupported_sd_alg`, `no_mandate_object`,
`multiple_mandate_objects`, `wrong_vct`, `no_cnf_jwk`, `invalid_cnf_jwk`, `wrong_typ`,
`intermediate_typ`, `typ_variant`, `binding_claim_count`, `binding_mismatch`, `cnf_in_closed`,
`missing_field`, `wrong_type`, `aud_mismatch`, `nonce_mismatch`, `aud_missing`,
`nonce_missing`, `no_expected_value`,
`no_kb_iat`, `iat_not_integer`, `signed_before_open`, `signed_after_expiry`,
`open_iat_after_exp`, `after_closed_exp`, `unknown_constraint_type`, `preset_claim_changed`,
`no_at`, `not_valid_at`, `delegation_unsupported`, `malformed_constraint`,
`missing_required_constraint`, `no_constraints`, `hidden_constraint`, `withheld_claim`,
`no_constraint`, `too_large`, `checkout_jwt_missing`, `not_jws`, `payload_not_object`,
`hash_mismatch`, `checkout_hash_missing`, `not_ascii`, `malformed_checkout`, `not_ucp`,
`checkout_canceled`, `checkout_not_final`, `merchant_not_allowed`,
`payee_not_allowed`, `none_revealed`, `no_merchant`, `merchant_unreadable`,
`line_items_unreadable`, `item_not_acceptable`, `quantity_exceeded`, `requirement_unfilled`,
`too_many_lines`, `transaction_id_mismatch`, `checkout_hash_mismatch`, `reference_mismatch`,
`reference_unverifiable_withheld`,
`issuer_jwt_form_with_withheld`, `amount_above_max`, `amount_below_min`, `currency_mismatch`,
`instrument_not_allowed`, `no_instrument`, `pisp_not_allowed`, `no_pisp`,
`execution_date_before_window`, `execution_date_after_window`, `malformed_mandate`,
`budget_exceeded`, `recurrence_malformed`, `recurrence_missing_companion`,
`cumulative_unverifiable`, `amount_mismatch`, `negative_total`, `no_single_total`,
`total_unreadable`, `payee_mismatch`, `payee_details_differ`, `agent_key_differs`,
`issuer_key_differs`, `key_not_pinned`, `sd_jwt_receipt`, `unsigned_receipt`,
`conflicting_outcome`, `success_with_error`, `prose_receipt_form`, `declined`, `rejected`,
`receipt_before_mandate`, `issuer_mismatch`, and for the bundle checks `not_object`,
`bad_version`, `bad_member_type`, `too_long`, `unknown_member`, `no_artifacts`, `invalid_key`,
`unknown_role`, `no_keys`.

## issue

A short Markdown block meant to be pasted into a GitHub issue: a reminder to review it for
non-test data first, the tool version, the Python version and OS family (Windows, Linux or
macOS; no OS release and no console encoding), the command and its options (file names are
replaced by `FILE`), the verdict with key trust, the summary counts, and a table of the checks
that FAILed, WARNed or were required but SKIPped (id, status, reason, detail, expected,
actual; consequences are marked "caused by"). Checks that were skipped because they do not
apply are only counted in one line. It has no evidence section. It stays under 60,000
characters (GitHub allows 65,536 per issue) by showing at most 80 rows and saying how many
were omitted.

```bash
ap2-evidence verify my-bundle.json --format issue --out issue.md
```

Review the block before posting it: it contains identifiers, names and hashes from your
tokens. Use test or sandbox data only.
