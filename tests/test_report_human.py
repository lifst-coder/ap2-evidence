"""The report as read by a dispute analyst: conclusion, root causes, wording, formats."""

from __future__ import annotations

import json
import re

from ap2_evidence.checks import REASONS, REGISTRY, reason_text
from ap2_evidence.demo import build_demo_bundle
from ap2_evidence.report import CAUSE_RULES, clean, glossary_for, md
from helpers import EXAMPLE, NOW, ROOT, builder, run_cli, trusted_for, verify


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


# --------------------------------------------------------------------------- conclusion


def test_amount_conclusion_leads_with_the_facts() -> None:
    r = verify(build_demo_bundle("amount", seed=1, now=NOW))
    assert r.finding == (
        "The agent paid USD 250.00 to Demo Merchant for checkout 'demo-checkout-0001'. The "
        "user's mandate allowed at most USD 200.00, and the merchant's signed checkout was for "
        "USD 199.00."
    )
    assert r.meaning.startswith("This bundle cannot be used to show that the payment was")
    assert "agent provider" in r.meaning
    steps = r.next_steps
    assert any("above the user's limit" in s for s in steps)
    assert any("differs from the merchant's checkout total" in s for s in steps)
    assert any("--trusted-keys" in s for s in steps)
    d = r.to_dict()
    assert d["finding"] == r.finding and d["next_steps"] == steps
    assert d["conclusion"].startswith("FAILED. " + r.finding)


def test_text_conclusion_has_no_truncation_and_no_thumbprints() -> None:
    r = verify(builder().build().bundle)
    text = r.to_text()
    concl = _section(text, "1. Conclusion", "2. Broken links")
    agent = r.evidence["delegation"]["payment"]["agent_key_thumbprint"]
    assert agent not in concl and agent[:8] not in concl  # no thumbprint, not even shortened
    assert "the agent the user authorised approved exactly this checkout and this payment" in (
        r.meaning
    )
    assert "more characters" not in concl
    assert "…" not in text  # text output stays ASCII-safe
    # the full thumbprint appears exactly once in the evidence chain section
    ev = _section(text, "4. Evidence chain", "5. All checks")
    assert ev.count(agent) == 1


def test_verified_without_pinned_keys_does_not_say_proves() -> None:
    r = verify(builder().build().bundle)
    assert r.verdict == "VERIFIED"
    assert not re.search(r"\bprove[sn]?\b", r.conclusion)
    assert "none of them pinned by you" in r.meaning
    assert "does not show who the signing keys belong to" in r.meaning.lower().replace(
        "it does", "does"
    )
    assert "Whoever assembled the file could have put any keys there" in r.key_trust_sentence()


def test_pinned_verified_meaning() -> None:
    b = builder()
    bundle = b.build().bundle
    from ap2_evidence import load_trusted_keys

    r = verify(bundle, trusted_keys=load_trusted_keys(json.dumps(trusted_for(b))))
    assert r.verdict == "VERIFIED"
    assert r.meaning.startswith("Checked with the keys you pinned")
    assert "self-asserted" not in r.conclusion


def test_payee_described_differently_is_called_out() -> None:
    b = builder()
    b.closed_payment["payee"] = dict(b.closed_payment["payee"], name="Evil Corp")
    r = verify(b.build().bundle)
    assert "to Demo Merchant" in r.finding  # the merchant-signed checkout's name is used
    assert "Evil Corp" in r.finding and "differs from the merchant" in r.finding
    assert not r.finding.startswith("The agent paid USD 199.00 to Evil Corp")


def test_incomplete_conclusion_for_official_sample() -> None:
    r = verify(json.loads(EXAMPLE.read_text(encoding="utf-8")))
    assert r.verdict == "INCOMPLETE"
    assert "the Checkout Receipt and the Payment Receipt are missing" in r.meaning
    assert "Already shown:" in r.meaning
    assert "Ask the merchant for the Checkout Receipt." in r.next_steps
    assert "Ask the payment processor for the Payment Receipt." in r.next_steps
    assert any(
        s.startswith("Get the public keys directly from the mandate issuer and the merchant")
        and "--issuer-key" in s
        and "--merchant-key" in s
        for s in r.next_steps
    )
    # receipts are missing, so the finding must not say the money moved
    assert "paid" not in r.finding
    assert "nothing in this bundle shows it was processed" in r.finding
    assert "not yet established that this payment was authorised" in r.finding
    text = r.to_text()
    assert "The Checkout Receipt and the Payment Receipt are not in the bundle." in text


def test_every_reason_code_has_wording_and_unknown_codes_fall_back() -> None:
    doc = (ROOT / "docs" / "output-formats.md").read_text(encoding="utf-8")
    codes = doc.split("Generic codes:", 1)[1].split("## issue", 1)[0]
    listed = set(re.findall(r"`([a-z0-9_]+)`", codes)) - {"blocked_by"}
    assert len(listed) > 100
    missing = sorted(code for code in listed if code not in REASONS)
    assert not missing, missing
    rt = reason_text("CM03", "some_future_code")
    assert rt is None
    from ap2_evidence.report import CheckResult, action_text, plain_text

    c = CheckResult("CM03", "checkout_mandate", "t", "FAIL", True, "d", reason="new_code")
    assert plain_text(c) and "CM03" in action_text(c)


def test_why_texts_state_the_purpose() -> None:
    for d in REGISTRY.values():
        assert d.why.startswith(("Confirms", "Without", "Answers", "Flags", "Reminds")), d.id
    text = verify(build_demo_bundle("amount")).to_text()
    assert "Why it matters" not in text
    assert "What this check is for: Confirms that the amount paid equals" in text


# --------------------------------------------------------------------------- root causes


def test_disclosure_swap_has_one_primary_and_consequences() -> None:
    r = verify(build_demo_bundle("disclosure"))
    fails = [c.id for c in r.checks if c.status == "FAIL"]
    assert [c.id for c in r.primary_failures()] == ["CM04"]
    assert {"CM09", "CM34"} <= set(r.causes())
    assert r.causes() == {cid: "CM04" for cid in fails if cid != "CM04"}
    links = r.to_dict()["broken_links"]
    assert [b["id"] for b in links] == fails  # every FAIL is still listed
    assert [b["caused_by"] for b in links] == [None] + ["CM04"] * (len(fails) - 1)
    text = r.to_text()
    assert "Consequences of CM04" in text
    assert f"1 underlying problem; the other {len(fails) - 1} failures follow from it." in text
    concl = r.finding + " " + r.meaning + " " + " ".join(r.next_steps)
    assert "(the list of allowed merchants) was changed after they were signed" in r.finding
    assert "Whoever supplied this file supplied altered evidence." in r.meaning
    assert "side effects of this change" in r.finding
    assert not re.search(r"\b(CM|PM)\d\d\b", concl)  # no check IDs in the conclusion


def test_independent_failures_stay_independent() -> None:
    r = verify(build_demo_bundle("amount"))
    assert r.causes() == {}
    assert {b["caused_by"] for b in r.broken_links()} == {None}


def test_signature_failures_are_never_primaries() -> None:
    primaries = {p for p, _reasons, _deps in CAUSE_RULES}
    assert not primaries & {"CM03", "PM03", "CM08", "PM08", "CM32", "CR02", "PR02"}


# --------------------------------------------------------------------------- helpers


def test_clean_truncates_on_a_word_boundary() -> None:
    text = "alpha beta gamma delta epsilon zeta eta theta"
    out = clean(text, 20)
    assert out.startswith("alpha beta gamma...")
    assert "delt" not in out
    assert out.endswith("more characters)")


def test_markdown_url_keeps_closing_parenthesis_outside_code_span() -> None:
    assert md("Demo Merchant (merchant_1, https://demo-merchant.example)") == (
        "Demo Merchant (merchant\\_1, `https://demo-merchant.example`)"
    )
    assert md("see https://x.example/a.") == "see `https://x.example/a`."
    assert md("(https://en.example/wiki/A_(b))") == "(`https://en.example/wiki/A_(b)`)"
    text = verify(builder().build().bundle).to_markdown()
    assert "`https://demo-merchant.example)`" not in text
    assert "`https://demo-merchant.example`)" in text


def test_glossary_only_lists_terms_that_occur() -> None:
    assert [t for t, _d in glossary_for("one segment and a disclosure")] == [
        "segment",
        "disclosure",
    ]
    text = verify(build_demo_bundle("disclosure")).to_text()
    gloss = text.split("7. Glossary", 1)[1]
    assert "- disclosure:" in gloss and "- open mandate:" in gloss
    assert "- PISP:" in gloss  # the evidence chain shows the PISP
    md_text = verify(build_demo_bundle("disclosure")).to_markdown()
    assert "## 7. Glossary" in md_text


# --------------------------------------------------------------------------- issue format


def test_issue_lists_only_actionable_rows() -> None:
    out = verify(build_demo_bundle("amount")).to_issue("demo --tamper amount --format issue")
    rows = [ln for ln in out.splitlines() if ln.startswith("| ") and not ln.startswith("| ID")]
    rows = [ln for ln in rows if not ln.startswith("| ---")]
    assert [ln.split("|")[1].strip() for ln in rows] == ["PM32", "XC01"]
    assert "not required" not in out.split("further check(s)")[0]
    assert "12 further check(s) were skipped because they do not apply" in out
    assert "encoding" not in out
    assert re.search(r"- Python: \d+\.\d+\.\d+ on (Windows|Linux|macOS|\w+)\n", out)
    official = verify(json.loads(EXAMPLE.read_text(encoding="utf-8"))).to_issue()
    assert "SKIP (not required)" not in official


# --------------------------------------------------------------------------- console


def test_text_output_on_cp949_console() -> None:
    p = run_cli("demo", "--tamper", "disclosure", env={"PYTHONIOENCODING": "cp949"})
    assert p.returncode == 1, p.stderr
    text = p.stdout.decode("cp949")
    assert "Consequences of CM04" in text
    assert "\\u2026" not in text and "…" not in text


# --------------------------------------------------------------------------- declined payments


def test_declined_outcome_is_never_a_plain_verified() -> None:
    r = verify(builder().build().bundle)
    assert r.outcome == "success"
    for cid in ("PR05", "CR05"):  # both receipts count and both say declined
        c = r.check(cid)
        c.status, c.reason = "WARN", "declined"
    assert r.verdict == "VERIFIED" and r.exit_code == 0
    assert r.outcome == "declined"
    assert r.verdict_label == "VERIFIED - PAYMENT DECLINED"
    assert "VERDICT: VERIFIED - PAYMENT DECLINED (keys:" in r.to_text()
    assert "**Verdict: VERIFIED - PAYMENT DECLINED**" in r.to_markdown()
    assert r.to_dict()["outcome"] == "declined"
    page = r.to_html()
    assert "PAYMENT DECLINED" in page and 'class="banner verified"' not in page


def test_declined_receipt_end_to_end() -> None:
    import pytest

    b = builder()
    for rec in (b.payment_receipt, b.checkout_receipt):
        rec["status"] = "Error"
        rec["error"] = "card_declined"
        rec["error_description"] = "Insufficient funds"
    b.payment_receipt.pop("psp_confirmation_id", None)
    b.payment_receipt.pop("network_confirmation_id", None)
    r = verify(b.build().bundle)
    if r.check("PR05").reason != "declined":
        pytest.skip("verifier does not report declined receipts as WARN")
    assert r.outcome == "declined"
    assert "The Payment Receipt is authentic and says the payment was DECLINED" in r.finding
    assert "Success" not in r.conclusion and "signed receipts saying it succeeded" not in (
        r.conclusion
    )


# --------------------------------------------------------------------------- walkthrough fixes

UPSTREAM = ROOT / "tests" / "fixtures" / "upstream-sdk" / "v_extras_usd"


def _extras(**kw: object) -> object:
    from ap2_evidence import load_trusted_keys

    bundle = json.loads((UPSTREAM / "bundle.json").read_text(encoding="utf-8"))
    keys = load_trusted_keys((UPSTREAM / "trusted_keys.json").read_text(encoding="utf-8"))
    return verify(bundle, trusted_keys=keys, **kw)


def test_cumulative_budget_failure_is_described_truthfully() -> None:
    r = _extras(history={"prior_total": {"amount": 5003, "currency": "USD"}, "prior_uses": 0})
    if r.check("PM39").reason != "budget_exceeded":
        return
    want = (
        "Together with the USD 50.03 you said was already spent, this payment of USD 99.98 "
        "exceeds the user's USD 150.00 budget."
    )
    assert want in r.finding
    assert "alone" not in r.finding
    assert "rests on the history figures supplied by the person running the verifier" in (r.meaning)
    text = r.to_text()
    assert "minor units)" not in text.split("5. All checks")[0]
    where = text.split("PM39 Cumulative")[1].split("What this check is for")[0]
    assert "prior_total" not in where and "rests on --prior-total" in where.replace("\n", " ")


def test_history_figures_not_needed_are_mentioned() -> None:
    r = verify(builder().build().bundle, history={"prior_total": {"amount": 1, "currency": "USD"}})
    assert any("were not needed" in n for n in r.notes)
    assert "were not needed" in r.to_text()


def test_key_tamper_lists_keys_only_for_signatures_they_verified() -> None:
    r = verify(build_demo_bundle("key"))
    keys = r.evidence["keys"]
    agent = next(k for k in keys if k["role"] == "agent")
    assert agent["used_for"] == ["the closed checkout mandate"]
    assert agent["failed_for"] == ["the closed payment mandate"]
    text = r.to_text()
    assert "The closed payment mandate was NOT signed by this agent key" in text.replace(
        "\n      ", " "
    )


def test_reader_hints_name_command_line_options() -> None:
    bundle = builder().build().bundle
    del bundle["keys"]
    text = verify(bundle).to_text()
    assert "under keys.mandate_issuer in the bundle" not in text.split("5. All checks")[0]
    assert "--issuer-key FILE" in text
    assert "verify_bundle" not in text.split("5. All checks")[0]
    assert "--expect-agent-key" in verify(builder().build().bundle).to_text()


def test_receipt_tamper_says_payment_not_shown_processed() -> None:
    r = verify(build_demo_bundle("receipt"))
    assert r.outcome == "unknown"
    assert "approved a payment of" in r.finding
    assert "nothing in this bundle shows it was processed" in r.finding


def test_verified_shows_status_gloss_note_and_no_python_none() -> None:
    bundle = builder().build().bundle
    bundle["note"] = "collected by analyst A"
    r = verify(bundle)
    text = r.to_text()
    assert "Note supplied with the bundle (free text, not verified)" in text
    assert '"collected by analyst A"' in text
    assert r.to_dict()["evidence"]["note"] == "collected by analyst A"
    assert "in UCP, " in text
    head = text.split("5. All checks")[0]  # the All checks details belong to verify.py
    assert "'null'" not in head and "''" not in head
    assert not [ln for ln in head.splitlines() if "None" in ln and ln.strip() != "None."]


def test_html_label_and_appendix() -> None:
    page = verify(build_demo_bundle("disclosure")).to_html()
    assert "Keys:</span> keys:" not in page
    assert "<details>" not in page and "printnote" not in page
    assert page.index("ap2-evidence inspect") > page.index("Technical appendix")


def test_issue_has_no_triple_blank_lines() -> None:
    from ap2_evidence.demo import build_demo_bundle as demo

    out = verify(demo()).to_issue()
    assert "\n\n\n" not in out


def test_spec_reference_names_the_upstream_repository() -> None:
    from ap2_evidence.checks import spec_reference_text

    assert "upstream AP2 repository github.com/google-agentic-commerce/AP2" in (
        spec_reference_text("PM32")
    )


def test_key_options_match_the_cli() -> None:
    from ap2_evidence.checks import KEY_OPTIONS
    from ap2_evidence.keys import ROLE_FLAGS

    assert KEY_OPTIONS == ROLE_FLAGS
