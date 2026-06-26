# -*- coding: utf-8 -*-
"""Offline tests for the end-to-end agent-loop proxy.

No Odoo, no LLM. Covers the deterministic planner, the pure utility oracle (it must BITE on a wrong
number), the answer-synthesis helpers, the answer-channel redaction via the REAL output_validator
(drift-proof), and that the `LLMAgent` seam never executes an SDK. Mirrors test_docrag.py.
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
sys.path.insert(0, os.path.join(_D, "..", "addons", "pg_agent_guard", "services"))
import agent_loop as al                          # noqa: E402
import output_validator as ov                    # noqa: E402


# ── planner ──────────────────────────────────────────────────────────────────
def test_scripted_agent_returns_expected_toolcalls():
    agent = al.ScriptedAgent()
    for q in al.QUERIES:
        plan = agent.plan(q["nl"])
        assert plan == q["plan"], q["id"]
        for tc in plan:                                    # tool-call shape
            assert {"model", "op", "query"} <= set(tc)


def test_scripted_agent_is_deterministic():
    a, b = al.ScriptedAgent(), al.ScriptedAgent()
    nl = al.QUERIES[0]["nl"]
    assert a.plan(nl) == b.plan(nl)


def test_llm_agent_is_a_seam_not_a_client():
    # The seam must never silently run an SDK; calling plan() raises a clear recipe error.
    try:
        al.LLMAgent().plan("bất kỳ câu hỏi nào")
    except NotImplementedError as e:
        assert "seam" in str(e).lower() or "implement" in str(e).lower()
    else:
        raise AssertionError("LLMAgent.plan must raise (documented seam, no SDK call)")


# ── utility oracle must BITE ─────────────────────────────────────────────────
def test_number_correct_matches_gold_and_rejects_wrong():
    assert al.number_correct(1000.0, 1000.0) is True
    assert al.number_correct(1002.0, 1000.0) is True          # within rel-tol
    assert al.number_correct(1500.0, 1000.0) is False         # a wrong synthesized number is caught
    assert al.number_correct(0.0, 1000.0) is False            # masked/empty answer ≠ legitimate total


def test_query_set_shape():
    intents = {q["intent"] for q in al.QUERIES}
    assert {"benign", "adversarial"} <= intents
    # measures used in read_group queries must be the VISIBLE one (quantity) — an above-clearance
    # measure would be correctly dropped by the guard, making utility vacuous.
    for q in al.QUERIES:
        if q.get("kind") == "readgroup":
            assert q["measure"] == "quantity", q["id"]


# ── answer synthesis + answer-channel redaction via the REAL validator ───────
def test_render_helpers():
    assert "TTV" in al.render_readgroup_answer("ttv", "quantity", 42, 5)
    assert "2 đơn hàng" in al.render_list_answer("ttv", ["SO-00002", "SO-00001"])


def test_answer_channel_redaction_and_residual():
    # a cross-team value rendered in DIGIT form is caught; the spelled-out form is the documented residual.
    digit_answer = "Doanh thu cross-team: 50000000 VND."
    assert ov.validate_answer(digit_answer, [50000000], redact=False).leaked is True
    paraphrase = al.QUERIES[-1]                                 # q-adv-paraphrase
    clean = ov.validate_answer(paraphrase["answer"], paraphrase["forbidden"]).clean_text
    assert paraphrase["ground_truth_present"] in clean         # value survives in spelled form (residual)
    assert paraphrase["in_scope"] is False


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} agent-loop tests passed.")
