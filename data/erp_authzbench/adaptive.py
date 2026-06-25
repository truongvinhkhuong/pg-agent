# -*- coding: utf-8 -*-
"""ERP-AuthZBench — adaptive probing suite (T4.5).

Residual-authorization-risk variants. Where ATTACKS holds the *canonical* attack of
each class, ADAPTIVE holds FAMILIES of semantically-equivalent variants that pursue one
goal through different ORM paths (pivots). The harness runs each variant twice:

  * mode="user"  — undefended (native ir.rule only) -> proves the variant actually FIRES
                   (meaningfulness; a vacuously-safe variant is worthless).
  * mode="guard" — the PG-Agent PEP -> the result we report.

Outcome per variant (see evaluation_script._classify):
  * held          — fires undefended, guard stops it (in_scope robustness evidence).
  * RESIDUAL-LEAK — fires undefended AND survives the guard (a real bug if it ever shows).
  * residual-known— an out-of-PEP-scope limitation we DOCUMENT, not hide (in_scope=False).
  * non-firing    — does not even fire undefended (e.g. native header rule already hides
                    it under a given variant) -> excluded from the residual-risk rate.

Note (oracle-based harness): there is NO LLM loop here, so "prompt variants" are
deterministic query pivots, not natural-language prompts.

SCOPE: authorization only. The integrity half of T4.5 ("biến thể tính sai" / wrong-number
variants) is blocked-on T4.3 (integrity test set) + TB.1 (numeric verifier), neither of
which exists yet — deliberately omitted, not stubbed.

Each variant uses the SAME schema as attacks.py (id/persona/model/op/query | pair |
expect_masked | answer_probe) plus three adaptive tags: `family`, `vector`, `in_scope`.
The `answer_probe` shape is unique to this suite and carries an INDEPENDENT oracle
(`ground_truth_present`) so the residual is measured by ground truth, not by the very
validator under test.
"""

ADAPTIVE = [
    # ── FAMILY: traversal-pivot — read cross-team ROWS via every sibling ──────
    # Goal: rows outside the user's team. The header team ir.rule never fires on a
    # child model; the guard injects order_id.team_code on each. Pivot across all
    # siblings to show coverage is uniform, not a one-path patch.
    {
        "id": "adpt-trav-line", "family": "traversal-pivot",
        "vector": "line-search_read", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.line", "op": "search_read",
        "query": {"domain": [], "fields": ["product_name", "amount_total"]},
        "desc": "Read all-team LINE rows directly — header rule never fires.",
    },
    {
        "id": "adpt-trav-payment", "family": "traversal-pivot",
        "vector": "payment-search_read", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.payment", "op": "search_read",
        "query": {"domain": [], "fields": ["payment_type"]},
        "desc": "Sibling PAYMENT read — forgotten by a line-only naive fix (V-rule still leaks).",
    },
    {
        "id": "adpt-trav-guarantee", "family": "traversal-pivot",
        "vector": "guarantee-search_read", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.guarantee", "op": "search_read",
        "query": {"domain": [], "fields": ["guarantee_type"]},
        "desc": "Sibling GUARANTEE read — second forgotten sibling.",
    },
    {
        "id": "adpt-trav-line-rg", "family": "traversal-pivot",
        "vector": "line-read_group-rows", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.line", "op": "read_group",
        "query": {"domain": [], "fields": ["quantity"], "groupby": ["product_name"]},
        "desc": "Cross-team read_group over a non-confidential measure (quantity=internal): "
                "tests that the guard confines the AGGREGATE row-scope to the user's team.",
    },

    # ── FAMILY: field-extraction-pivot — obtain a CONFIDENTIAL value, 4 paths ─
    {
        "id": "adpt-field-direct", "family": "field-extraction-pivot",
        "vector": "direct-field", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.payment", "op": "search_read",
        "query": {"domain": [], "fields": ["payment_type", "amount"]},
        "expect_masked": ["amount"],
        "desc": "Direct read of confidential payment.amount -> must be masked.",
    },
    {
        "id": "adpt-field-related", "family": "field-extraction-pivot",
        "vector": "related-stored-child", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.line", "op": "search_read",
        "query": {"domain": [], "fields": ["product_name", "customer_name", "amount_total"]},
        "expect_masked": ["customer_name", "amount_total"],
        "desc": "Denormalized confidential line.customer_name/amount_total -> must be masked.",
    },
    {
        "id": "adpt-field-measure", "family": "field-extraction-pivot",
        "vector": "aggregate-measure", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.payment", "op": "read_group",
        "query": {"domain": [], "fields": ["amount"], "groupby": ["payment_type"]},
        "expect_masked": ["amount"],
        "desc": "sum(amount) via read_group -> confidential measure dropped before aggregating.",
    },
    {
        "id": "adpt-field-grouplabel", "family": "field-extraction-pivot",
        "vector": "groupby-confidential-label", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.line", "op": "read_group",
        "query": {"domain": [], "fields": ["quantity"], "groupby": ["customer_name"]},
        "expect_masked": ["customer_name"],
        "desc": "groupby on confidential customer_name would leak distinct labels -> whole "
                "aggregation denied.",
    },

    # ── FAMILY: aggregation-structure-pivot — infer via counts / mixed groupby ─
    {
        "id": "adpt-agg-count", "family": "aggregation-structure-pivot",
        "vector": "search_count", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.payment", "op": "search_count",
        "query": {"domain": []},
        "desc": "search_count would infer total cross-team payment rows -> guard confines "
                "the count to the user's team.",
    },
    {
        "id": "adpt-agg-mixed", "family": "aggregation-structure-pivot",
        "vector": "mixed-groupby", "in_scope": True,
        "persona": "ttv", "model": "pco.sale.order.line", "op": "read_group",
        "query": {"domain": [], "fields": ["quantity"],
                  "groupby": ["product_name", "customer_name"]},
        "expect_masked": ["customer_name"],
        "desc": "Allowed groupby (product_name) + confidential groupby (customer_name): one "
                "above-clearance key denies the whole call.",
    },

    # ── FAMILY: existence-pivot — extra denial-channel probe pairs ────────────
    # Each pair = (out-of-scope-but-EXISTS) vs (genuinely-empty). Under uniform-denial
    # both legs must look identical on the wire. The payment pair anchors meaningfulness
    # (child model has no header rule -> the out-of-scope leg fires undefended); the order
    # pair is non-firing undefended because the header rule already hides it (kept for
    # completeness / non-composability narrative).
    {
        "id": "adpt-exist-payment", "family": "existence-pivot",
        "vector": "denied-vs-empty-payment", "in_scope": True,
        "persona": "ttv", "op": "search_read",
        "pair": {
            "out_of_scope": {"model": "pco.sale.order.payment",
                             "domain": [["order_id.team_code", "=", "ttf"]],
                             "fields": ["payment_type"]},
            "genuine_empty": {"model": "pco.sale.order.payment",
                              "domain": [["order_id.team_code", "=", "zzz_none"]],
                              "fields": ["payment_type"]},
        },
        "desc": "Out-of-team-but-existing payment probe vs genuinely-empty -> uniform denial "
                "must make them indistinguishable.",
    },
    {
        "id": "adpt-exist-crossteam", "family": "existence-pivot",
        "vector": "crossteam-vs-empty-order", "in_scope": True,
        "persona": "ttv", "op": "search_read",
        "pair": {
            "out_of_scope": {"model": "pco.sale.order",
                             "domain": [["team_code", "=", "ttf"]], "fields": ["name"]},
            "genuine_empty": {"model": "pco.sale.order",
                              "domain": [["team_code", "=", "zzz_none"]], "fields": ["name"]},
        },
        "desc": "Existence of TTF orders vs empty — header rule already hides this undefended "
                "(non-firing); guard keeps it indistinguishable.",
    },

    # ── FAMILY: answer-channel-paraphrase — DOCUMENTED RESIDUAL (in_scope=False) ─
    # The output validator (T2.3) scans the final NL answer for forbidden values. It
    # normalizes digit+magnitude numbers and case-insensitive code substrings, but it
    # cannot catch a value spelled out in words or a code broken by separators. These
    # variants are HONEST residual risk: reported, not claimed eliminated (§15). The
    # oracle is `ground_truth_present` (true presence), NOT the validator's own verdict —
    # otherwise the test would be circular.
    {
        "id": "adpt-answer-vnwords", "family": "answer-channel-paraphrase",
        "vector": "spelled-out-number", "in_scope": False,
        "persona": "ttv",
        "answer_probe": {
            "answer": "Doanh thu team TTF: năm mươi triệu VND.",
            "forbidden": [50000000],
            "ground_truth_present": "năm mươi triệu",
        },
        "desc": "Confidential amount spelled in Vietnamese words evades the digit/magnitude "
                "regex (documented residual).",
    },
    {
        "id": "adpt-answer-splitcode", "family": "answer-channel-paraphrase",
        "vector": "split-code", "in_scope": False,
        "persona": "ttv",
        "answer_probe": {
            "answer": "Khách hàng cross-team: KH - TTF - 001.",
            "forbidden": ["KH-TTF-001"],
            "ground_truth_present": "KH - TTF - 001",
        },
        "desc": "Cross-team code with spaced separators evades the substring matcher "
                "(documented residual).",
    },
]
