# -*- coding: utf-8 -*-
"""T4.3 — ERP-AuthZBench integrity test set (opens RQ6).

Questions with a GOLD answer computed by symbolic computation over the synthetic data
(TQA-Bench style), across five kinds: aggregation / ratio / growth-% / period-comparison /
multi-step. The driver (`integrity()` in tests/evaluation_script.py) computes each gold via a
TRUSTED sudo aggregation independent of the agent's query path, then plants two answers per
question — a gold-derived CORRECT answer and a silently-WRONG one (a number not derivable from
the governed execution table) — and runs the TB.1 numeric verifier on each.

HONEST FRAMING (no LLM in the public artifact): this is APPLIED / adopt-not-invent. We do NOT
measure a real model's hallucination rate. We demonstrate the verifier's MECHANISM — it binds
every number a legitimate derivation yields from the governed table (zero false-flags across
all five kinds) and flags numbers no derivation yields (unbindable = silently-wrong). TB.1
catches *fabricated / cross-data* numbers; *correct-arithmetic-with-the-wrong-formula* is a
documented limitation that TB.2 (execution-guided self-consistency) / TB.3 (governed metrics)
address. Real-LLM Silently-Wrong-Number Rate is validated privately.

Persona ↔ measure clearance is mandatory (a below-clearance measure is masked away → empty
execution table): `quantity` is internal → persona `ttv`; `amount_total` is confidential →
persona `viewer_all`. `price_unit` (restricted) is never used as a measure.

Period axis: the synthetic generator populates no dates, so period-comparison uses a
deterministic SYNTHESIZED H1/H2 split (order id parity), labelled as synthesized.
"""

INTEGRITY = [
    {"id": "int-agg-qty", "kind": "aggregation", "persona": "ttv",
     "model": "pco.sale.order.line", "measure": "quantity", "groupby": "product_name",
     "gold_kind": "sum", "wrong_kind": "crossteam",
     "desc": "Total quantity over the team's lines; wrong = the unfiltered all-team total."},
    {"id": "int-agg-amount", "kind": "aggregation", "persona": "viewer_all",
     "model": "pco.sale.order", "measure": "amount_total", "groupby": "team_code",
     "gold_kind": "sum", "wrong_kind": "fabricated",
     "desc": "Total order amount over the governed table; wrong = a fabricated near-value."},
    {"id": "int-ratio-share", "kind": "ratio", "persona": "ttv",
     "model": "pco.sale.order.line", "measure": "quantity", "groupby": "product_name",
     "gold_kind": "top-share", "wrong_kind": "fabricated",
     "desc": "Share of the top product in total quantity (ratio %)."},
    {"id": "int-growth-pct", "kind": "growth-pct", "persona": "ttv",
     "model": "pco.sale.order.line", "measure": "quantity", "groupby": "period",
     "gold_kind": "growth", "wrong_kind": "fabricated",
     "desc": "H1-vs-H2 growth % in quantity (synthesized period split)."},
    {"id": "int-period-cmp", "kind": "period-comparison", "persona": "ttv",
     "model": "pco.sale.order.line", "measure": "quantity", "groupby": "period",
     "gold_kind": "period-diff", "wrong_kind": "fabricated",
     "desc": "H1 vs H2 quantity + their difference (synthesized period split)."},
    {"id": "int-multistep", "kind": "multi-step", "persona": "viewer_all",
     "model": "pco.sale.order", "measure": "amount_total", "groupby": "team_code",
     "gold_kind": "pairwise-diff", "wrong_kind": "fabricated",
     "desc": "Difference between the two largest team totals (multi-step)."},
]


# ─────────────────────────────────────────────────────────────────────────────
# TB.2 + TB.3: correct-arithmetic-WRONG-FORMULA (TB.1's documented blind spot).
# Each wrong value BINDS under TB.1 (it equals a legitimate derivation target — identity /
# pairwise-diff / share%) while answering a DIFFERENT question. `metric` names the governed
# table source; `in_scope` = a governed metric answers the exact question (TB.3) vs not (TB.2).
# ─────────────────────────────────────────────────────────────────────────────

INTEGRITY_FORMULA = [
    # in-scope: the governed metric answers the asked question -> TB.3 catches by raw != governed.
    {"id": "fml-topgroup-sum", "kind": "wrong-aggregation-scope", "persona": "viewer_all",
     "metric": "net_revenue_by_team", "gold_kind": "sum", "wrong_kind": "top_group_instead_of_sum",
     "in_scope": True,
     "desc": "Asked total net revenue; answered the biggest team's total (an identity target "
             "-> TB.1 binds it; governed sum catches). [WF-A]"},
    {"id": "fml-leadteam", "kind": "wrong-filter", "persona": "viewer_all",
     "metric": "net_revenue_by_team", "gold_kind": "max", "wrong_kind": "wrong_group_identity",
     "in_scope": True,
     "desc": "Asked the leading team's revenue; answered a different team (both identity "
             "targets -> TB.1 binds; governed dimension lookup catches). [WF-B]"},
    {"id": "fml-wrongagg-avg", "kind": "wrong-aggregation", "persona": "viewer_all",
     "metric": "avg_order_value", "gold_kind": "avg", "wrong_kind": "sum_instead_of_avg",
     "in_scope": True,
     "desc": "Asked average order value; answered the sum (full-sum target -> TB.1 binds; "
             "governed avg catches)."},
    {"id": "fml-qty-topgroup", "kind": "wrong-aggregation-scope", "persona": "ttv",
     "metric": "total_quantity_by_product", "gold_kind": "sum", "wrong_kind": "top_group_instead_of_sum",
     "in_scope": True,
     "desc": "Asked total quantity; answered the top product's quantity (internal measure "
             "-> ttv clearance). [WF-A]"},

    # out-of-scope: no governed metric answers the exact question -> TB.2 self-consistency carries it.
    {"id": "fml-oos-pairdiff", "kind": "wrong-pair-diff", "persona": "viewer_all",
     "metric": "net_revenue_by_team", "gold_kind": "pairdiff", "wrong_kind": "wrong_pair_diff",
     "in_scope": False,
     "desc": "Diff of the two largest team totals; wrong = a different pair's diff (both "
             "pairwise-diff targets -> TB.1 binds; no metric -> vote catches). [WF-C]"},
    {"id": "fml-oos-share", "kind": "wrong-share", "persona": "viewer_all",
     "metric": "net_revenue_by_team", "gold_kind": "top_share", "wrong_kind": "wrong_share",
     "in_scope": False,
     "desc": "Top team's share of total; wrong = a non-top team's share (both share-of-total "
             "targets -> TB.1 binds; vote catches). [WF-D]"},

    # CONTRAST: TB.1 ALREADY catches this — kept to mark the taxonomy boundary, excluded from 0/N.
    {"id": "fml-contrast-subtotal", "kind": "forgot-tax", "persona": "viewer_all",
     "metric": "net_revenue_by_team", "gold_kind": "sum", "wrong_kind": "subtotal_instead_of_total",
     "in_scope": True,
     "desc": "sum(amount_subtotal) instead of amount_total. NOT a blind spot: unbindable to the "
             "governed amount_total table -> TB.1 already catches it (contrast)."},
]


def formula_wrong_value(wrong_kind, vals):
    """Pure: a correct-arithmetic-WRONG-FORMULA value derived from the governed group values.

    Each is a legitimate derivation target of `vals` (so TB.1 binds it) yet the wrong answer.
    `vals` = the metric's per-group measure values (descending order not assumed)."""
    s = sorted([float(v) for v in vals], reverse=True)
    total = sum(s)
    return {
        "top_group_instead_of_sum": s[0] if s else 0.0,                 # identity (a group) vs sum
        "wrong_group_identity": s[1] if len(s) > 1 else 0.0,            # a different group (identity)
        "sum_instead_of_avg": total,                                    # full-sum vs avg
        "wrong_pair_diff": (s[0] - s[2]) if len(s) > 2 else 0.0,        # a different pairwise diff
        "wrong_share": round(s[1] / total * 100, 1) if len(s) > 1 and total else 0.0,  # wrong share%
        "subtotal_instead_of_total": total / 1.1,                       # CONTRAST: unbindable
    }[wrong_kind]
