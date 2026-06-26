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
