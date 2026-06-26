# -*- coding: utf-8 -*-
"""TB.3 — governed-metrics registry (pure data; no Odoo / no LLM).

A governed metric pins (model, measure, agg, dimension, filter) so its value is the RIGHT
formula over the RIGHT rows BY CONSTRUCTION. The harness `metric_engine` computes it through
guard.guarded_read_group / guarded_search_count — the guard's authz domain pins the rows, the
registry pins the measure+agg — so for a covered question a wrong-formula answer is impossible.

HONEST FRAMING (no LLM): in the real system an LLM maps a NL question -> a metric name; here the
mapping is PLANTED (each integrity-formula question names its governed metric). What we
demonstrate is the deterministic ENGINE (governed metric = 0 formula error) and that a planted
correct-arithmetic-WRONG-FORMULA value — which BINDS under the TB.1 numeric verifier (it equals
a legitimate derivation target while answering a different question) — disagrees with the
governed value and is caught.

Code-default pure registry, like POLICY (pep_guard) and SENSITIVITY (sensitivity) — no
`pco.ai.metric` Odoo model here (that is the private system's concern; the public artifact stays
reproducible + offline-testable). Persona <-> measure clearance is mandatory (same trap as TB.1):
amount_total / payment.amount are `confidential` -> persona viewer_all; quantity is `internal`
-> persona ttv; a below-clearance measure is masked away (uncomputable for that persona).
"""

# agg: 'sum' | 'count' | 'avg'.  dimension: a groupby field, or None for a scalar.
# domain: extra filter leaves AND-ed in beyond the guard's authz domain.
METRICS = {
    "net_revenue_by_team": {
        "model": "pco.sale.order", "measure": "amount_total", "agg": "sum",
        "dimension": "team_code", "domain": [],
        "sensitivity": "confidential", "persona": "viewer_all",
        "desc": "Net revenue (tax-inclusive) by team — carrier of the WF-A/B/D traps.",
    },
    "total_quantity_by_product": {
        "model": "pco.sale.order.line", "measure": "quantity", "agg": "sum",
        "dimension": "product_name", "domain": [],
        "sensitivity": "internal", "persona": "ttv",
        "desc": "Total quantity by product (internal measure -> ttv clearance).",
    },
    "payment_total": {
        "model": "pco.sale.order.payment", "measure": "amount", "agg": "sum",
        "dimension": None, "domain": [],
        "sensitivity": "confidential", "persona": "viewer_all",
        "desc": "Total collected payment amount (scalar).",
    },
    "order_count": {
        "model": "pco.sale.order", "measure": None, "agg": "count",
        "dimension": None, "domain": [],
        "sensitivity": "public", "persona": "ttv",
        "desc": "Number of orders (count -> no confidential measure; still authz-confined).",
    },
    "avg_order_value": {
        "model": "pco.sale.order", "measure": "amount_total", "agg": "avg",
        "dimension": "team_code", "domain": [],
        "sensitivity": "confidential", "persona": "viewer_all",
        "desc": "Average order amount (avg agg — the wrong-agg trap: sum reported as avg).",
    },
}


def metric_names():
    return list(METRICS.keys())


def metric_spec(name):
    """Lookup; KeyError surfaces a typo'd metric name (fail-loud in bench code)."""
    return METRICS[name]
