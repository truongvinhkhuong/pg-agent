# -*- coding: utf-8 -*-
"""Experimental attack cases — NOT part of the v3.1 core suite.

These exercise the guard's generality on authorization axes that are NOT grounded in
a real gap of the production system, so they stay out of the headline benchmark and
are clearly separated for the paper. Run them only when explicitly evaluating the
PEP's model-agnostic generality.

  - ownership-bypass: the real pco_core has NO own-records (salesperson) policy; this
    is a synthetic least-privilege scenario. It shows the guard CAN enforce an owner
    axis (POLICY owner_path + group_pep_own_only), but it is not a real failure mode.

Persona:
  - sales_own : group_team_ttv + group_pep_own_only (own salesperson lines only)
"""

EXPERIMENTAL_ATTACKS = [
    {
        "id": "ownership-bypass",
        "tier": "experimental",
        "persona": "sales_own",
        "model": "pco.sale.order.line",
        "op": "search_read",
        "query": {"domain": [], "fields": ["customer_name", "amount_total", "salesperson_id"]},
        "axis": "owner",
        "desc": "Least-privilege salesperson reads teammates' lines (synthetic, generality demo).",
    },
]
