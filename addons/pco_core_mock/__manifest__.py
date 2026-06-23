# -*- coding: utf-8 -*-
{
    "name": "PCO Core Mock — ERP-AuthZBench schema skeleton",
    "version": "1.0.0",
    "summary": "Public 4-model sale cluster (schema + relations ONLY). No business logic, no real data.",
    "description": """
PCO Core Mock
=============
Layer-1 (public) schema skeleton for the ERP-AuthZBench benchmark.

Reproduces ONLY the structural surface of the real `pco_core` sale cluster that the
permission-aware RAG agent can reach:
  - pco.sale.order            (header, carries the `team_code` discriminator)
  - pco.sale.order.line       (order_id -> header; denormalized customer_name/amount_total)
  - pco.sale.order.payment    (order_id -> header)
  - pco.sale.order.guarantee  (order_id -> header)

What is intentionally ABSENT (per docs/pg-agent/mock-boundary-spec.md):
  - real customer/vendor names, amounts, FX rates  -> synthetic only
  - business formulas (profit_percent, FX conversion, dashboard SQL) -> PRIVATE
  - long-tail business fields (legacy_*, kob, part_no, ...) -> DROPPED

Authz-relevant field NAMES are kept verbatim (team_code, order_id, customer_name,
amount_total, company_id, salesperson_id) because they ARE the guard contract.
""",
    # License decision deferred (spec §5). Provisional LGPL-3 to match Odoo norm.
    # The guard's audit module is isolated from AGPL `tdh_audit` regardless of this choice.
    "license": "LGPL-3",
    "author": "PG-Agent (academic)",
    "category": "Research/Benchmark",
    "depends": ["base", "product"],
    "data": [
        "security/security_groups.xml",
        # V-vuln baseline: team isolation rule on HEADER ONLY (faithful to prod today).
        # Swap for security/team_security_vrule.xml to load the naive-fix variant.
        "security/team_security.xml",
        "security/ir.model.access.csv",
    ],
    "application": False,
    "installable": True,
}
