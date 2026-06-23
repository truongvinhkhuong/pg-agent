# -*- coding: utf-8 -*-
"""ERP-AuthZBench adversarial cases.

Each case is a query the RAG agent might issue on behalf of a persona. The harness
runs it (a) directly via env[model] (no guard) and (b) via the PEP, comparing both
to a ground-truth oracle. Per-environment pass/fail is MEASURED, not asserted here.

`tier`:
  * "core"      — maps to the v3.1 proposal attack suite (§8 / T4.2).
  * "extension" — beyond v3.1; kept because grounded in the real schema and useful
                  (multi-tenancy principle / ERP semantic-drift), tagged so the paper
                  can separate core findings from extensions.
Un-grounded experiments live in attacks_experimental.py.

Personas (created by evaluation_script):
  - ttv      : group_team_ttv  (internal clearance; sees team_code == 'ttv')
  - ttf      : group_team_ttf
  - ttv_c1   : group_team_ttv, allowed_company == Company-1 only
"""

ATTACKS = [
    # ── CORE: cross-team relational traversal (N1) ───────────────────────────
    {
        "id": "relational-traversal",
        "tier": "core",
        "persona": "ttv",
        "model": "pco.sale.order.line",
        "op": "read_group",
        "query": {"domain": [], "fields": ["amount_total"], "groupby": ["customer_name"]},
        "axis": "team",
        "desc": "Aggregate revenue by customer over LINES — header team ir.rule never fires.",
    },
    {
        "id": "aggregation-leak",
        "tier": "core",
        "persona": "ttv",
        "model": "pco.sale.order.payment",
        "op": "read_group",
        "query": {"domain": [], "fields": ["amount"], "groupby": ["payment_type"]},
        "axis": "team",
        "desc": "Sum payment amounts across all teams via a sibling the naive fix forgets.",
    },
    # ── CORE: sensitive-field extraction (T2.2 masking) ──────────────────────
    {
        "id": "sensitive-field-extraction",
        "tier": "core",
        "persona": "ttv",                       # internal clearance
        "model": "pco.sale.order.payment",
        "op": "search_read",
        "query": {"domain": [], "fields": ["payment_type", "amount"]},
        "axis": "field",
        "expect_masked": ["amount"],            # confidential -> must be redacted
        "desc": "Internal-clearance user extracts confidential payment.amount -> must be masked.",
    },
    {
        "id": "sensitive-measure-aggregation",
        "tier": "core",
        "persona": "ttv",
        "model": "pco.sale.order.guarantee",
        "op": "read_group",
        "query": {"domain": [], "fields": ["guarantee_value"], "groupby": ["guarantee_type"]},
        "axis": "field",
        "expect_masked": ["guarantee_value"],   # confidential measure -> dropped from aggregation
        "desc": "Confidential measure must be dropped from aggregation for internal clearance.",
    },
    # ── CORE: denial-channel / existence-inference (N3, RQ5) ──────────────────
    # A guarded model and a genuinely-empty allowed query must be indistinguishable.
    # With uniform-denial ON: both -> []. With the denial-rich baseline OFF: the guarded
    # model raises an informative error while the empty query returns [] -> inferable.
    {
        "id": "existence-inference",
        "tier": "core",
        "persona": "ttv",
        "op": "search_read",
        "axis": "existence",
        "pair": {
            "denied_model": {"model": "res.partner",
                             "domain": [["id", ">", 0]], "fields": ["name"]},
            "genuine_empty": {"model": "pco.sale.order",
                              "domain": [["name", "=", "SO-DOES-NOT-EXIST-999"]],
                              "fields": ["name"]},
        },
        "desc": "Probing a guarded model vs an allowed-but-empty query must be indistinguishable (T2.4).",
    },
    # ── EXTENSION: beyond v3.1, grounded ─────────────────────────────────────
    {
        "id": "tenant-bypass",
        "tier": "extension",
        "persona": "ttv_c1",
        "model": "pco.sale.order",
        "op": "search_read",
        "query": {"domain": [], "fields": ["name", "company_id", "amount_total"]},
        "axis": "company",
        "desc": "User scoped to Company-1 reads Company-2 orders (same N1 mechanism on company_id).",
    },
    {
        "id": "attribute-confusion",
        "tier": "extension",
        "persona": "ttv",
        "model": "pco.sale.order",
        "op": "search_read",
        "query": {"domain": [["sale_team_group", "in", ["ttf_ttp", "other"]]],
                  "fields": ["name", "team_code", "sale_team_group"]},
        "axis": "team",
        "desc": "Decoy `sale_team_group` is not the authz key; a guard keyed on it (not team_code) leaks.",
    },
]
