# -*- coding: utf-8 -*-
{
    "name": "PG-Agent Guard (PEP)",
    "version": "1.0.0",
    "summary": "Policy Enforcement Point for permission-aware RAG agents over Odoo.",
    "description": """
PG-Agent Guard
==============
Model-agnostic Policy Enforcement Point (PEP). The RAG agent's data tools
(search_read / read_group / search_count) MUST route through this guard instead
of calling env[model] directly.

Guarantees (see docs/pg-agent/mock-boundary-spec.md §3):
  - team isolation via the per-model `team_path` (incl. dotted order_id.team_code)
  - multi-company (tenant) scoping via `company_path`
  - optional least-privilege ownership scoping via `owner_path`
  - FAIL-CLOSED: any model without an explicit policy entry is DENIED
  - every decision is recorded by an INDEPENDENT audit module (no tdh_audit; AGPL-free)

The guard depends ONLY on the contract surface present in BOTH the public mock and
the real private pco_core, so the same code runs unchanged in both repos.
""",
    # License decision deferred (spec §5). The audit submodule is deliberately
    # isolated from the AGPL `tdh_audit` library so this guard stays AGPL-free and
    # the academic/commercial license can be chosen later without contamination.
    "license": "LGPL-3",
    "author": "PG-Agent (academic)",
    "category": "Research/Security",
    "depends": ["base", "pco_core_mock"],
    "data": [
        "security/pep_groups.xml",
    ],
    "application": False,
    "installable": True,
}
