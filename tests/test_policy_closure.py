# -*- coding: utf-8 -*-
"""Offline unit tests for the policy-closure core (no Odoo, no LLM).

Mirrors tests/test_output_validator.py. Fixtures replicate the pco_core_mock relation graph
+ ir.rule coverage for both schema variants. Expected closure paths are HARD-CODED from
pep_guard.POLICY (lines 47-68) as the source of truth — NOT imported, because importing
pep_guard pulls in `from odoo import ...` and would break this offline lane.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data", "erp_authzbench"))
from policy_closure import derive_closures  # noqa: E402

PCO_MODELS = [
    "pco.sale.order", "pco.sale.order.line",
    "pco.sale.order.payment", "pco.sale.order.guarantee",
]

# Many2one edges: the three order_id child->parent edges + two decoys that MUST NOT
# become the discriminator path.
EDGES = [
    ("pco.sale.order.line", "order_id", "pco.sale.order"),
    ("pco.sale.order.payment", "order_id", "pco.sale.order"),
    ("pco.sale.order.guarantee", "order_id", "pco.sale.order"),
    ("pco.sale.order.line", "salesperson_id", "res.users"),    # decoy
    ("pco.sale.order.line", "customer_id", "res.partner"),     # decoy
]

DISCRIMINATORS = {
    "team": ("pco.sale.order", "team_code"),
    "company": ("pco.sale.order", "company_id"),
}

# V-vuln: team rule on header only. V-rule: header + line (siblings still unruled).
# Company: no native rule anywhere, in either variant.
RULES_VVULN = {"team": {"pco.sale.order"}, "company": set()}
RULES_VRULE = {"team": {"pco.sale.order", "pco.sale.order.line"}, "company": set()}

# Source of truth: pep_guard.POLICY (lines 47-68). Hard-coded (not imported — see docstring).
EXPECTED_TEAM = {
    "pco.sale.order": "team_code",
    "pco.sale.order.line": "order_id.team_code",
    "pco.sale.order.payment": "order_id.team_code",
    "pco.sale.order.guarantee": "order_id.team_code",
}
EXPECTED_COMPANY = {
    "pco.sale.order": "company_id",
    "pco.sale.order.line": "order_id.company_id",
    "pco.sale.order.payment": "order_id.company_id",
    "pco.sale.order.guarantee": "order_id.company_id",
}


def _index(records):
    return {(r["model"], r["axis"]): r for r in records}


def test_vvuln_team_children_are_gaps():
    recs = _index(derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS))
    assert recs[("pco.sale.order", "team")]["verdict"] == "GOVERNED"
    for child in ("pco.sale.order.line", "pco.sale.order.payment", "pco.sale.order.guarantee"):
        r = recs[(child, "team")]
        assert r["verdict"] == "GAP", (child, r["verdict"])
        assert r["derived_closure"] == "order_id.team_code"


def test_vrule_line_governed_siblings_gap():
    recs = _index(derive_closures(EDGES, RULES_VRULE, DISCRIMINATORS, PCO_MODELS))
    assert recs[("pco.sale.order.line", "team")]["verdict"] == "GOVERNED"
    for sib in ("pco.sale.order.payment", "pco.sale.order.guarantee"):
        assert recs[(sib, "team")]["verdict"] == "GAP", sib
        assert recs[(sib, "team")]["derived_closure"] == "order_id.team_code"
    assert recs[("pco.sale.order", "team")]["verdict"] == "GOVERNED"


def test_company_axis_root_ungoverned_everywhere():
    for rules in (RULES_VVULN, RULES_VRULE):
        recs = _index(derive_closures(EDGES, rules, DISCRIMINATORS, PCO_MODELS))
        for m in PCO_MODELS:
            r = recs[(m, "company")]
            assert r["verdict"] == "ROOT-UNGOVERNED", (m, r["verdict"])
            assert r["derived_closure"] is None
            assert r["parent_governed"] is False


def test_relation_paths_match_policy():
    recs = _index(derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS))
    for m in PCO_MODELS:
        assert recs[(m, "team")]["relation_path"] == EXPECTED_TEAM[m], m
        assert recs[(m, "company")]["relation_path"] == EXPECTED_COMPANY[m], m


def test_hops_header_zero_children_one():
    recs = _index(derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS))
    assert recs[("pco.sale.order", "team")]["hops"] == 0
    assert recs[("pco.sale.order.line", "team")]["hops"] == 1


def test_decoy_edges_dont_shorten_path():
    recs = _index(derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS))
    # salesperson_id/customer_id edges must not hijack the team closure path.
    assert recs[("pco.sale.order.line", "team")]["relation_path"] == "order_id.team_code"


def test_determinism():
    a = derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS)
    b = derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, PCO_MODELS)
    assert a == b


def test_unreachable_model():
    scope = PCO_MODELS + ["pco.sale.order.note"]   # synthetic model with no edge
    recs = _index(derive_closures(EDGES, RULES_VVULN, DISCRIMINATORS, scope))
    r = recs[("pco.sale.order.note", "team")]
    assert r["verdict"] == "UNREACHABLE"
    assert r["reachable"] is False
    assert r["derived_closure"] is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
