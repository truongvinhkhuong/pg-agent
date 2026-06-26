# -*- coding: utf-8 -*-
"""Offline unit tests for the emit core (F10 Increment 2; no Odoo). Mirrors test_policy_closure."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data", "erp_authzbench"))
from policy_closure import derive_closures                          # noqa: E402
from policy_emit import emit_policy, emit_ir_rule_domain, classify_emit   # noqa: E402

PCO_MODELS = ["pco.sale.order", "pco.sale.order.line",
              "pco.sale.order.payment", "pco.sale.order.guarantee"]
EDGES = sorted([
    ("pco.sale.order.line", "order_id", "pco.sale.order"),
    ("pco.sale.order.payment", "order_id", "pco.sale.order"),
    ("pco.sale.order.guarantee", "order_id", "pco.sale.order"),
])
DISCR = {"team": ("pco.sale.order", "team_code"), "company": ("pco.sale.order", "company_id")}
RULES = {"team": {"pco.sale.order"}, "company": {"pco.sale.order"}}   # both axes governed -> reachable


def test_emit_policy_reproduces_pco_paths():
    pol = emit_policy(derive_closures(EDGES, RULES, DISCR, PCO_MODELS))
    assert pol["pco.sale.order"]["team_path"] == "team_code"
    assert pol["pco.sale.order"]["company_path"] == "company_id"
    for child in ("pco.sale.order.line", "pco.sale.order.payment", "pco.sale.order.guarantee"):
        assert pol[child]["team_path"] == "order_id.team_code", child
        assert pol[child]["company_path"] == "order_id.company_id", child


def test_emit_policy_owner_path_always_none():
    pol = emit_policy(derive_closures(EDGES, RULES, DISCR, PCO_MODELS))
    for m in PCO_MODELS:
        assert pol[m]["owner_path"] is None, m


def test_emit_policy_skips_unreachable():
    # company axis ungoverned + a synthetic unreachable model still yields no spurious entry.
    recs = derive_closures(EDGES, {"team": {"pco.sale.order"}, "company": set()},
                           DISCR, PCO_MODELS + ["pco.x.note"])
    pol = emit_policy(recs)
    assert "pco.x.note" not in pol                       # unreachable -> no entry
    assert pol["pco.sale.order.line"]["company_path"] == "order_id.company_id"  # company still reachable


def test_emit_policy_determinism():
    recs = derive_closures(EDGES, RULES, DISCR, PCO_MODELS)
    assert emit_policy(recs) == emit_policy(recs)


def test_emit_domain_pushdownable_company():
    d, status = emit_ir_rule_domain(
        {"field": "company_id", "relation_path": "storage_category_id.company_id"}, True, "simple")
    assert status == "pushdownable"
    assert d == "[('storage_category_id.company_id', 'in', company_ids)]"


def test_emit_domain_pushdownable_user():
    d, status = emit_ir_rule_domain(
        {"field": "user_id", "relation_path": "order_id.user_id"}, True, "simple")
    assert status == "pushdownable" and d == "[('order_id.user_id', '=', user.id)]"


def test_emit_domain_manual_review():
    d, status = emit_ir_rule_domain(
        {"field": "user_id", "relation_path": "order_id.user_id"}, False, "or/not")
    assert d is None and status == "manual-review:or/not"


# The 5 real Odoo CE gaps (Increment 1b) + their PARENT-rule pushdownability.
_REAL_GAPS = [
    {"model": "sale.order.line", "field": "user_id",
     "relation_path": "order_id.user_id", "definer_model": "sale.order"},
    {"model": "account.payment.term.line", "field": "company_id",
     "relation_path": "payment_id.company_id", "definer_model": "account.payment.term"},
    {"model": "account.fiscal.position.account", "field": "company_id",
     "relation_path": "position_id.company_id", "definer_model": "account.fiscal.position"},
    {"model": "account.bank.statement.line", "field": "invoice_user_id",
     "relation_path": "move_id.invoice_user_id", "definer_model": "account.move"},
    {"model": "stock.storage.category.capacity", "field": "company_id",
     "relation_path": "storage_category_id.company_id", "definer_model": "stock.storage.category"},
]
_REAL_PARENTS = {
    ("sale.order", "user_id"): (False, "or/not"),
    ("account.payment.term", "company_id"): (False, "or/not;op:parent_of"),
    ("account.fiscal.position", "company_id"): (False, "op:parent_of"),
    ("account.move", "invoice_user_id"): (False, "or/not;multi-field"),
    ("stock.storage.category", "company_id"): (True, "simple"),
}


def test_classify_emit_real_gaps_1_of_5():
    rows, n_push = classify_emit(_REAL_GAPS, _REAL_PARENTS)
    assert n_push == 1
    assert sum(1 for r in rows if r["emit_status"] == "pushdownable") == 1
    assert sum(1 for r in rows if r["emit_status"].startswith("manual-review")) == 4
    push = [r for r in rows if r["emit_status"] == "pushdownable"][0]
    assert push["model"] == "stock.storage.category.capacity"
    assert push["emitted_domain"] == "[('storage_category_id.company_id', 'in', company_ids)]"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
