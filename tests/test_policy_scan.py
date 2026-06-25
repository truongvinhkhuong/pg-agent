# -*- coding: utf-8 -*-
"""Offline unit tests for the module-agnostic scanner core (no Odoo, no LLM).

Covers data/erp_authzbench/policy_closure.derive_gaps (field-keyed multi-definer) and
data/erp_authzbench/domain_ast.parse_domain. Mirrors tests/test_output_validator.py.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data", "erp_authzbench"))
from policy_closure import derive_gaps      # noqa: E402
from domain_ast import parse_domain         # noqa: E402

# ── Fixtures: the pco mock as a field-keyed multi-definer graph ──────────────
PCO_MODELS = ["pco.sale.order", "pco.sale.order.line",
              "pco.sale.order.payment", "pco.sale.order.guarantee"]
EDGES = sorted([
    ("pco.sale.order.line", "order_id", "pco.sale.order"),
    ("pco.sale.order.payment", "order_id", "pco.sale.order"),
    ("pco.sale.order.guarantee", "order_id", "pco.sale.order"),
    ("pco.sale.order.line", "salesperson_id", "res.users"),    # decoy (res.users out of scope)
])
# team_code defined only on the header; company_id defined on header (genuine) AND on
# line as a stored-RELATED mirror (the real-Odoo pattern that must NOT become hops-0).
DEFINES = {
    "team_code": {"pco.sale.order"},
    "company_id": {"pco.sale.order", "pco.sale.order.line"},
}
MIRRORS = {"company_id": {"pco.sale.order.line"}}          # line.company_id is related=store
RULED_VVULN = {"team_code": {"pco.sale.order"}, "company_id": set()}
RULED_VRULE = {"team_code": {"pco.sale.order", "pco.sale.order.line"}, "company_id": set()}


def _index(records):
    return {(r["model"], r["field"]): r for r in records}


def test_derive_gaps_vvuln_matches_poc():
    recs = _index(derive_gaps(EDGES, DEFINES, RULED_VVULN, PCO_MODELS, MIRRORS))
    assert recs[("pco.sale.order", "team_code")]["verdict"] == "GOVERNED"
    for child in ("pco.sale.order.line", "pco.sale.order.payment", "pco.sale.order.guarantee"):
        r = recs[(child, "team_code")]
        assert r["verdict"] == "GAP", (child, r["verdict"])
        assert r["derived_closure"] == "order_id.team_code"


def test_derive_gaps_vrule_line_governed_siblings_gap():
    recs = _index(derive_gaps(EDGES, DEFINES, RULED_VRULE, PCO_MODELS, MIRRORS))
    assert recs[("pco.sale.order.line", "team_code")]["verdict"] == "GOVERNED"
    for sib in ("pco.sale.order.payment", "pco.sale.order.guarantee"):
        assert recs[(sib, "team_code")]["verdict"] == "GAP", sib


def test_stored_related_mirror_forces_relational_closure():
    # company_id is RULED on the header (so the axis is governed and the child reaches a
    # governed parent). The child carries company_id as a stored-related MIRROR.
    ruled = {"company_id": {"pco.sale.order"}}
    with_fix = _index(derive_gaps(EDGES, DEFINES, ruled, PCO_MODELS, MIRRORS))
    r = with_fix[("pco.sale.order.line", "company_id")]
    assert r["hops"] == 1, r["hops"]
    assert r["relation_path"] == "order_id.company_id"     # NOT the degenerate "company_id"
    assert r["verdict"] == "GAP"

    # Without the mirror exclusion, the child would degenerate to its own hops-0 column.
    without_fix = _index(derive_gaps(EDGES, DEFINES, ruled, PCO_MODELS, exclude_self_definer=None))
    bad = without_fix[("pco.sale.order.line", "company_id")]
    assert bad["hops"] == 0 and bad["relation_path"] == "company_id"


def test_company_root_ungoverned_when_no_rule():
    recs = _index(derive_gaps(EDGES, DEFINES, RULED_VVULN, PCO_MODELS, MIRRORS))
    for m in PCO_MODELS:
        assert recs[(m, "company_id")]["verdict"] == "ROOT-UNGOVERNED", m


def test_multi_definer_nearest_wins_and_deterministic():
    # a -> b -> c, field defined on both b (hops1) and c (hops2); nearest (b) wins.
    edges = sorted([("a", "b_id", "b"), ("b", "c_id", "c")])
    defines = {"x": {"b", "c"}}
    ruled = {"x": {"c"}}            # only the far definer is governed
    recs = _index(derive_gaps(edges, defines, ruled, ["a", "b", "c"], None))
    ra = recs[("a", "x")]
    assert ra["relation_path"] == "b_id.x" and ra["hops"] == 1 and ra["definer_model"] == "b"
    # b reaches its own field at hops 0 (genuine definer) -> not a relational closure
    assert recs[("b", "x")]["hops"] == 0
    assert derive_gaps(edges, defines, ruled, ["a", "b", "c"], None) == \
        derive_gaps(edges, defines, ruled, ["a", "b", "c"], None)


def test_parent_ungoverned_vs_gap():
    # axis governed somewhere (c) but the model's nearest definer (itself, b) is ungoverned.
    edges = sorted([("a", "b_id", "b")])
    defines = {"x": {"a", "b", "c"}}
    ruled = {"x": {"c"}}           # only the unreachable c is governed
    recs = _index(derive_gaps(edges, defines, ruled, ["a", "b", "c"], None))
    # `a` defines x locally (hops0) and is ungoverned; its definer is itself, not a
    # governed parent -> PARENT-UNGOVERNED (a local-rule fix, not a relational closure).
    assert recs[("a", "x")]["verdict"] == "PARENT-UNGOVERNED"


def test_unreachable_when_field_undefined_anywhere_reachable():
    edges = sorted([("p", "q_id", "q")])
    defines = {"x": {"z"}}         # z not reachable from p/q
    ruled = {"x": {"z"}}
    recs = _index(derive_gaps(edges, defines, ruled, ["p", "q"], None))
    assert recs[("p", "x")]["verdict"] == "UNREACHABLE"


# ── parse_domain (real Odoo domain strings) ──────────────────────────────────
def test_parse_simple_pushdownable():
    for src, field in [("[('user_id','=',user.id)]", "user_id"),
                       ("[('company_id','in',company_ids)]", "company_id"),
                       ("[('order_id.company_id','in',company_ids)]", "company_id")]:
        fields, simple, reason = parse_domain(src)
        assert fields == {field}, (src, fields)
        assert simple is True, (src, reason)


def test_parse_complex_or():
    fields, simple, reason = parse_domain(
        "['|',('company_id','=',False),('company_id','in',allowed_company_ids)]")
    assert fields == {"company_id"} and simple is False and "or/not" in reason


def test_parse_complex_multifield():
    fields, simple, reason = parse_domain("[('team_id','in',t),('user_id','=',user.id)]")
    assert fields == {"team_id", "user_id"} and simple is False and "multi-field" in reason


def test_parse_complex_operator():
    fields, simple, reason = parse_domain("[('state','!=','draft')]")
    assert fields == {"state"} and simple is False and reason.startswith("op:")


def test_parse_global_rule_has_no_field():
    fields, simple, reason = parse_domain("[(1,'=',1)]")
    assert fields == set() and simple is False and reason == "no-field"


def test_parse_unparseable_never_raises():
    fields, simple, reason = parse_domain("[('a','=',1)")   # missing closing bracket
    assert fields == set() and simple is False and reason == "unparseable"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
