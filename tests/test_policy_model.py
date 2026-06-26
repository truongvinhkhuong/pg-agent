# -*- coding: utf-8 -*-
"""Offline tests for the ABAC/ReBAC formalization (RQ7).

No Odoo, no LLM. The load-bearing test is `test_compile_policy_round_trip_*`: `compile_policy`
reproduces `pep_guard._authz_domain`'s exact effective domain (leaves, order, fail-closed None,
empty-set short-circuit) — the live driver `evaluation_script.policy_model(env)` then proves the
same equivalence against the real guard. Mirrors test_policy_closure / test_metrics_and_consistency
(hard-coded fixture POLICY: pep_guard imports odoo, so the real POLICY can't load offline; the live
driver guards against fixture drift).
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
import policy_model as pm                        # noqa: E402
import domain_ast                                # noqa: E402
import policy_closure                            # noqa: E402

# Fixture mirrors pep_guard.POLICY lines 47-68 (source of truth; hard-coded, not imported).
FIXTURE_POLICY = {
    "pco.sale.order": {"team_path": "team_code", "company_path": "company_id", "owner_path": None},
    "pco.sale.order.line": {"team_path": "order_id.team_code",
                            "company_path": "order_id.company_id", "owner_path": "salesperson_id"},
    "pco.sale.order.payment": {"team_path": "order_id.team_code",
                               "company_path": "order_id.company_id", "owner_path": None},
    "pco.sale.order.guarantee": {"team_path": "order_id.team_code",
                                 "company_path": "order_id.company_id", "owner_path": None},
}
GRANTS = pm.derive(FIXTURE_POLICY)


def _ctx(teams, company_ids, uid=7, own_only=False):
    return {"teams": teams, "company_ids": company_ids, "uid": uid, "own_only": own_only}


# ── derive() shape ───────────────────────────────────────────────────────────
def test_derive_axes_per_model():
    assert [g["axis"] for g in GRANTS["pco.sale.order"]] == ["team", "company"]
    assert [g["axis"] for g in GRANTS["pco.sale.order.line"]] == ["team", "company", "owner"]
    for m in ("pco.sale.order.payment", "pco.sale.order.guarantee"):
        assert [g["axis"] for g in GRANTS[m]] == ["team", "company"]   # owner_path None -> no owner grant


def test_grant_fields_consistent():
    for model, grants in GRANTS.items():
        for g in grants:
            assert g["attribute"] == g["relation_path"].rsplit(".", 1)[-1]
            assert g["hops"] == g["relation_path"].count(".")
            assert g["operator"] in ("in", "=")


# ── compile_policy round-trip: reproduce _authz_domain exactly ───────────────
def test_round_trip_restricted_team_and_company():
    ctx = _ctx(["ttv"], [1])
    assert pm.compile_policy("pco.sale.order.line", FIXTURE_POLICY["pco.sale.order.line"], ctx) == [
        ("order_id.team_code", "in", ["ttv"]),
        ("order_id.company_id", "in", [1]),
    ]
    assert pm.compile_policy("pco.sale.order", FIXTURE_POLICY["pco.sale.order"], ctx) == [
        ("team_code", "in", ["ttv"]),
        ("company_id", "in", [1]),
    ]


def test_round_trip_see_all_omits_team_leaf():
    ctx = _ctx(None, [1, 2])                      # viewer_all / admin -> teams None
    assert pm.compile_policy("pco.sale.order.line", FIXTURE_POLICY["pco.sale.order.line"], ctx) == [
        ("order_id.company_id", "in", [1, 2]),
    ]


def test_round_trip_own_only_adds_owner_leaf():
    ctx = _ctx(["ttv"], [1], uid=7, own_only=True)
    assert pm.compile_policy("pco.sale.order.line", FIXTURE_POLICY["pco.sale.order.line"], ctx) == [
        ("order_id.team_code", "in", ["ttv"]),
        ("order_id.company_id", "in", [1]),
        ("salesperson_id", "=", 7),
    ]
    # own_only set but model has no owner_path -> NO owner leaf
    assert pm.compile_policy("pco.sale.order.payment", FIXTURE_POLICY["pco.sale.order.payment"], ctx) == [
        ("order_id.team_code", "in", ["ttv"]),
        ("order_id.company_id", "in", [1]),
    ]


def test_round_trip_empty_team_is_whole_domain_short_circuit():
    # belongs to no team -> [("id","=",0)] and NOTHING else (company/owner suppressed).
    ctx = _ctx([], [1], own_only=True)
    assert pm.compile_policy("pco.sale.order.line", FIXTURE_POLICY["pco.sale.order.line"], ctx) == [("id", "=", 0)]


def test_round_trip_deny_paths_return_none():
    ctx = _ctx(["ttv"], [1])
    assert pm.compile_policy("pco.sale.order.X", None, ctx) is None        # model not in POLICY
    no_team = {"team_path": None, "company_path": "company_id", "owner_path": None}
    assert pm.compile_policy("m", no_team, ctx) is None                    # restricted + no team_path


def test_round_trip_preserves_team_list_order():
    # leaf-tuple equality is order-sensitive; compile must pass the list through untouched.
    ctx = _ctx(["ttf", "ttv"], [2, 1])
    leaves = pm.compile_policy("pco.sale.order", FIXTURE_POLICY["pco.sale.order"], ctx)
    assert leaves == [("team_code", "in", ["ttf", "ttv"]), ("company_id", "in", [2, 1])]


# ── classify + F10 cross-checks (ReBAC closure / ABAC context) ───────────────
def test_closure_matches_team_company_owner():
    for model, grants in GRANTS.items():
        for g in grants:
            assert pm.closure_matches(model, g), (model, g["axis"])
    # explicit hops: header axes hops 0, child team/company hops 1, owner hops 0
    assert pm.classify(GRANTS["pco.sale.order"][0])["rebac_hops"] == 0
    assert pm.classify(GRANTS["pco.sale.order.line"][0])["rebac_hops"] == 1
    owner = [g for g in GRANTS["pco.sale.order.line"] if g["axis"] == "owner"][0]
    assert owner["hops"] == 0 and owner["definer_model"] == "pco.sale.order.line"


def test_context_recognized_company_owner_true_team_false():
    for model, grants in GRANTS.items():
        for g in grants:
            if g["axis"] == "team":
                assert pm.context_recognized(g) is False               # team is RBAC, not _CONTEXT_NAMES
                assert pm.subject_context_kind(g) == "rbac-group-membership"
            else:                                                      # company / owner are ABAC contexts
                assert pm.context_recognized(g) is True, (model, g["axis"])
                assert pm.subject_context_kind(g) == "abac-domain-context"


# ── drift-proof: policy_model reuses the REAL F10 functions, not local copies ──
def test_reuses_real_f10_machinery():
    assert pm._CONTEXT_NAMES is domain_ast._CONTEXT_NAMES
    assert pm._derive_path is policy_closure._derive_path


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} policy-model (RQ7) tests passed.")
