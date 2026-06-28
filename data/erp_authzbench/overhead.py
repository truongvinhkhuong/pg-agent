# -*- coding: utf-8 -*-
"""ERP-AuthZBench — structural overhead of the PEP rewrite (§4.8), pure + offline.

The PEP rewrites every query (forced row-domain + masking + uniform-denial); reviewers ask "what
does it cost?". This module characterizes the overhead as a STRUCTURAL BOUND — a closed-form
function of the committed POLICY + SENSITIVITY, NOT a latency. The headline claim is that the added
work has no super-linear term:

  * the forced row-domain adds `authz_leaves` (<=3) conjuncts, each a relation-path traversal of
    depth `closure_hops` (<=1 here: a child reaches its team/company definer through the single FK
    `order_id`) over an INDEXED FK — realized by Odoo as an INNER JOIN or a correlated sub-select,
    bounded by the path depth + the FK index (no per-row scan, no cross-product);
  * masking is an in-process post-fetch scan of O(result_rows * masked_fields), no extra round-trip.

`closure_hops` is a relation-path DEPTH (true by construction = `path.count('.')`, the same BFS
closure §5.4 certifies) — NOT a query-plan claim. We never assert a specific plan.

PURE (no Odoo). It REUSES the single sources of truth: `policy_model.compile_policy` (the
RQ7-calibrated transcription of `_authz_domain`, proven `== guard._authz_domain` 20/20) for the
forced-domain leaves, and the pure `sensitivity` registry for the mask universe. The live driver
`evaluation_script.overhead(env)` re-measures the SAME metrics through the REAL guard, and
`tests/test_overhead.py` calibrates pure == committed CSV — the policy_model/write_model
non-circular pattern. `POLICY` here is a fixture drift-guarded against the live `pep_guard.POLICY`.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "addons", "pg_agent_guard", "models"))
import sensitivity                                  # noqa: E402  (pure registry — single source of truth)
import policy_model as pm                           # noqa: E402  (compile_policy == guard._authz_domain)

# Fixture copy of pep_guard.POLICY (which lives in an Odoo-importing module). The live driver asserts
# the REAL POLICY equals this, so a drift on either side fails CI on both sides.
POLICY = {
    "pco.sale.order": {"team_path": "team_code", "company_path": "company_id", "owner_path": None},
    "pco.sale.order.line": {"team_path": "order_id.team_code",
                            "company_path": "order_id.company_id", "owner_path": "salesperson_id"},
    "pco.sale.order.payment": {"team_path": "order_id.team_code",
                               "company_path": "order_id.company_id", "owner_path": None},
    "pco.sale.order.guarantee": {"team_path": "order_id.team_code",
                                 "company_path": "order_id.company_id", "owner_path": None},
}

# Per-persona resolved context (mirrors evaluation_script.PERSONAS, declared order). Only the fields
# that affect the STRUCTURAL counts are meaningful: `teams` (None = see-all) drives the team leaf,
# `own_only` the owner leaf, `groups` the clearance. company_ids/uid are placeholders (a company/owner
# leaf is present-or-absent independent of the id VALUES, so the counts are id-independent -> stable).
PERSONA_CTX = {
    "ttv":        {"teams": ["ttv"], "own_only": False, "groups": {"pco_core_mock.group_team_ttv"}},
    "ttf":        {"teams": ["ttf"], "own_only": False, "groups": {"pco_core_mock.group_team_ttf"}},
    "ttv_c1":     {"teams": ["ttv"], "own_only": False, "groups": {"pco_core_mock.group_team_ttv"}},
    "viewer_all": {"teams": None,    "own_only": False, "groups": {"pco_core_mock.group_team_view_all"}},
    "sales_own":  {"teams": ["ttv"], "own_only": True,
                   "groups": {"pco_core_mock.group_team_ttv", "pg_agent_guard.group_pep_own_only"}},
}

FIELDS = ["persona", "model", "clearance", "authz_leaves", "closure_hops",
          "team_scoped", "company_scoped", "owner_scoped",
          "sensitivity_surface", "masked_fields", "mask_cost_class"]

# Constant claim-strings — committing the COMPLEXITY itself (byte-checked), not just the counts.
MASK_COST_CLASS = "O(result_rows*masked_fields)"
COMPLEXITY = {
    "authz": "O(closure_hops indexed-FK traversals + authz_leaves indexed predicates)",
    "masking": MASK_COST_CLASS,
}

_DENY = -1                                          # sentinel: fail-closed deny != see-all 0-leaves


def authz_leaves(model, entry, ctx):
    """Number of forced-domain conjuncts the PEP AND-s onto the caller domain, via the
    RQ7-calibrated `compile_policy`. `_DENY` for a fail-closed deny (model not scopable)."""
    leaves = pm.compile_policy(model, entry, ctx)
    return _DENY if leaves is None else len(leaves)


def closure_hops(model, entry, ctx):
    """Max relation-path DEPTH across the forced leaves (0 header / 1 child); 0 if none/denied."""
    leaves = pm.compile_policy(model, entry, ctx)
    if not leaves:
        return 0
    return max(path.count(".") for path, _op, _v in leaves)


def scope_flags(model, entry, ctx):
    """(team_scoped, company_scoped, owner_scoped): is each axis's leaf actually present?"""
    leaves = pm.compile_policy(model, entry, ctx) or []
    paths = {path for path, _op, _v in leaves}
    return (entry.get("team_path") in paths,
            entry.get("company_path") in paths,
            entry.get("owner_path") in paths)


def sensitivity_surface(model):
    """The model's full declared sensitivity-tagged field set (the mask universe) — a CONSERVATIVE,
    not query-specific, upper bound on the per-row mask cost. Stable, not cherry-picked."""
    return sorted(sensitivity.SENSITIVITY.get(model, {}).keys())


def masked_count(model, clearance):
    """How many of the model's declared sensitivity surface are masked at this clearance."""
    _visible, masked = sensitivity.partition_fields(model, sensitivity_surface(model), clearance)
    return len(masked)


def overhead_row(persona_key, model):
    """One CSV row of structural overhead for a (persona, model), purely from POLICY + SENSITIVITY."""
    entry = POLICY[model]
    ctx = dict(PERSONA_CTX[persona_key], company_ids=[1], uid=1)   # id placeholders (count-irrelevant)
    clearance = sensitivity.user_clearance(ctx["groups"])
    team, company, owner = scope_flags(model, entry, ctx)
    return {
        "persona": persona_key, "model": model, "clearance": clearance,
        "authz_leaves": authz_leaves(model, entry, ctx),
        "closure_hops": closure_hops(model, entry, ctx),
        "team_scoped": team, "company_scoped": company, "owner_scoped": owner,
        "sensitivity_surface": len(sensitivity_surface(model)),
        "masked_fields": masked_count(model, clearance),
        "mask_cost_class": MASK_COST_CLASS,
    }


def predict_rows():
    """The full 20-row (5 persona x 4 model) prediction, declared order — the offline calibration set."""
    return [overhead_row(p, m) for p in PERSONA_CTX for m in POLICY]


if __name__ == "__main__":
    for r in predict_rows():
        print("%-11s %-26s clr=%-12s leaves=%2d hops=%d scope=%d%d%d surface=%2d masked=%2d" % (
            r["persona"], r["model"], r["clearance"], r["authz_leaves"], r["closure_hops"],
            r["team_scoped"], r["company_scoped"], r["owner_scoped"],
            r["sensitivity_surface"], r["masked_fields"]))
