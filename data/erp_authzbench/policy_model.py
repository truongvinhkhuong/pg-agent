# -*- coding: utf-8 -*-
"""ERP-AuthZBench — ABAC/ReBAC policy formalization (RQ7).

The guard's bespoke per-model `POLICY` (`team_path` / `company_path` / `owner_path`) is, when
named explicitly, an **instance of a general subject-context model** with three composable axes:

  * a **ReBAC relation-path** — the M2O closure from the model to the field's DEFINING model
    (`order_id.team_code` on a child, `team_code` on the header); equals the PCC-ERP BFS closure
    (`policy_closure._derive_path`).
  * an **ABAC attribute-predicate** — the terminal field + operator + subject-context RHS.
  * a **subject-context** of one of three kinds: group-membership (team), tenant-set (company),
    principal-id (owner).

This module is PURE (no Odoo) and **formalizes `pep_guard._authz_domain`** — the ENFORCED PEP
domain. It is deliberately distinct from `evaluation_script.ground_truth_domain` (the independent
leak oracle), which differs in the team leaf (`= code` vs the guard's `in [codes]`); this model
mirrors the guard, not the oracle.

`compile_policy` is a faithful TRANSCRIPTION of `_authz_domain`'s branch ladder (NOT a fold over
grants — the empty-team case is a whole-domain early-return), so it reproduces the guard's exact
effective domain leaf-for-leaf. A live round-trip in `evaluation_script.policy_model(env)` asserts
`compile_policy(...) == guard._authz_domain(model)` for every persona × model.

Honest scope: this ADDS NO ENFORCEMENT — it names what the guard already does. It formalizes only
the team/company/owner predicates that are actually enforced (the synthetic generator does not
populate state/date/region, so an ABAC predicate over those would be vacuous). NO LLM.
"""

from domain_ast import _CONTEXT_NAMES          # the recognized ABAC context-token registry
from policy_closure import _derive_path         # the ReBAC BFS closure over the M2O graph

# The M2O edge graph for the pco models (same graph the PCC-ERP closure tests use). A child
# reaches the header (the team/company definer) through `order_id`. Pure data describing the ORM.
PCO_EDGES = (
    ("pco.sale.order.line", "order_id", "pco.sale.order"),
    ("pco.sale.order.payment", "order_id", "pco.sale.order"),
    ("pco.sale.order.guarantee", "order_id", "pco.sale.order"),
)

# (POLICY key, axis, subject_context RHS, operator, gate, context_kind). Mirrors the exact leaf
# `_authz_domain` emits per axis. team's subject-context is a GROUP-MEMBERSHIP list (RBAC realized
# as a data predicate) — note its root is NOT in `_CONTEXT_NAMES`; company/owner are ABAC domain
# contexts whose roots ARE recognized.
_AXES = (
    ("team_path", "team", "group-membership", "in", None, "membership-set"),
    ("company_path", "company", "company_ids", "in", None, "tenant-set"),
    ("owner_path", "owner", "user.id", "=", "own_only", "principal-id"),
)


def _terminal(path):
    """Terminal attribute of a (possibly dotted) relation-path. `order_id.team_code` -> `team_code`."""
    return path.rsplit(".", 1)[-1]


def _definer_model(model, relation_path, edges):
    """Model that DEFINES the terminal attribute: follow the M2O prefix segments through `edges`.

    hops 0 (`team_code` on the header, `salesperson_id` on the line) -> the model itself.
    hops 1 (`order_id.team_code` on a child) -> the model reached via `order_id`.
    Returns None if a prefix segment is unresolved (should not happen for the pco paths).
    """
    segments = relation_path.split(".")
    cur = model
    for seg in segments[:-1]:                   # every segment except the terminal attribute
        nxt = next((tgt for (m, fld, tgt) in edges if m == cur and fld == seg), None)
        if nxt is None:
            return None
        cur = nxt
    return cur


def derive(policy_dict, edges=PCO_EDGES):
    """Decompose each POLICY entry into explicit ABAC×ReBAC grants (single source of truth = POLICY).

    Returns {model: [Grant]} where Grant =
      {axis, relation_path, attribute, hops, definer_model, subject_context, operator, gate, context_kind}.
    """
    out = {}
    for model, entry in policy_dict.items():
        grants = []
        for key, axis, subject_ctx, operator, gate, context_kind in _AXES:
            path = entry.get(key)
            if not path:
                continue
            grants.append({
                "axis": axis,
                "relation_path": path,
                "attribute": _terminal(path),
                "hops": path.count("."),
                "definer_model": _definer_model(model, path, edges),
                "subject_context": subject_ctx,
                "operator": operator,
                "gate": gate,
                "context_kind": context_kind,
            })
        out[model] = grants
    return out


def compile_policy(model, policy_entry, ctx):
    """Faithful transcription of `pep_guard._authz_domain`. Returns the leaf list, `[("id","=",0)]`
    (belongs-to-no-team empty set), or None (fail-closed deny) — byte-for-byte the guard's output.

    `ctx` carries the guard's OWN resolved values: {teams: list|None, company_ids: list, uid: int,
    own_only: bool}. Lists are passed through UNTOUCHED (no sort/copy) so leaf-tuple equality holds.
    """
    if policy_entry is None:
        return None                             # model not in POLICY -> deny (fail-closed)

    leaves = []

    teams = ctx.get("teams")
    if teams is not None:                       # restricted user
        team_path = policy_entry.get("team_path")
        if not team_path:
            return None                         # no way to scope this model by team -> deny
        if not teams:
            return [("id", "=", 0)]             # belongs to no team -> whole-domain empty set
        leaves.append((team_path, "in", teams))

    company_path = policy_entry.get("company_path")
    if company_path:
        leaves.append((company_path, "in", ctx.get("company_ids")))

    owner_path = policy_entry.get("owner_path")
    if owner_path and ctx.get("own_only"):
        leaves.append((owner_path, "=", ctx.get("uid")))

    return leaves


def classify(grant):
    """The RQ7 two-axis classification of a grant: ReBAC hops × ABAC/RBAC context kind."""
    return {"rebac_hops": grant["hops"], "context_kind": grant["context_kind"]}


def closure_matches(model, grant, edges=PCO_EDGES):
    """True iff the grant's relation_path equals the PCC-ERP BFS closure over the M2O graph.

    team/company -> a genuine relation closure (hops 0 on the header, hops 1 on a child).
    owner -> the degenerate hops-0 SELF-match (a local field; `policy_closure` deliberately excludes
    owner from relational-closure scope, so this is not a BFS path).
    """
    path, hops = _derive_path(model, edges, grant["definer_model"], grant["attribute"])
    return (path, hops) == (grant["relation_path"], grant["hops"])


def context_recognized(grant):
    """True iff the grant's subject-context root is a recognized ABAC context-token (`_CONTEXT_NAMES`).

    True for company (`company_ids`) and owner (`user.id`); FALSE for team — team is RBAC (group
    membership resolved via `has_group`), realized as a data-plane attribute predicate, and its
    `group-membership` token is NOT a domain context.
    """
    return grant["subject_context"].split(".")[0] in _CONTEXT_NAMES


def subject_context_kind(grant):
    """`abac-domain-context` (company/owner) vs `rbac-group-membership` (team)."""
    return "abac-domain-context" if context_recognized(grant) else "rbac-group-membership"


if __name__ == "__main__":
    _FIXTURE = {
        "pco.sale.order": {"team_path": "team_code", "company_path": "company_id", "owner_path": None},
        "pco.sale.order.line": {"team_path": "order_id.team_code",
                                "company_path": "order_id.company_id", "owner_path": "salesperson_id"},
    }
    for m, grants in derive(_FIXTURE).items():
        print(m)
        for g in grants:
            print("  %-8s hops=%d definer=%-22s ctx=%-16s closure=%s recognized=%s (%s)" % (
                g["axis"], g["hops"], g["definer_model"], g["subject_context"],
                closure_matches(m, g), context_recognized(g), subject_context_kind(g)))
