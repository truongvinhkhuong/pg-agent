# -*- coding: utf-8 -*-
"""Pure policy-closure derivation core for the ERP-AuthZBench differential linter (F10 PoC).

No Odoo dependency — operates on plain data so it is unit-testable offline. Given:
  - the ORM relation graph (Many2one edges),
  - which models carry a NATIVE row rule per governance axis,
  - the discriminator field per axis (and the model that defines it),
it decides, for each (model, axis), whether row-level authorization is GOVERNED, a GAP
(reachable to a governed parent but lacking its own rule), or ROOT-UNGOVERNED (the axis is
not enforced anywhere) — and DERIVES the relation-path closure (e.g. "order_id.team_code")
that a compiler would push down to fix a GAP.

This is the de-risking core for F10 (ERP Policy-Closure Compiler). The Odoo-shell driver
(tests/policy_linter.py) feeds it data read from ir.model.fields + ir.rule. The derivation
is independent of whether a rule exists, so a future author should note: the OWNER axis
(a local field, opt-in) is NOT a parent-pushdown target and is deliberately not modelled
here — only relational-closure axes (team/company) are.
"""

from collections import deque

VERDICTS = ("GOVERNED", "GAP", "ROOT-UNGOVERNED", "PARENT-UNGOVERNED", "UNREACHABLE")


def _derive_path(model, edges, def_model, field):
    """Relation path from `model` to `def_model`.`field`, or (None, None) if unreachable.

    `model == def_model` -> (field, 0). Otherwise BFS over Many2one edges
    (model, m2o_field, target_model). Deterministic: edges are scanned in input order at
    each frontier; the first path that reaches def_model wins. A `visited` set guards
    against cycles and is multi-hop-ready (path = "a_id.b_id.field").
    """
    if model == def_model:
        return field, 0
    visited = {model}
    queue = deque([(model, [], 0)])          # (current_model, field_prefix, hops)
    while queue:
        cur, prefix, hops = queue.popleft()
        for (m, fld, tgt) in edges:
            if m != cur:
                continue
            if tgt == def_model:
                return ".".join(prefix + [fld, field]), hops + 1
            if tgt not in visited:
                visited.add(tgt)
                queue.append((tgt, prefix + [fld], hops + 1))
    return None, None


def derive_closures(edges, rules_by_axis, discriminators, scope_models=None):
    """Classify every (model, axis) and derive the closure path for each GAP.

    edges:          list[(model, m2o_field, target_model)]
    rules_by_axis:  dict[axis -> set(models_with_a_native_rule_on_axis)]
    discriminators: dict[axis -> (defining_model, field)]
    scope_models:   iterable | None (default = models seen in edges + discriminator definers)

    Returns list[record] sorted by (model, axis) for deterministic output. Record:
        {model, axis, discriminator, relation_path|None, hops, reachable,
         axis_governed, parent_governed, native_rule, verdict, derived_closure|None}
    """
    if scope_models is None:
        scope_models = set()
        for (m, _f, t) in edges:
            scope_models.add(m)
            scope_models.add(t)
        for _axis, (dm, _fld) in discriminators.items():
            scope_models.add(dm)

    out = []
    for model in sorted(scope_models):
        for axis in sorted(discriminators):
            def_model, field = discriminators[axis]
            path, hops = _derive_path(model, edges, def_model, field)
            reachable = path is not None

            governed = rules_by_axis.get(axis) or set()
            axis_governed = bool(governed)
            parent_governed = def_model in governed
            native_rule = model in governed

            if not reachable:
                verdict = "UNREACHABLE"
            elif not axis_governed:
                verdict = "ROOT-UNGOVERNED"      # axis carries no rule anywhere (e.g. company)
            elif native_rule:
                verdict = "GOVERNED"
            elif parent_governed:
                verdict = "GAP"                  # the finding: reachable, parent ruled, self not
            else:
                verdict = "PARENT-UNGOVERNED"    # axis ruled elsewhere but not on this discriminator

            out.append({
                "model": model,
                "axis": axis,
                "discriminator": field,
                "relation_path": path,
                "hops": hops if hops is not None else -1,
                "reachable": reachable,
                "axis_governed": axis_governed,
                "parent_governed": parent_governed,
                "native_rule": native_rule,
                "verdict": verdict,
                "derived_closure": path if verdict == "GAP" else None,
            })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Module-agnostic generalization (F10 Increment 1): field-keyed, multi-definer.
# derive_closures above stays the single-definer PoC entry point (unchanged); the
# generalized scanner uses derive_gaps so a discriminator field may be DEFINED on
# many models (real Odoo: company_id/user_id live on dozens of models).
# ─────────────────────────────────────────────────────────────────────────────

def _nearest_definer_path(model, edges, hops0_definers, all_definers, field):
    """Relation path from `model` to the NEAREST model that defines `field`.

    hops0_definers : models eligible at hops 0 (genuine LOCAL definer of the field).
    all_definers   : models eligible as a BFS target at hops >= 1 (includes stored-
                     related mirrors — a parent reached through a child's M2O still
                     terminates a path).
    Returns (path|None, hops|None, definer_model|None). Deterministic: BFS by hop
    distance, frontier scanned in edge input order (pass canonically-sorted edges);
    the model itself is never a hops>=1 target (visited guard), so a stored-related
    mirror is forced to resolve to its real parent (the closure point).
    """
    if model in hops0_definers:
        return field, 0, model
    visited = {model}
    queue = deque([(model, [], 0)])
    while queue:
        cur, prefix, hops = queue.popleft()
        for (m, fld, tgt) in edges:
            if m != cur:
                continue
            if tgt in all_definers:
                return ".".join(prefix + [fld, field]), hops + 1, tgt
            if tgt not in visited:
                visited.add(tgt)
                queue.append((tgt, prefix + [fld], hops + 1))
    return None, None, None


def derive_gaps(edges, defines, ruled, scope_models, exclude_self_definer=None):
    """Module-agnostic generalization of derive_closures (field-keyed, multi-definer).

    edges:    list[(model, m2o_field, target_model)]  — Many2one graph (in-scope only)
    defines:  dict[field -> set(models that carry the STORED column)] — BFS targets
    ruled:    dict[field -> set(models with an active rule referencing field)]
              The discovered discriminators are exactly `set(ruled)`.
    scope_models: iterable[str] to classify.
    exclude_self_definer: dict[field -> set(models)] that carry the field ONLY as a
              stored-RELATED mirror -> excluded from hops-0 definers, forcing a
              relational closure (e.g. line.company_id mirror -> order_id.company_id,
              not the degenerate local company_id). Default: none.

    Reuses the same 5-verdict ladder as derive_closures, with parent_governed keyed on
    the NEAREST reached definer. Returns list[record] sorted by (model, field):
        {model, field, discriminator, relation_path|None, hops, reachable,
         axis_governed, parent_governed, native_rule, verdict, derived_closure|None,
         definer_model|None}
    """
    exclude_self_definer = exclude_self_definer or {}
    out = []
    for model in sorted(scope_models):
        for field in sorted(ruled):
            all_defs = defines.get(field) or set()
            hops0 = all_defs - (exclude_self_definer.get(field) or set())
            path, hops, definer = _nearest_definer_path(model, edges, hops0, all_defs, field)
            reachable = path is not None

            governed = ruled.get(field) or set()
            axis_governed = bool(governed)
            native_rule = model in governed
            parent_governed = (definer in governed) if definer is not None else False

            if not reachable:
                verdict = "UNREACHABLE"
            elif not axis_governed:
                verdict = "ROOT-UNGOVERNED"
            elif native_rule:
                verdict = "GOVERNED"
            elif parent_governed:
                verdict = "GAP"
            else:
                verdict = "PARENT-UNGOVERNED"

            out.append({
                "model": model,
                "field": field,
                "discriminator": field,
                "relation_path": path,
                "hops": hops if hops is not None else -1,
                "reachable": reachable,
                "axis_governed": axis_governed,
                "parent_governed": parent_governed,
                "native_rule": native_rule,
                "verdict": verdict,
                "derived_closure": path if verdict == "GAP" else None,
                "definer_model": definer,
            })
    return out
