# -*- coding: utf-8 -*-
"""PCC-ERP — soundness theorem for relation-path pushdown (pure, no Odoo).

PCC-ERP fixes a relational-traversal gap by EMITTING a child record-rule from the parent's: push the parent
domain `D_P` down the containment relation `r` (each leaf field-path `f` -> `r.f`). The original emit gate
(`domain_ast.parse_domain`, "pushdownable") is CONSERVATIVE — single `{=,in}` leaf, no OR/NOT. This module
proves a strictly-TIGHTER SOUND gate and characterizes the real frontier.

THEOREM. Let `r` be the F10 containment relation: a stored Many2one that is `required` (TOTAL) and
`ondelete=cascade` — hence a FUNCTIONAL + TOTAL map c -> unique existing parent pi(c). For a parent domain
`D_P`, `pushdown(D_P, r)` admits exactly the children c whose pi(c) is admitted by the parent's OPERATIVE gate
iff:
  (1) OP-VALUE-COMPARISON: every leaf operator is a value-comparison (=, !=, <>, in, not in, <, >, <=, >=,
      like, not like, ilike, not ilike, =like, =ilike) and NONE is hierarchical/subquery
      (child_of, parent_of, any, not any) nor the surprising `=?` (excluded, conservative);
  (2) LEAF-STORED: every leaf left-path is stored/searchable on P (dotted paths through P's own m2m/o2m are
      fine — the existential commutes through a functional+total r);
  (3) P-ACTIVE-CLEAN: the operative parent gate is `D_P AND active_test(P)`; pushdown reproduces only `D_P`, so
      a child of an ARCHIVED parent could be admitted while the parent rule rejects it. Fix: when P has an
      `active` field, the emit RE-IMPOSES `(r.active, '=', True)` (an explicit value-comparison leaf) — keeping
      soundness; else (conservative) -> manual-review.
BOOLEAN STRUCTURE (AND/OR/NOT, nesting, multi-field) imposes NO precondition. Proof (structural induction): r
functional+total => each value-comparison leaf `(r.f, op, v)` on c equals `(f, op, v)` on pi(c); the combinators
&/|/! are pointwise on the same c (same pi(c)); hence pushdown(D_P,r)(c) = D_P(pi(c)). QED.

We WITHHOLD (manual-review), we do NOT refute, the hierarchical/subquery cases — their dotted-rewrite expansion
semantics are implementation-dependent. This is a sound, conservative frontier, not a general domain prover.
"""
import ast

from domain_ast import _OPERATORS                      # the recognized domain-leaf operators (lockstep)

# Operators whose semantics do NOT commute with the relation rewrite (hierarchical recursion / subquery), plus
# `=?` (the "equals-if-truthy" operator — technically sound but surprising; excluded at zero cost).
_EXCLUDED_OPS = frozenset({"child_of", "parent_of", "any", "not any", "=?"})
VALUE_COMPARISON_OPS = frozenset(_OPERATORS) - _EXCLUDED_OPS


def _parse(domain_force):
    src = (domain_force or "").strip()
    if not src:
        return "empty"
    try:
        return ast.parse(src, mode="eval")
    except (SyntaxError, ValueError):
        return "unparseable"


def _leaves(tree):
    """Yield (leaf_node, lhs_const, op_value) for every 3-element domain leaf (parse, never evaluate)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) == 3:
            lhs, op = node.elts[0], node.elts[1]
            if (isinstance(lhs, ast.Constant) and isinstance(lhs.value, str)
                    and isinstance(op, ast.Constant) and op.value in _OPERATORS):
                yield node, lhs, op.value


def pushdown_sound(domain_force, parent_active_sensitive=False):
    """(bool, reason): is `pushdown(domain_force, r)` SOUND for an F10 containment r?

    True iff every leaf operator is a value-comparison (no child_of/parent_of/any/not any/=?). Boolean
    structure (or/not, multi-field) is irrelevant — it is sound. `parent_active_sensitive=True` means the
    parent is active-bearing AND the emit does NOT re-impose `r.active` -> (False, "active-sensitive")
    (the conservative path; `pushdown(..., parent_has_active=True)` re-imposes it and stays sound).
    """
    tree = _parse(domain_force)
    if isinstance(tree, str):
        return False, tree                              # "empty" / "unparseable"
    ops = [op for _n, _l, op in _leaves(tree)]
    if not ops:
        return False, "no-field"
    excluded = sorted(set(ops) & _EXCLUDED_OPS)
    if excluded:
        return False, "op:" + ",".join(excluded)
    if parent_active_sensitive:
        return False, "active-sensitive"
    return True, "value-comparison"


def reclassify(reason, parent_active_sensitive=False):
    """Theorem verdict from a `domain_ast.parse_domain` reason string (offline re-classification primitive).

    parse_domain appends `op:<x>` for EVERY operator not in {=,in}, and all excluded ops are recognized leaf
    operators -> an excluded op ALWAYS surfaces in `reason` and can never hide. So the verdict reads cleanly:
    sound iff no op-token is excluded (or/not and multi-field are sound), and P-ACTIVE-CLEAN holds.
    """
    if reason in ("empty", "no-field", "unparseable"):
        return False, reason
    excluded = []
    for tok in reason.split(";"):
        if tok.startswith("op:"):
            excluded += [o for o in tok[3:].split(",") if o in _EXCLUDED_OPS]
    if excluded:
        return False, "op:" + ",".join(sorted(set(excluded)))
    if parent_active_sensitive:
        return False, "active-sensitive"
    return True, "value-comparison"


def pushdown(domain_force, relation_field, parent_has_active=False):
    """Rewrite each leaf's left field-path `f` -> `relation_field.f`, preserving &/|/! and structure; when
    `parent_has_active`, prepend `(relation_field.active, '=', True)` (AND) so the emit re-imposes the parent's
    active gate (P-ACTIVE-CLEAN). Returns the emitted child domain string. Raises ValueError on an unsound or
    unparseable domain (callers gate on `pushdown_sound` first)."""
    ok, why = pushdown_sound(domain_force)
    if not ok:
        raise ValueError("not soundly pushdownable: %s" % why)
    tree = ast.parse(domain_force.strip(), mode="eval")
    for _node, lhs, _op in _leaves(tree):
        lhs.value = "%s.%s" % (relation_field, lhs.value)       # f -> r.f (RHS kept verbatim)
    body = tree.body
    if parent_has_active:
        active_leaf = ast.Tuple(elts=[ast.Constant("%s.active" % relation_field),
                                      ast.Constant("="), ast.Constant(True)], ctx=ast.Load())
        body.elts = [active_leaf] + list(body.elts)             # prepend -> implicit AND
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)
