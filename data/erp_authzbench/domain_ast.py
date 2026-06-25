# -*- coding: utf-8 -*-
"""Pure ir.rule domain field-extractor for the policy-closure scanner (no Odoo).

Extracts the discriminator field-names a record-rule constrains, by PARSING (never
evaluating) the `domain_force` string. Odoo domains are Python list literals whose
operands may be Name/Attribute nodes (`user.id`, `company_ids`, `allowed_company_ids`)
— `ast.literal_eval` would raise on those, so we `ast.parse(..., mode="eval")` and walk
the tree, reading only leaf left-operands (field paths). The terminal path segment is
the discriminator (`order_id.company_id` -> `company_id`), so a child's parent-anchored
rule registers the same axis as the parent's own rule.

Also classifies each domain pushdownable-vs-complex (sets up the F10 emit step and is
honest about how much a relational closure could soundly cover).
"""
import ast

# Operators that mark a 3-element tuple as a genuine domain leaf (filters value tuples
# like ('a','b','c') that are not leaves). Pushdownable subset is narrower.
_OPERATORS = {
    "=", "!=", "<>", "in", "not in", "like", "not like", "ilike", "not ilike",
    "=like", "=ilike", ">", "<", ">=", "<=", "=?", "child_of", "parent_of",
    "any", "not any",
}
_PUSHDOWN_OPS = {"=", "in"}
_BOOL_TOKENS = {"|", "!"}        # OR / NOT make a domain non-conjunctive ('&' is implicit AND)


def _terminal(field_path):
    return field_path.rsplit(".", 1)[-1]


def parse_domain(domain_force):
    """Return (fields:set[str], pushdownable:bool, reason:str).

    fields       = terminal field-names referenced by leaf left-operands.
    pushdownable = exactly one distinct field AND no OR/NOT operators AND every leaf
                   operator in {=, in} (the relationally-pushdownable fragment).
    reason       = "simple" | "empty" | "no-field" | "unparseable" | a ';'-joined list
                   of "or/not" / "multi-field" / "op:<x>,<y>".
    Never raises: any parse error -> (set(), False, "unparseable").
    """
    src = (domain_force or "").strip()
    if not src:
        return set(), False, "empty"
    try:
        tree = ast.parse(src, mode="eval")
    except (SyntaxError, ValueError):
        return set(), False, "unparseable"

    fields, ops, has_bool = set(), [], False
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and node.value in _BOOL_TOKENS):
            has_bool = True
        if isinstance(node, (ast.Tuple, ast.List)) and len(node.elts) == 3:
            lhs, op = node.elts[0], node.elts[1]
            if (isinstance(lhs, ast.Constant) and isinstance(lhs.value, str)
                    and isinstance(op, ast.Constant) and op.value in _OPERATORS):
                fields.add(_terminal(lhs.value))
                ops.append(op.value)
    if not fields:
        return set(), False, "no-field"

    reasons = []
    if has_bool:
        reasons.append("or/not")
    if len(fields) > 1:
        reasons.append("multi-field")
    bad_ops = sorted({o for o in ops if o not in _PUSHDOWN_OPS})
    if bad_ops:
        reasons.append("op:" + ",".join(bad_ops))
    return (fields, True, "simple") if not reasons else (fields, False, ";".join(reasons))
