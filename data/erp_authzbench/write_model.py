# -*- coding: utf-8 -*-
"""ERP-AuthZBench — write/mutation attack suite (RQ10), pure + offline.

The read suite shows a relational-traversal LEAK: a child relation with no record rule
of its own returns other teams' rows when queried directly. The SAME confused-deputy gap
exists on the WRITE side — native Odoo does NOT re-apply a parent's record rule when a
child is mutated directly, so a child without a rule is writable across teams once an
operational user holds coarse create/write/unlink ACL (the realistic ERP misconfiguration:
sales staff legitimately manage an order's lines/payments/guarantees, but the record-rule
scoping is forgotten on the children). The PEP closes it with a forced write-check:
USING (a write/unlink target row must be in the authorization domain) + WITH-CHECK (any
governed FK being SET must resolve to an in-domain parent).

This module is the SINGLE SOURCE OF TRUTH for the attack specs + the expected verdicts,
self-contained (no Odoo). The live driver (`write_attacks` in tests/evaluation_script.py)
injects the runtime ids and measures the real Odoo behaviour; the offline calibration test
(tests/test_write_model.py) checks the committed results/write_attacks.csv against the
expected verdicts here. Mirrors data/erp_authzbench/policy_model.py (pure) + its driver.
"""

# Child models governed only via the FK traversal `order_id.team_code` — i.e. NO record
# rule of their own in V-vuln (payment/guarantee in both variants). The driver injects the
# foreign `order_id` (create/reassign) or the foreign target row (write/unlink) at runtime.
CHILD_MODELS = (
    "pco.sale.order.line",
    "pco.sale.order.payment",
    "pco.sale.order.guarantee",
)

# Minimal valid create vals per child (required field + a probe value). `order_id` is
# injected by the driver to point at ANOTHER team's order (the confused-deputy target).
CREATE_FIELDS = {
    "pco.sale.order.line": {"product_name": "wa-probe", "quantity": 1.0},
    "pco.sale.order.payment": {"payment_type": "wa-probe", "amount": 1.0},
    "pco.sale.order.guarantee": {"guarantee_type": "wa-probe", "guarantee_value": 1.0},
}

# A writable scalar + a sentinel value unlikely to collide with seeded data, used by the
# write-foreign-child family (overwrite a foreign team's row) — breach iff the value sticks.
WRITE_FIELD = {
    "pco.sale.order.line": ("price_unit", 123456.78),
    "pco.sale.order.payment": ("amount", 123456.78),
    "pco.sale.order.guarantee": ("guarantee_value", 123456.78),
}

# (family, op, vector-template). Each is instantiated once per child model.
FAMILIES = (
    ("write-create-foreign-parent", "create", "create a {c} on another team's order"),
    ("write-foreign-child",         "write",  "overwrite a foreign team's {c} row"),
    ("unlink-foreign-child",        "unlink", "delete a foreign team's {c} row"),
    ("cross-team-reassignment",     "write",  "reassign an owned {c} to a foreign order (WITH-CHECK)"),
)

_ABBR = {
    "write-create-foreign-parent": "create",
    "write-foreign-child": "update",
    "unlink-foreign-child": "unlink",
    "cross-team-reassignment": "reassign",
}


def short(model):
    """`pco.sale.order.payment` -> `payment` (CSV-friendly, stable)."""
    return model.rsplit(".", 1)[1]


def generate(persona="ttv"):
    """The full write-attack list (4 families x 3 child models = 12), deterministic order.

    Every attack is a confused-deputy WRITE constructed to touch a FOREIGN-team parent/row,
    so under the vulnerable variant the undefended path breaches and the guarded path must
    deny — all `in_scope=True` (the PEP claims authority over every one).
    """
    atks = []
    for family, op, vec in FAMILIES:
        for model in CHILD_MODELS:
            atks.append({
                "id": f"wa-{_ABBR[family]}-{short(model)}",
                "family": family,
                "vector": vec.format(c=short(model)),
                "persona": persona,
                "model": model,
                "op": op,
                "in_scope": True,
                "desc": f"{family} on {model} as {persona}",
            })
    return atks


WRITE_ATTACKS = generate("ttv")


def expected_verdict(atk, variant="v-vuln"):
    """Expected (undefended, pg_agent, outcome) for one attack.

    v-vuln: the child has no record rule -> every undefended write BREACHES; the PEP write-check
            DENIES -> outcome `held`.
    v-rule: the naive fix adds a record rule on `.line` only. It blocks the USING-based ops on the
            line (create / overwrite-foreign / unlink -> undefended does not fire -> `non-firing`),
            but NOT cross-team reassignment — Odoo record rules are USING-only, with no WITH-CHECK,
            so moving an owned line onto a foreign order still breaches — and NOT the forgotten
            payment/guarantee siblings. Those still breach and are held by the PEP's write-check.
    The PEP never permits a confused-deputy write, so `pg_agent` is always `denied`.
    """
    line = short(atk["model"]) == "line"
    if variant == "v-rule" and line and atk["family"] != "cross-team-reassignment":
        return ("denied", "denied", "non-firing")
    return ("breach", "denied", "held")
