# -*- coding: utf-8 -*-
"""Comparison baselines for ERP-AuthZBench (the paper's plane-comparison, N4a/N5).

Two reference points the PG-Agent PEP is measured against:

  * inherited-RBAC (Cortex-Analyst-style) — rely ONLY on native Odoo record rules
    "as inherited"; no extra enforcement. In the harness this is exactly the
    "run the op as the user" path (`_run_op_unguarded`), so it needs no code here.

  * action-authorization (OAP-style) — authorize the *call* (model ∈ agent
    allow-list + params/fields valid), then run the op with **no result-plane
    filtering**. It evaluates *actions, not results*: it blocks calling a tool on a
    forbidden model, but a permitted tool still returns forbidden rows. That gap is
    the confused-deputy / BOLA failure the paper highlights.

`authorized()` mirrors the real `pco_ai_chat` control-plane check
(`_validate_tool_params`: model whitelist + field existence) so the baseline is a
faithful stand-in for a deployed action-authorization layer.
"""

# The agent's tool allow-list (benchmark scope: the 4-model sale cluster).
AGENT_ALLOWLIST = (
    "pco.sale.order",
    "pco.sale.order.line",
    "pco.sale.order.payment",
    "pco.sale.order.guarantee",
)


def authorized(env, model, q):
    """OAP-style action+param authorization. Returns (allowed: bool, reason: str).

    Authorizes the CALL only — it never inspects or filters result rows.
    """
    if model not in AGENT_ALLOWLIST:
        return False, "model not in agent allow-list"
    valid = set(env[model]._fields)
    for key in ("domain", "fields", "groupby"):
        for item in (q.get(key) or []):
            base = item[0] if (key == "domain" and isinstance(item, (list, tuple))) else item
            if str(base).split(":")[0] not in valid:
                return False, f"unknown field: {base}"
    return True, "action authorized"
