# -*- coding: utf-8 -*-
"""Pure emit core for the policy-closure compiler (F10 Increment 2) — no Odoo.

Turns derived closures (policy_closure.derive_closures / derive_gaps records) into an
ENFORCEABLE artifact:
  * emit_policy        — a guard POLICY dict (the pco-shaped {team_path,company_path,owner_path}),
                         consumed by pg_agent_guard; verified at runtime by rebinding the guard's
                         POLICY to it and re-running ERP-AuthZBench.
  * emit_ir_rule_domain— a generic native ir.rule domain string for one closure, GATED on the
                         PARENT rule's pushdownability (we refuse to push a complex OR/parent_of/
                         multi-field parent domain into a single child leaf — not sound in general).
  * classify_emit      — per-gap emit rows (pushdownable vs manual-review) for a report.

No discovery here; this only materializes already-derived closures. Owner axis is out of scope
(a local opt-in field, not a parent pushdown) — emit_policy always sets owner_path=None.
"""

# Discriminator family -> (operator, RHS context token) for a native rule leaf.
_AXIS_TOKEN = {
    "company_id": ("in", "company_ids"),
    "company_ids": ("in", "company_ids"),
    "user_id": ("=", "user.id"),
    "invoice_user_id": ("=", "user.id"),
    "create_uid": ("=", "user.id"),
    "partner_id": ("=", "user.partner_id"),
    "commercial_partner_id": ("=", "user.commercial_partner_id"),
}
_DEFAULT_TOKEN = ("=", "user.id")


def emit_policy(records, slot_map=None):
    """Build a guard POLICY dict from reachable closure records.

    slot_map maps a derive_closures `axis` key to a POLICY slot (default team/company).
    Every reachable record contributes its relation_path as the enforcement path (GOVERNED
    or GAP alike — the guard enforces both). owner_path is always None (out of scope).
    """
    slot_map = slot_map or {"team": "team_path", "company": "company_path"}
    out = {}
    for r in records:
        if not r.get("reachable"):
            continue
        slot = slot_map.get(r.get("axis"))
        if slot is None:
            continue
        out.setdefault(r["model"], {"team_path": None, "company_path": None, "owner_path": None})
        out[r["model"]][slot] = r["relation_path"]
    return out


def _field_of(record):
    return record.get("field") or record.get("discriminator")


def emit_ir_rule_domain(record, parent_pushdownable, parent_reason=""):
    """(domain_str | None, status) for one closure, gated on the PARENT rule.

    parent_pushdownable -> a single-leaf native rule pushing the discriminator down the
    relation path; else None + 'manual-review:<reason>' (we do NOT emit unsound rules).
    """
    if not parent_pushdownable:
        return None, "manual-review:" + (parent_reason or "complex")
    op, rhs = _AXIS_TOKEN.get(_field_of(record), _DEFAULT_TOKEN)
    return "[('%s', '%s', %s)]" % (record["relation_path"], op, rhs), "pushdownable"


def classify_emit(gap_records, parent_rule_by_key):
    """Per-GAP emit rows + count of pushdownable ones.

    parent_rule_by_key: {(definer_model, field): (pushdownable: bool, reason: str)}.
    Returns (rows, n_pushdownable).
    """
    rows, n_push = [], 0
    for r in gap_records:
        key = (r.get("definer_model"), _field_of(r))
        push, reason = parent_rule_by_key.get(key, (False, "no-parent-rule"))
        domain, status = emit_ir_rule_domain(r, push, reason)
        if status == "pushdownable":
            n_push += 1
        rows.append({
            "model": r["model"],
            "discriminator": _field_of(r),
            "relation_path": r.get("relation_path") or "",
            "definer_model": r.get("definer_model") or "",
            "parent_pushdownable": push,
            "parent_reason": reason,
            "emit_status": status,
            "emitted_domain": domain or "",
        })
    return rows, n_push
