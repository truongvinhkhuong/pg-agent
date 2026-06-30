# -*- coding: utf-8 -*-
"""Real-Odoo-schema enforcement driver (§5.6 / read plane). Run inside `odoo shell`; see tools/real_schema.sh.

Demonstrates the SAME PG-Agent PEP guard closing the relational-traversal confused-deputy gap on the REAL,
unmodified upstream Odoo `sale.order` / `sale.order.line` (the bespoke `pco_core_mock` is a synthetic copy of
exactly this pair). The static scanner (§5.2) independently flagged `sale.order.line` as a GAP via the owner axis
`order_id.user_id`; here we reproduce the leak and the fix at runtime on the real schema.

Honest scope (read / owner axis / single company / draft orders):
  * The DATA (partner/product/orders) is synthetic seed; the SCHEMA, FK relation (`order_id`), record-rule
    engine, and ORM are 100% real Odoo. We add exactly ONE realistic parent record rule
    (`[('user_id','=',user.id)]` on `sale.order` — a standard per-salesperson-visibility deployment) and ZERO
    child rules: the govern-parent-forget-child misconfiguration. We did NOT manufacture the gap — the scanner
    flagged it before any rule.
  * The leak oracle is NON-CIRCULAR: cross-owner is measured via sudo on `order_id.user_id`, never the guard's
    verdict.
  * In-band POSITIVE CONTROL: the restricted user must see only its own 3 of 6 orders on the GOVERNED parent
    (CONTROL-OK iff 3); if 6, the rule is not binding (a privileged/bypassing run) -> CONTROL-FAIL, run invalid.
  * Byte-stable: only COUNTS/verdicts are written — never ids/names/dates/amounts.

The guard is NOT modified for this model. We pass a per-call LOCAL policy via the additive `policy=` kwarg
(`guarded_search_read(..., policy=...)`), so the global `POLICY` (consumed by exact-equality/count asserts
elsewhere) is untouched. The probe user is put in `pco_core_mock.group_team_view_all` so `_user_teams()` returns
None (team axis OFF) and the guard applies the OWNER leaf only — the native parent rule still scopes it by owner.
"""
import csv
import os

# Per-call LOCAL policy for the real models — team/company OFF, owner axis ON (the scanner-flagged gap).
# NOT added to the global pep_guard.POLICY (that would break exact-equality/count asserts in the offline suite).
LOCAL_POLICY = {
    "sale.order":      {"team_path": None, "company_path": None, "owner_path": "user_id"},
    "sale.order.line": {"team_path": None, "company_path": None, "owner_path": "order_id.user_id"},
}

_GROUP_FIELD = None        # resolved at runtime (Odoo 19 renamed res.users.groups_id -> group_ids)


def _grpfield(env):
    global _GROUP_FIELD
    if _GROUP_FIELD is None:
        _GROUP_FIELD = "group_ids" if "group_ids" in env["res.users"]._fields else "groups_id"
    return _GROUP_FIELD


def _user(env, login, name, company, group_xmlids):
    """search-or-create a plain INTERNAL user (never admin) in the given groups."""
    u = env["res.users"].sudo().search([("login", "=", login)], limit=1)
    if not u:
        gids = [env.ref(g).id for g in group_xmlids]
        u = env["res.users"].sudo().create({
            "name": name, "login": login, "company_id": company.id,
            "company_ids": [(6, 0, [company.id])], _grpfield(env): [(6, 0, gids)],
        })
    return u


def _cross_owner(env, ids, owner_id):
    """Non-circular oracle: of line `ids`, how many belong to a DIFFERENT salesperson (sudo on order_id.user_id)."""
    lines = env["sale.order.line"].sudo().browse(list(ids))
    return sum(1 for ln in lines if ln.order_id.user_id.id != owner_id)


def real_schema_run(env, outdir="results/repro"):
    Comp = env["res.company"].sudo()
    company = env.company or Comp.search([], limit=1)

    # ── master data (none exists under --without-demo=all) ───────────────────────
    partner = env["res.partner"].sudo().search([("name", "=", "RS-Partner")], limit=1) \
        or env["res.partner"].sudo().create({"name": "RS-Partner", "company_id": company.id})
    product = env["product.product"].sudo().search([("name", "=", "RS-Product")], limit=1) \
        or env["product.product"].sudo().create({"name": "RS-Product", "type": "consu", "list_price": 100.0})

    # Custom restricted role = the confused-deputy misconfiguration. Odoo 19's `sale` ships PAIRED rules
    # ("Own Documents Only" governs BOTH sale.order and sale.order.line; "All Documents" opens both), so the
    # shipped sale groups have NO gap. The realistic gap is a BESPOKE role that grants READ on orders+lines and
    # scopes the parent by salesperson, but FORGETS the line-level rule. We model that exactly: a custom group
    # with read-ACL on both models + a parent own-rule + NO child rule. The probe user is in this group ONLY
    # (NOT in any `sales_team.*` group), so the shipped child rules do not apply to it.
    grp = env["res.groups"].sudo().search([("name", "=", "RS Restricted Salesperson")], limit=1)
    if not grp:
        grp = env["res.groups"].sudo().create({"name": "RS Restricted Salesperson"})
    Access = env["ir.model.access"].sudo()
    for m in ("sale.order", "sale.order.line"):           # READ-only ACL for the bespoke role
        if not Access.search_count([("name", "=", "rs_read_" + m), ("group_id", "=", grp.id)]):
            Access.create({"name": "rs_read_" + m, "model_id": env["ir.model"]._get(m).id,
                           "group_id": grp.id, "perm_read": True,
                           "perm_write": False, "perm_create": False, "perm_unlink": False})

    # Probe user A: ONLY base internal + the bespoke role + see-all-by-TEAM (so the guard uses the OWNER axis,
    # not team) + own-only at the OWNER axis. NOT in any sales_team group; NOT admin.
    a = _user(env, "rs_sales_a", "RS Salesperson A", company,
              ["base.group_user", "pco_core_mock.group_team_view_all", "pg_agent_guard.group_pep_own_only"])
    a.sudo().write({_grpfield(env): [(4, grp.id)]})
    # User B: just another order owner (never reads); plain internal user.
    b = _user(env, "rs_sales_b", "RS Salesperson B", company, ["base.group_user"])

    # ── seed DRAFT orders: 3 per salesperson × 2 lines = 12 lines (6 per owner) ──
    SO = env["sale.order"].sudo()
    if SO.search_count([("partner_id", "=", partner.id)]) < 6:
        for owner in (a, b):
            for _ in range(3):
                SO.create({
                    "partner_id": partner.id, "user_id": owner.id, "company_id": company.id,
                    "order_line": [(0, 0, {"product_id": product.id, "product_uom_qty": 1}) for _ in range(2)],
                })

    # parent OWN rule on sale.order for the restricted group; NO rule on sale.order.line (the deliberate gap).
    if not env["ir.rule"].sudo().search_count([("name", "=", "RS own sale orders")]):
        env["ir.rule"].sudo().create({
            "name": "RS own sale orders",
            "model_id": env["ir.model"]._get("sale.order").id,
            "groups": [(6, 0, [grp.id])],
            "domain_force": "[('user_id', '=', user.id)]",
            "perm_read": True, "perm_write": False, "perm_create": False, "perm_unlink": False,
        })

    # ── probes as the restricted user A (the PEP runs in A's env) ─────────────────
    assert not (a.has_group("base.group_system") or a.has_group("base.group_erp_manager")), \
        "probe user must NOT be admin (would bypass record rules -> vacuous run)"
    penv = env(user=a.id)
    guard = penv["pg.agent.guard"]

    total_orders = SO.search_count([("partner_id", "=", partner.id)])
    total_lines = env["sale.order.line"].sudo().search_count([("order_id.partner_id", "=", partner.id)])
    assert total_orders == 6 and total_lines == 12, f"seed drift: {total_orders} orders / {total_lines} lines"

    # (1) parent positive control: governed sale.order -> A sees only its own 3 of 6.
    parent_n = penv["sale.order"].search_count([])
    parent_cross = sum(1 for o in penv["sale.order"].sudo().browse(penv["sale.order"].search([]).ids)
                       if o.user_id.id != a.id)
    ctl_ok = (parent_n == 3 and parent_cross == 0)

    # (2) child UNGUARDED (the gap): A reads sale.order.line directly -> all 12 lines, 6 cross-owner.
    ug_ids = penv["sale.order.line"].search([]).ids
    ug_cross = _cross_owner(env, ug_ids, a.id)
    ug_leak = ug_cross > 0

    # (3) child GUARDED (the PEP, via the per-call LOCAL policy): owner predicate pushed down -> 6 lines, 0 cross.
    authz = guard._authz_domain("sale.order.line", LOCAL_POLICY)       # for the one-leaf assertion
    assert authz == [("order_id.user_id", "=", a.id)], f"guarded domain must be the single owner leaf, got {authz}"
    g_rows = guard.guarded_search_read("sale.order.line", [], ["id"], policy=LOCAL_POLICY)
    g_ids = [r["id"] for r in g_rows]
    g_cross = _cross_owner(env, g_ids, a.id)

    rows = [
        ["v-native", "parent-control", "salesperson", "yes", parent_n, parent_cross,
         "CONTROL-OK" if ctl_ok else "CONTROL-FAIL"],
        ["v-native", "child-direct", "salesperson", "yes", len(ug_ids), ug_cross,
         "LEAK" if ug_leak else "SAFE"],
        ["v-pep", "child-direct", "salesperson", "yes", len(g_ids), g_cross,
         "SAFE" if g_cross == 0 and len(g_ids) > 0 else "LEAK"],
    ]
    out = os.path.join(outdir, "real_sale.csv")
    os.makedirs(outdir, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["variant", "probe", "role", "own_only", "row_count", "cross_owner_rows", "verdict"])
        w.writerows(rows)

    print("\n=== Real-Odoo-schema enforcement (sale.order / sale.order.line) ===")
    print(f"  parent-control : A sees {parent_n}/6 orders ({parent_cross} cross-owner) -> "
          f"{'CONTROL-OK' if ctl_ok else 'CONTROL-FAIL'}")
    print(f"  child UNGUARDED: {len(ug_ids)} lines, {ug_cross} cross-owner -> {'LEAK' if ug_leak else 'SAFE'}")
    print(f"  child GUARDED  : {len(g_ids)} lines, {g_cross} cross-owner -> "
          f"{'SAFE' if g_cross == 0 else 'LEAK'}  (PEP forced {authz})")
    assert ctl_ok, "CONTROL-FAIL: parent rule not binding (probe user too privileged) — run invalid"
    assert ug_leak and ug_cross == 6, f"gap not reproduced on real schema (cross-owner={ug_cross})"
    assert g_cross == 0 and len(g_ids) == 6, f"PEP did not close the gap (guarded cross={g_cross}, n={len(g_ids)})"
    print(f"Wrote {out} (counts/verdicts only; byte-stable)\n")
    return rows
