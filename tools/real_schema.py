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


# ── savepoint isolation (replicated from evaluation_script.py — driver is standalone, must NOT import it) ──
def _reset_orm(env):
    """Drop the ORM cache AND the pending-write/recompute queues after a raw savepoint rollback. `env.clear()`
    is load-bearing: a bare `invalidate_all()` leaves the rolled-back mutation in `env.all.towrite`, which Odoo
    re-flushes on the next query (here with REAL stored computes, e.g. sale.order.amount_total) — silently
    re-applying a change we undid. `clear()` drops towrite + tocompute + cache."""
    for name in ("clear", "invalidate_all"):
        fn = getattr(env, name, None)
        if callable(fn):
            fn()
            return


def _isolated(env, fn):
    """Run `fn` inside a per-attack savepoint, then roll it back + reset the ORM so the mutation leaves NO residue."""
    env.cr.execute("SAVEPOINT rs")
    try:
        return fn()
    finally:
        env.cr.execute("ROLLBACK TO SAVEPOINT rs")
        env.cr.execute("RELEASE SAVEPOINT rs")
        _reset_orm(env)


def _safe_mutate(env, fn):
    """Attempt one mutation under a defensive savepoint: a raised denial (AccessError) is rolled back so it
    cannot poison the outer transaction; a success is kept so the sudo breach oracle can read its DB effect.
    The guarded deny path returns a value (no raise) and simply does not mutate."""
    env.cr.execute("SAVEPOINT rs_op")
    try:
        fn()
    except Exception:
        env.cr.execute("ROLLBACK TO SAVEPOINT rs_op")
        return
    env.cr.execute("RELEASE SAVEPOINT rs_op")


def _seed(env):
    """Shared fixtures for the read (§5.6) and write planes. Idempotent. Returns (company, partner, product, a, b,
    grp). The bespoke role models the confused-deputy misconfiguration: Odoo 19's `sale` ships PAIRED rules ("Own
    Documents Only" governs BOTH sale.order and sale.order.line), so the shipped roles have NO gap; the realistic
    gap is a BESPOKE role that can READ+manage lines and scopes the parent by salesperson but FORGETS the
    line-level rule. We grant the role read-ACL on the header and FULL CRUD on the LINE (manage lines) + a parent
    own-rule + NO child rule; the probe user is in this group ONLY (not in any sales_team.* group), so the shipped
    child rules never apply to it."""
    company = env.company or env["res.company"].sudo().search([], limit=1)
    partner = env["res.partner"].sudo().search([("name", "=", "RS-Partner")], limit=1) \
        or env["res.partner"].sudo().create({"name": "RS-Partner", "company_id": company.id})
    product = env["product.product"].sudo().search([("name", "=", "RS-Product")], limit=1) \
        or env["product.product"].sudo().create({"name": "RS-Product", "type": "consu", "list_price": 100.0})

    grp = env["res.groups"].sudo().search([("name", "=", "RS Restricted Salesperson")], limit=1)
    if not grp:
        grp = env["res.groups"].sudo().create({"name": "RS Restricted Salesperson"})
    access = env["ir.model.access"].sudo()
    # header read-only; LINE full CRUD (read+write+create+unlink) — the "manage lines" grant that makes the
    # confused-deputy WRITE fire undefended (the line record-rule is the forgotten piece, not the ACL).
    grants = {"sale.order": (True, False, False, False),
              "sale.order.line": (True, True, True, True)}
    for m, (r, w, c, u) in grants.items():
        name = "rs_acl_" + m
        if not access.search_count([("name", "=", name), ("group_id", "=", grp.id)]):
            access.create({"name": name, "model_id": env["ir.model"]._get(m).id, "group_id": grp.id,
                           "perm_read": r, "perm_write": w, "perm_create": c, "perm_unlink": u})

    a = _user(env, "rs_sales_a", "RS Salesperson A", company,
              ["base.group_user", "pco_core_mock.group_team_view_all", "pg_agent_guard.group_pep_own_only"])
    a.sudo().write({_grpfield(env): [(4, grp.id)]})
    b = _user(env, "rs_sales_b", "RS Salesperson B", company, ["base.group_user"])

    SO = env["sale.order"].sudo()
    if SO.search_count([("partner_id", "=", partner.id)]) < 6:    # 3 DRAFT orders/owner × 2 lines = 12 (6/owner)
        for owner in (a, b):
            for _ in range(3):
                SO.create({
                    "partner_id": partner.id, "user_id": owner.id, "company_id": company.id,
                    "order_line": [(0, 0, {"product_id": product.id, "product_uom_qty": 1}) for _ in range(2)],
                })

    # parent OWN rule on sale.order for the bespoke group; NO rule on sale.order.line (the deliberate gap).
    if not env["ir.rule"].sudo().search_count([("name", "=", "RS own sale orders")]):
        env["ir.rule"].sudo().create({
            "name": "RS own sale orders", "model_id": env["ir.model"]._get("sale.order").id,
            "groups": [(6, 0, [grp.id])], "domain_force": "[('user_id', '=', user.id)]",
            "perm_read": True, "perm_write": False, "perm_create": False, "perm_unlink": False,
        })
    assert not (a.has_group("base.group_system") or a.has_group("base.group_erp_manager")), \
        "probe user must NOT be admin (would bypass record rules -> vacuous run)"
    return company, partner, product, a, b, grp


def real_schema_run(env, outdir="results/repro"):
    _company, partner, _product, a, _b, _grp = _seed(env)
    SO = env["sale.order"].sudo()
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


# Sentinels for the write-foreign-child oracle. `name` (Description) is store=True/readonly=False and NO
# sale.order compute depends on order_line.name (so a direct write sticks + dirties no parent → cleanest,
# recompute-free oracle). Never written to the CSV (byte-stability).
_FOREIGN_SENTINEL = "WA-FOREIGN-SENTINEL"
_OWN_SENTINEL = "WA-OWN-SENTINEL"


_SOL = "sale.order.line"


def _attempt(env, mutate, breach_check):
    """One isolated attempt: SAVEPOINT → mutate (defensively) → evaluate the breach oracle BEFORE rollback.
    `breach_check` is a 0-arg callable returning bool (pure-SQL sudo count, cache-independent, never the guard's
    verdict). The savepoint is always rolled back → no residue."""
    return _isolated(env, lambda: (_safe_mutate(env, mutate), breach_check())[1])


def real_schema_write_run(env, outdir="results/repro"):
    """Write plane (§5.6 extension / RQ10 on the real schema): a bespoke role that can MANAGE lines (CRUD ACL)
    but whose line-level rule was forgotten can create/write/unlink/reassign ANOTHER salesperson's order lines
    (confused-deputy WRITE). The same PEP write-check (USING + WITH-CHECK) holds all of them, while the in-scope
    OWN write still succeeds (positive control). Every attempt is savepoint-isolated; the DB is left untouched."""
    _company, partner, product, a, b, _grp = _seed(env)
    SOL = env[_SOL].sudo()
    SO = env["sale.order"].sudo()
    penv = env(user=a.id)
    guard = penv["pg.agent.guard"]

    # right-reason guard: the guarded owner leaf must be exactly one owner predicate. A missed policy-thread would
    # make _vals_in_authz fall back to the global POLICY (which lacks sale.order.line) and deny for the WRONG
    # reason = vacuous "held"; the positive control below also catches that (an own write would vacuously deny).
    authz = guard._authz_domain(_SOL, LOCAL_POLICY)
    assert authz == [("order_id.user_id", "=", a.id)], f"guarded owner leaf wrong: {authz}"

    b_order = SO.search([("user_id", "=", b.id)], order="id", limit=1)
    b_line = SOL.search([("order_id.user_id", "=", b.id)], order="id", limit=1)
    a_line = SOL.search([("order_id.user_id", "=", a.id)], order="id", limit=1)
    n_before = SOL.search_count([("order_id.partner_id", "=", partner.id)])

    gone = lambda lid: SOL.search_count([("id", "=", lid)]) == 0
    has_name = lambda lid, s: SOL.search_count([("id", "=", lid), ("name", "=", s)]) > 0
    added = lambda oid: SOL.search_count([("order_id", "=", oid)]) > 2     # B's order seeds 2 lines
    moved = lambda lid: SOL.search_count([("id", "=", lid), ("order_id.user_id", "!=", a.id)]) > 0
    cvals = {"order_id": b_order.id, "product_id": product.id, "product_uom_qty": 1}

    # each row: (attack_id, op, undefended_mutate, guarded_mutate, breach_check)
    attacks = [
        ("write-foreign-child", "write",
         lambda: penv[_SOL].browse(b_line.id).write({"name": _FOREIGN_SENTINEL}),
         lambda: guard.guarded_write(_SOL, [b_line.id], {"name": _FOREIGN_SENTINEL}, policy=LOCAL_POLICY),
         lambda: has_name(b_line.id, _FOREIGN_SENTINEL)),
        ("unlink-foreign-child", "unlink",
         lambda: penv[_SOL].browse(b_line.id).unlink(),
         lambda: guard.guarded_unlink(_SOL, [b_line.id], policy=LOCAL_POLICY),
         lambda: gone(b_line.id)),
        ("create-foreign-parent", "create",
         lambda: penv[_SOL].create(dict(cvals)),
         lambda: guard.guarded_create(_SOL, dict(cvals), policy=LOCAL_POLICY),
         lambda: added(b_order.id)),
        ("cross-owner-reassignment", "write",
         lambda: penv[_SOL].browse(a_line.id).write({"order_id": b_order.id}),
         lambda: guard.guarded_write(_SOL, [a_line.id], {"order_id": b_order.id}, policy=LOCAL_POLICY),
         lambda: moved(a_line.id)),
    ]

    results = []   # (attack_id, op, undef_breach, guard_breach)
    for aid, op, undef_fn, guard_fn, check in attacks:
        ub = _attempt(env, undef_fn, check)
        gb = _attempt(env, guard_fn, check)
        results.append((aid, op, ub, gb))

    # positive control: A's OWN line, guarded write MUST SUCCEED (guard is permissive in-scope, not blanket-deny).
    pc_ok = _attempt(env, lambda: guard.guarded_write(_SOL, [a_line.id], {"name": _OWN_SENTINEL}, policy=LOCAL_POLICY),
                     lambda: has_name(a_line.id, _OWN_SENTINEL))

    # residue snapshot: every savepoint rolled back -> DB bit-for-bit back to seed.
    after_lines = SOL.search_count([("order_id.partner_id", "=", partner.id)])
    after_orders = SO.search_count([("partner_id", "=", partner.id)])
    sentinel_rows = SOL.search_count(["|", ("name", "=", _FOREIGN_SENTINEL), ("name", "=", _OWN_SENTINEL)])
    assert after_lines == n_before == 12 and after_orders == 6 and sentinel_rows == 0, \
        f"write residue (savepoint isolation broke): lines {after_lines} orders {after_orders} sentinel {sentinel_rows}"

    rows = []
    print("\n=== Real-Odoo-schema WRITE plane (sale.order.line; owner axis) ===")
    for aid, op, ub, gb in results:
        outcome = "held" if (ub and not gb) else ("RESIDUAL-LEAK" if gb else "n/a-native-block")
        rows.append([aid, op, "breach" if ub else "denied", "breach" if gb else "denied", outcome])
        print(f"  {aid:<26} {op:<7} undefended={'breach' if ub else 'denied'} "
              f"pg_agent={'breach' if gb else 'denied'} -> {outcome}")
    rows.append(["positive-control", "write", "na", "na", "SUCCESS" if pc_ok else "CONTROL-FAIL"])
    print(f"  {'positive-control':<26} {'write':<7} OWN guarded write -> {'SUCCESS' if pc_ok else 'CONTROL-FAIL'}")

    out = os.path.join(outdir, "real_sale_write.csv")
    os.makedirs(outdir, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["attack", "op", "undefended", "pg_agent", "outcome"])
        w.writerows(rows)

    # Honest invariants. On real Odoo, a foreign FIELD-overwrite (write-foreign-child) is incidentally blocked by
    # Odoo's parent-read coupling (writing a line whose parent order A cannot read raises AccessError) — so it does
    # NOT breach; the structural writes (unlink/create/reassign) DO breach and the PEP holds them. Require >=3
    # undefended breaches (non-vacuity) + every breaching attack held + the positive control.
    breached = [r for r in results if r[2]]
    assert len(breached) >= 3, f"write plane vacuous: only {len(breached)} undefended breach(es)"
    for aid, op, ub, gb in results:
        assert not gb, f"{aid}: PEP write-check FAILED to hold (guarded breach)"
    assert pc_ok, "positive control FAILED: in-scope OWN guarded write did not succeed (guard blanket-denying?)"
    print(f"Wrote {out} (counts/verdicts only; byte-stable)\n")
    return rows
