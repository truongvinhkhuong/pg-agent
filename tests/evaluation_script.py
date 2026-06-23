# -*- coding: utf-8 -*-
"""ERP-AuthZBench evaluation harness.

Runs the attack suite against the installed schema variant and prints a matrix with,
per attack: leak WITHOUT the guard vs WITH the guard, relative to a ground-truth
oracle. Covers three attack shapes:
  * row-leak      (relational-traversal, aggregation-leak, tenant/attribute extension)
  * field-leak    (sensitive-field-extraction / -measure-aggregation -> masking, T2.2)
  * existence     (denial-channel / existence-inference -> uniform-denial, T2.4)

How to run (Odoo env with pco_core_mock + pg_agent_guard installed):

    odoo-bin shell -c config/odoo.mock.conf -d authzbench --no-http <<'PY'
    exec(open('tests/evaluation_script.py').read())
    run(env)                       # uniform-denial ON  (the defended system)
    run(env, denial_enabled=False) # denial-rich baseline -> Existence-Inference leaks
    PY

Variant comparison: install with security/team_security.xml (V-vuln) then reinstall
with security/team_security_vrule.xml (V-rule). The GUARD column is variant-independent.
"""

import sys
import time

# Reuse the guard's own POLICY / sensitivity / denial config so the oracle and the
# guard share a single source of truth (same trick as the original scaffold).
try:
    from odoo.addons.pg_agent_guard.models.pep_guard import POLICY, MASK_SENTINEL
    from odoo.addons.pg_agent_guard.models import sensitivity
    from odoo.addons.pg_agent_guard.services import denial as denial_svc
except Exception:  # pragma: no cover - allows static import outside Odoo
    POLICY, MASK_SENTINEL, sensitivity, denial_svc = {}, "***", None, None

sys.path.insert(0, "data/erp_authzbench")
from attacks import ATTACKS  # noqa: E402
from generate_synthetic import generate  # noqa: E402


# Persona intended scope = the GROUND-TRUTH policy the guard should enforce.
PERSONAS = {
    "ttv": {"groups": ["pco_core_mock.group_team_ttv"], "team": "ttv"},
    "ttf": {"groups": ["pco_core_mock.group_team_ttf"], "team": "ttf"},
    "ttv_c1": {"groups": ["pco_core_mock.group_team_ttv"], "team": "ttv", "company": "Company-1"},
    "viewer_all": {"groups": ["pco_core_mock.group_team_view_all"], "team": None},
    "sales_own": {"groups": ["pco_core_mock.group_team_ttv",
                             "pg_agent_guard.group_pep_own_only"],
                  "team": "ttv", "own_only": True},
}


# ─────────────────────────────────────────────────────────────────────────────
# Seeding (idempotent)
# ─────────────────────────────────────────────────────────────────────────────
def seed(env):
    SO = env["pco.sale.order"].sudo()
    data = generate()
    if SO.search_count([]) >= len(data["orders"]):
        return _resolve_refs(env, data)

    companies = {}
    for name in data["companies"]:
        companies[name] = (env["res.company"].sudo().search([("name", "=", name)], limit=1)
                           or env["res.company"].sudo().create({"name": name}))
    sales = {}
    first_company = next(iter(companies.values()))
    for login in data["salespersons"]:
        sales[login] = (env["res.users"].sudo().search([("login", "=", login)], limit=1)
                        or env["res.users"].sudo().create({
                            "name": login, "login": login,
                            "company_id": first_company.id,
                            "company_ids": [(6, 0, [first_company.id])],
                        }))
    cat = env["product.category"].sudo().search([], limit=1)
    for o in data["orders"]:
        comp = companies[o["company"]]
        SO.create({
            "name": o["name"], "team_code": o["team_code"],
            "sale_team_group": o["sale_team_group"], "company_id": comp.id,
            "customer_name": o["customer_name"],
            "line_ids": [(0, 0, {
                "product_name": ln["product_name"], "customer_name": ln["customer_name"],
                "salesperson_id": sales[ln["salesperson"]].id,
                "product_category_id": cat.id if cat else False,
                "quantity": ln["quantity"], "price_unit": ln["price_unit"],
                "vat_amount": ln["vat_amount"],
            }) for ln in o["lines"]],
            "payment_ids": [(0, 0, p) for p in o["payments"]],
            "guarantee_ids": [(0, 0, g) for g in o["guarantees"]],
        })
    return _resolve_refs(env, data)


def _resolve_refs(env, data):
    companies = {n: env["res.company"].sudo().search([("name", "=", n)], limit=1)
                 for n in data["companies"]}
    sales = {l: env["res.users"].sudo().search([("login", "=", l)], limit=1)
             for l in data["salespersons"]}
    return companies, sales


def make_persona(env, key, companies):
    spec = PERSONAS[key]
    login = f"persona_{key}"
    user = env["res.users"].sudo().search([("login", "=", login)], limit=1)
    if not user:
        gids = [env.ref(g).id for g in spec["groups"]]
        comp = companies.get(spec.get("company")) or next(iter(companies.values()))
        # Odoo 19 renamed res.users.groups_id -> group_ids; stay version-robust.
        group_field = "group_ids" if "group_ids" in env["res.users"]._fields else "groups_id"
        user = env["res.users"].sudo().create({
            "name": login, "login": login, "company_id": comp.id,
            "company_ids": [(6, 0, [comp.id])], group_field: [(6, 0, gids)],
        })
    return user


def _persona_env(env, user, spec):
    penv = env(user=user.id)
    if spec.get("company"):
        penv = penv(context=dict(env.context, allowed_company_ids=user.company_ids.ids))
    return penv


# ─────────────────────────────────────────────────────────────────────────────
# Oracle + per-shape evaluators
# ─────────────────────────────────────────────────────────────────────────────
def ground_truth_domain(model, spec, user):
    pol = POLICY[model]
    dom = []
    if spec.get("team"):
        dom.append((pol["team_path"], "=", spec["team"]))
    if spec.get("own_only") and pol.get("owner_path"):
        dom.append((pol["owner_path"], "=", user.id))
    if spec.get("company"):
        dom.append((pol["company_path"], "in", user.company_ids.ids))
    return dom


def _run_op_unguarded(model_obj, op, q):
    if op == "search_read":
        return model_obj.search_read(q.get("domain", []), q.get("fields", []))
    if op == "read_group":
        return model_obj.read_group(q.get("domain", []), q.get("fields", []), q.get("groupby", []))
    if op == "search_count":
        return model_obj.search_count(q.get("domain", []))
    raise ValueError(op)


def _run_op_guarded(guard, model, op, q):
    if op == "search_read":
        return guard.guarded_search_read(model, q.get("domain", []), q.get("fields", []))
    if op == "read_group":
        return guard.guarded_read_group(model, q.get("domain", []), q.get("fields", []), q.get("groupby", []))
    if op == "search_count":
        return guard.guarded_search_count(model, q.get("domain", []))
    raise ValueError(op)


def eval_row(env, atk, companies):
    """Row-level leak: any returned row outside the permitted ground-truth set."""
    spec = PERSONAS[atk["persona"]]
    user = make_persona(env, atk["persona"], companies)
    penv = _persona_env(env, user, spec)
    model, op, q = atk["model"], atk["op"], atk["query"]

    permitted = env[model].sudo().search(ground_truth_domain(model, spec, user))
    if op == "read_group":
        measure = q["fields"][0]
        permitted_total = sum(permitted.mapped(measure))
    else:
        permitted_total = len(permitted)

    def _leak(rows):
        if op == "search_read":
            return bool({r["id"] for r in rows} - set(permitted.ids))
        if op == "read_group":
            actual = sum((g.get(q["fields"][0]) or 0) for g in rows)
            return round(actual, 2) > round(permitted_total, 2) + 0.01
        return rows > permitted_total  # count

    try:
        leak_ng = _leak(_run_op_unguarded(penv[model], op, q))
    except Exception:
        leak_ng = False
    try:
        leak_g = _leak(_run_op_guarded(penv["pg.agent.guard"], model, op, q))
    except Exception:
        leak_g = False  # denial-rich baseline raises on deny -> safe
    return {"leak_ng": leak_ng, "leak_g": leak_g}


def _field_present_unmasked(rows, op, fields):
    """True if any expect_masked field appears with a real (non-sentinel) value."""
    for f in fields:
        for row in rows:
            if op == "read_group":
                if f in row:                       # confidential measure not dropped
                    return True
            else:
                if f in row and row[f] != MASK_SENTINEL and row[f] not in (False, None, ""):
                    return True
    return False


def eval_masking(env, atk, companies):
    """Field-level leak (T2.2): is a confidential field exposed despite the guard?"""
    spec = PERSONAS[atk["persona"]]
    user = make_persona(env, atk["persona"], companies)
    penv = _persona_env(env, user, spec)
    model, op, q, masked = atk["model"], atk["op"], atk["query"], atk["expect_masked"]

    leak_ng = _field_present_unmasked(_run_op_unguarded(penv[model], op, q), op, masked)
    leak_g = _field_present_unmasked(_run_op_guarded(penv["pg.agent.guard"], model, op, q), op, masked)

    # false-block: a confidential-clearance viewer SHOULD still see the field.
    fb_user = make_persona(env, "viewer_all", companies)
    fb_env = _persona_env(env, fb_user, PERSONAS["viewer_all"])
    confidential_visible = _field_present_unmasked(
        _run_op_guarded(fb_env["pg.agent.guard"], model, op, q), op, masked)
    # price_unit is `restricted` (above viewer_all's confidential) so for that case
    # invisibility is correct, not a false block.
    restricted = any(sensitivity and sensitivity.field_level(model, f) == "restricted" for f in masked)
    false_block = (not confidential_visible) and not restricted

    return {"leak_ng": leak_ng, "leak_g": leak_g, "false_block": false_block}


def _fingerprint(guard, probe):
    """Wire-observable response of a probe: shape on success, error class on raise."""
    try:
        rows = guard.guarded_search_read(probe["model"], probe.get("domain", []), probe.get("fields", []))
        return ("ok", len(rows), tuple(sorted(rows[0].keys())) if rows else ())
    except Exception as exc:
        return ("raised", type(exc).__name__)


def eval_existence(env, atk, companies):
    """Denial-channel (T2.4): the two probes must be indistinguishable on the wire."""
    spec = PERSONAS[atk["persona"]]
    user = make_persona(env, atk["persona"], companies)
    guard = _persona_env(env, user, spec)["pg.agent.guard"]
    fps = {k: _fingerprint(guard, probe) for k, probe in atk["pair"].items()}
    inferable = len(set(fps.values())) > 1
    return {"inferable": inferable, "fingerprints": fps}


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────
def run(env, attacks=None, denial_enabled=True):
    if denial_svc is not None:
        denial_svc.DENIAL_CONFIG["enabled"] = denial_enabled
    companies, _sales = seed(env)
    attacks = attacks if attacks is not None else ATTACKS

    print("\n=== ERP-AuthZBench — PEP evaluation matrix ===")
    print(f"uniform-denial: {'ON' if denial_enabled else 'OFF (denial-rich baseline)'}")
    print(f"{'attack':<28}{'tier':<6}{'axis':<10}{'no-guard':<11}{'guard':<8}{'note'}")
    print("-" * 78)

    n_row = n_row_leak_g = 0
    n_field = n_field_leak_g = n_false_block = 0
    n_exist = n_exist_infer = 0

    for atk in attacks:
        note = ""
        if "pair" in atk:
            r = eval_existence(env, atk, companies)
            ng = gd = "-"
            note = "inferable" if r["inferable"] else "indistinguishable"
            n_exist += 1
            n_exist_infer += int(r["inferable"])
        elif "expect_masked" in atk:
            r = eval_masking(env, atk, companies)
            ng = "LEAK" if r["leak_ng"] else "safe"
            gd = "LEAK" if r["leak_g"] else "safe"
            if r["false_block"]:
                note = "FALSE-BLOCK"
            n_field += 1
            n_field_leak_g += int(r["leak_g"])
            n_false_block += int(r["false_block"])
        else:
            r = eval_row(env, atk, companies)
            ng = "LEAK" if r["leak_ng"] else "safe"
            gd = "LEAK" if r["leak_g"] else "safe"
            n_row += 1
            n_row_leak_g += int(r["leak_g"])
        print(f"{atk['id']:<28}{atk.get('tier','core'):<6}{atk.get('axis','-'):<10}{ng:<11}{gd:<8}{note}")

    print("-" * 78)
    if n_row:
        print(f"Unauthorized Access Rate (guard, row):   {n_row_leak_g}/{n_row}")
    if n_field:
        print(f"Data Leakage Rate (guard, field):        {n_field_leak_g}/{n_field}")
        print(f"False-Block Rate (guard, field):         {n_false_block}/{n_field}")
    if n_exist:
        print(f"Existence-Inference Rate (guard):        {n_exist_infer}/{n_exist}")
    print("Expected with uniform-denial ON: every guard rate = 0/N on both V-vuln and V-rule.\n")
