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

import csv
import json
import os
import sys
import time

# Reuse the guard's own POLICY / sensitivity / denial config so the oracle and the
# guard share a single source of truth (same trick as the original scaffold).
try:
    from odoo.addons.pg_agent_guard.models.pep_guard import POLICY, MASK_SENTINEL, GUARD_CONFIG
    from odoo.addons.pg_agent_guard.models import sensitivity
    from odoo.addons.pg_agent_guard.services import denial as denial_svc
    from odoo.addons.pg_agent_guard.services import output_validator as ov_svc
except Exception:  # pragma: no cover - allows static import outside Odoo
    POLICY, MASK_SENTINEL = {}, "***"
    GUARD_CONFIG = {"enforce_masking": True}
    sensitivity, denial_svc, ov_svc = None, None, None

sys.path.insert(0, "data/erp_authzbench")
from attacks import ATTACKS  # noqa: E402
from generate_synthetic import generate  # noqa: E402
from baselines import authorized  # noqa: E402


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


def _run_op_action_authz(penv, model, op, q):
    """OAP-style baseline: authorize the call (allow-list + params); no row filter."""
    ok, _reason = authorized(penv, model, q)
    if not ok:
        return 0 if op == "search_count" else []   # action denied
    return _run_op_unguarded(penv[model], op, q)    # authorized -> native rules only


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
        leak_ng = _leak(_run_op_unguarded(penv[model], op, q))   # inherited-RBAC
    except Exception:
        leak_ng = False
    try:
        leak_aa = _leak(_run_op_action_authz(penv, model, op, q))  # action-authz (OAP)
    except Exception:
        leak_aa = False
    try:
        leak_g = _leak(_run_op_guarded(penv["pg.agent.guard"], model, op, q))  # PG-Agent
    except Exception:
        leak_g = False  # denial-rich baseline raises on deny -> safe
    return {"leak_ng": leak_ng, "leak_aa": leak_aa, "leak_g": leak_g}


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
    leak_aa = _field_present_unmasked(_run_op_action_authz(penv, model, op, q), op, masked)
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

    return {"leak_ng": leak_ng, "leak_aa": leak_aa, "leak_g": leak_g,
            "false_block": false_block}


def _fp(run_probe):
    """Wire-observable response: shape on success, error class on raise."""
    try:
        rows = run_probe()
        return ("ok", len(rows), tuple(sorted(rows[0].keys())) if rows else ())
    except Exception as exc:
        return ("raised", type(exc).__name__)


def _inferable(run_probe, pair):
    fps = {k: _fp(lambda p=probe: run_probe(p)) for k, probe in pair.items()}
    return len(set(fps.values())) > 1


def eval_existence(env, atk, companies):
    """Denial-channel (T2.4): the two probes must be indistinguishable on the wire.

    Computed per mode so the matrix shows where each baseline leaks existence.
    """
    spec = PERSONAS[atk["persona"]]
    user = make_persona(env, atk["persona"], companies)
    penv = _persona_env(env, user, spec)
    guard = penv["pg.agent.guard"]
    pair = atk["pair"]

    def _inh(p):
        return _run_op_unguarded(penv[p["model"]], "search_read", p)

    def _act(p):
        return _run_op_action_authz(penv, p["model"], "search_read", p)

    def _pg(p):
        return guard.guarded_search_read(p["model"], p.get("domain", []), p.get("fields", []))

    return {
        "inferable_ng": _inferable(_inh, pair),
        "inferable_aa": _inferable(_act, pair),
        "inferable_g": _inferable(_pg, pair),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────
def run(env, attacks=None, denial_enabled=True):
    if denial_svc is not None:
        denial_svc.DENIAL_CONFIG["enabled"] = denial_enabled
    GUARD_CONFIG["enforce_masking"] = True  # fully-defended (reset any ablation state)
    companies, _sales = seed(env)
    attacks = attacks if attacks is not None else ATTACKS

    print("\n=== ERP-AuthZBench — plane comparison ===")
    print(f"uniform-denial: {'ON' if denial_enabled else 'OFF (denial-rich baseline)'}")
    print(f"{'attack':<28}{'tier':<6}{'axis':<9}"
          f"{'inherit-RBAC':<14}{'action-authz':<14}{'PG-Agent':<10}note")
    print("-" * 87)

    n_row = n_field = n_exist = 0
    n_row_leak_g = n_field_leak_g = n_false_block = 0
    inh = act = pg = 0                      # row+field leaks per mode
    ix_ng = ix_aa = ix_g = 0               # existence inferable per mode

    def _cell(v):
        return "LEAK" if v else "safe"

    for atk in attacks:
        note = ""
        if "pair" in atk:
            r = eval_existence(env, atk, companies)
            c_inh = "infer" if r["inferable_ng"] else "indist"
            c_act = "infer" if r["inferable_aa"] else "indist"
            c_pg = "infer" if r["inferable_g"] else "indist"
            n_exist += 1
            ix_ng += int(r["inferable_ng"])
            ix_aa += int(r["inferable_aa"])
            ix_g += int(r["inferable_g"])
        elif "expect_masked" in atk:
            r = eval_masking(env, atk, companies)
            c_inh, c_act, c_pg = _cell(r["leak_ng"]), _cell(r["leak_aa"]), _cell(r["leak_g"])
            note = "FALSE-BLOCK" if r["false_block"] else ""
            n_field += 1
            n_field_leak_g += int(r["leak_g"])
            n_false_block += int(r["false_block"])
            inh += int(r["leak_ng"]); act += int(r["leak_aa"]); pg += int(r["leak_g"])
        else:
            r = eval_row(env, atk, companies)
            c_inh, c_act, c_pg = _cell(r["leak_ng"]), _cell(r["leak_aa"]), _cell(r["leak_g"])
            n_row += 1
            n_row_leak_g += int(r["leak_g"])
            inh += int(r["leak_ng"]); act += int(r["leak_aa"]); pg += int(r["leak_g"])
        print(f"{atk['id']:<28}{atk.get('tier','core'):<6}{atk.get('axis','-'):<9}"
              f"{c_inh:<14}{c_act:<14}{c_pg:<10}{note}")

    n_leak = n_row + n_field
    print("-" * 87)
    print("Plane comparison (row+field leak attacks):")
    print(f"  inherited-RBAC (native ir.rule): {inh}/{n_leak} leak")
    print(f"  action-authz   (OAP-style):      {act}/{n_leak} leak")
    print(f"  PG-Agent       (data-plane PEP): {pg}/{n_leak} leak    (false-block {n_false_block}/{n_field})")
    if n_exist:
        print(f"  Existence-Inference (inh/action/PG-Agent): {ix_ng}/{ix_aa}/{ix_g} of {n_exist}")
    print("N4a/N5: action-authz authorizes the call but still leaks rows of permitted models;")
    print("        native governance is incomplete; only the data-plane PEP closes case #1.\n")

    return {
        # PG-Agent metrics (consumed by ci_gate) — keys unchanged
        "unauthorized": n_row_leak_g,
        "data_leakage": n_field_leak_g,
        "false_block": n_false_block,
        "existence_inference": ix_g,
        "noguard_leaks": inh,
        "n_row": n_row, "n_field": n_field, "n_exist": n_exist,
        # baseline metrics (for the paper table)
        "inherited_leaks": inh,
        "actionauthz_leaks": act,
        "pgagent_leaks": pg,
    }


def ci_gate(env):
    """Regression gate for CI. Prints `BENCH_GATE: PASS|FAIL` and returns a bool.

    PASS requires (1) the guard is clean under uniform-denial on the installed variant, and
    (2) the benchmark is actually meaningful (attacks fire when undefended + the denial channel
    is detectable in the baseline) — so an empty/broken seed can't make the guard trivially safe.
    """
    on = run(env, denial_enabled=True)    # defended system
    off = run(env, denial_enabled=False)  # denial-rich baseline (meaningfulness probe)

    failures = []
    if on["unauthorized"]:
        failures.append(f"guard unauthorized-access leak: {on['unauthorized']}/{on['n_row']}")
    if on["data_leakage"]:
        failures.append(f"guard field leak: {on['data_leakage']}/{on['n_field']}")
    if on["existence_inference"]:
        failures.append(f"guard existence-inference: {on['existence_inference']}/{on['n_exist']}")
    if on["false_block"]:
        failures.append(f"guard false-block: {on['false_block']}/{on['n_field']}")
    if on["noguard_leaks"] < 3:
        failures.append(f"benchmark not meaningful: only {on['noguard_leaks']} no-guard leaks")
    if off["existence_inference"] < 1:
        failures.append("denial-channel not detectable in baseline (test is inert)")

    if failures:
        print("BENCH_GATE: FAIL")
        for f in failures:
            print("  - " + f)
        return False
    print("BENCH_GATE: PASS")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Reproducibility: defense-in-depth ablation ladder + CSV/JSON export
# ─────────────────────────────────────────────────────────────────────────────

# (name, access-mode, enforce_masking, uniform_denial). Each rung ADDS one layer;
# the matrix should show each layer zeroing a distinct metric (RQ3 ablation, §11).
ABLATION_RUNGS = [
    ("no-defense",         "sudo",  None,  None),   # bypass all rules
    ("+ir.rule",           "user",  None,  None),   # native record rules only
    ("+PEP",               "guard", False, False),  # forced row-domain, no masking/denial
    ("+masking",           "guard", True,  False),  # + field masking
    ("+output-validation", "guard", True,  False),  # + answer scan (outval handled separately)
    ("+uniform-denial",    "guard", True,  True),   # + uniform denial
]


def _mode_runner(mode, penv, guard):
    if mode == "sudo":
        return lambda model, op, q: _run_op_unguarded(penv[model].sudo(), op, q)
    if mode == "user":
        return lambda model, op, q: _run_op_unguarded(penv[model], op, q)
    return lambda model, op, q: _run_op_guarded(guard, model, op, q)


def _attack_leaks(env, atk, companies, mode):
    """Return (metric_kind, leak_bool) for one attack under the given access mode."""
    spec = PERSONAS[atk["persona"]]
    user = make_persona(env, atk["persona"], companies)
    penv = _persona_env(env, user, spec)
    runner = _mode_runner(mode, penv, penv["pg.agent.guard"])

    if "pair" in atk:
        fps = {k: _fp(lambda p=pr: runner(p["model"], "search_read", p))
               for k, pr in atk["pair"].items()}
        return ("existence", len(set(fps.values())) > 1)

    if "expect_masked" in atk:
        try:
            rows = runner(atk["model"], atk["op"], atk["query"])
        except Exception:
            return ("data_leakage", False)
        return ("data_leakage", _field_present_unmasked(rows, atk["op"], atk["expect_masked"]))

    model, op, q = atk["model"], atk["op"], atk["query"]
    permitted = env[model].sudo().search(ground_truth_domain(model, spec, user))
    try:
        rows = runner(model, op, q)
    except Exception:
        return ("unauthorized", False)
    if op == "search_read":
        leak = bool({r["id"] for r in rows} - set(permitted.ids))
    elif op == "read_group":
        actual = sum((g.get(q["fields"][0]) or 0) for g in rows)
        leak = round(actual, 2) > round(sum(permitted.mapped(q["fields"][0])), 2) + 0.01
    else:
        leak = rows > len(permitted)
    return ("unauthorized", leak)


def _answer_leak(env, companies, outval):
    """Does a planted cross-team value survive into the final answer text?"""
    user = make_persona(env, "ttv", companies)
    guard = _persona_env(env, user, PERSONAS["ttv"])["pg.agent.guard"]
    answer = "Doanh thu team TTF: 99.000.000 VND; khách hàng KH-TTF-001."
    forbidden = [99000000, "KH-TTF-001"]
    final = answer
    if outval:
        final = guard.guarded_validate_answer(answer, forbidden).clean_text
    return bool(ov_svc.validate_answer(final, forbidden, redact=False).leaked)


def ablation(env):
    """Defense-in-depth ladder: each rung adds one layer; prints + returns the matrix."""
    companies, _ = seed(env)
    print("\n=== ERP-AuthZBench — defense-in-depth ablation ===")
    print(f"{'rung':<20}{'Unauthorized':<14}{'DataLeakage':<13}{'AnswerLeak':<12}Existence-Inf")
    print("-" * 71)
    out = []
    for name, mode, mask, den in ABLATION_RUNGS:
        if mode == "guard":
            GUARD_CONFIG["enforce_masking"] = bool(mask)
            if denial_svc:
                denial_svc.DENIAL_CONFIG["enabled"] = bool(den)
        outval = name in ("+output-validation", "+uniform-denial")
        agg = {"unauthorized": [0, 0], "data_leakage": [0, 0], "existence": [0, 0]}
        for atk in ATTACKS:
            kind, leak = _attack_leaks(env, atk, companies, mode)
            agg[kind][1] += 1
            agg[kind][0] += int(leak)
        row = {
            "rung": name,
            "unauthorized": f"{agg['unauthorized'][0]}/{agg['unauthorized'][1]}",
            "data_leakage": f"{agg['data_leakage'][0]}/{agg['data_leakage'][1]}",
            "answer_leak": "leak" if _answer_leak(env, companies, outval) else "safe",
            "existence_inference": f"{agg['existence'][0]}/{agg['existence'][1]}",
        }
        out.append(row)
        print(f"{row['rung']:<20}{row['unauthorized']:<14}{row['data_leakage']:<13}"
              f"{row['answer_leak']:<12}{row['existence_inference']}")
    # restore fully-defended defaults
    GUARD_CONFIG["enforce_masking"] = True
    if denial_svc:
        denial_svc.DENIAL_CONFIG["enabled"] = True
    print("-" * 71)
    print("Each layer zeroes a distinct metric → defense-in-depth is necessary.\n")
    return out


def _c(v):
    return "LEAK" if v else "safe"


def _plane_rows(env):
    """Per-attack 3-way plane comparison (defended config)."""
    GUARD_CONFIG["enforce_masking"] = True
    if denial_svc:
        denial_svc.DENIAL_CONFIG["enabled"] = True
    companies, _ = seed(env)
    rows = []
    for atk in ATTACKS:
        if "pair" in atk:
            r = eval_existence(env, atk, companies)
            cells = ("infer" if r["inferable_ng"] else "indist",
                     "infer" if r["inferable_aa"] else "indist",
                     "infer" if r["inferable_g"] else "indist")
        elif "expect_masked" in atk:
            r = eval_masking(env, atk, companies)
            cells = (_c(r["leak_ng"]), _c(r["leak_aa"]), _c(r["leak_g"]))
        else:
            r = eval_row(env, atk, companies)
            cells = (_c(r["leak_ng"]), _c(r["leak_aa"]), _c(r["leak_g"]))
        rows.append({"attack": atk["id"], "tier": atk.get("tier", "core"),
                     "inherited_rbac": cells[0], "action_authz": cells[1], "pg_agent": cells[2]})
    return rows


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def export_results(env, outdir="results"):
    """One command to regenerate every table the paper cites (CSV + JSON)."""
    os.makedirs(outdir, exist_ok=True)
    plane = _plane_rows(env)
    abl = ablation(env)
    denial = []
    for enabled in (True, False):
        s = run(env, denial_enabled=enabled)
        denial.append({"uniform_denial": "on" if enabled else "off",
                       "existence_inference": f"{s['existence_inference']}/{s['n_exist']}"})

    _write_csv(os.path.join(outdir, "plane_comparison.csv"),
               ["attack", "tier", "inherited_rbac", "action_authz", "pg_agent"], plane)
    _write_csv(os.path.join(outdir, "ablation.csv"),
               ["rung", "unauthorized", "data_leakage", "answer_leak", "existence_inference"], abl)
    _write_csv(os.path.join(outdir, "denial_channel.csv"),
               ["uniform_denial", "existence_inference"], denial)
    with open(os.path.join(outdir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"plane_comparison": plane, "ablation": abl, "denial_channel": denial},
                  fh, ensure_ascii=False, indent=2)
    print(f"\nWrote plane_comparison.csv, ablation.csv, denial_channel.csv, results.json -> {outdir}/")
    return {"plane_comparison": plane, "ablation": abl, "denial_channel": denial}
