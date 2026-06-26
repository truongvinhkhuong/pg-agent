# -*- coding: utf-8 -*-
"""Module-agnostic policy-closure SCALE scanner (F10 Increment 1) — Odoo shell, static.

Generalizes the pco-specific differential linter (tests/policy_linter.py) to ANY set of
Odoo modules. Purely STATIC and read-only: it reads ir.model / ir.model.fields / ir.rule /
ir.model.data only — no seed, no personas, no synthetic data, no runtime differential
(that is Increment 2's emit+verify). It auto-DISCOVERS the governance graph + discriminators
from the live schema, classifies every (model, discriminator) via the generalized core
(policy_closure.derive_gaps), and quantifies how many relation-path closures it derives
automatically vs the hand-written guard POLICY.

Run in an Odoo shell against a DB with the target modules installed:

    odoo shell -d scale --no-http <<'PY'
    exec(open('tests/policy_scan.py').read())
    scan(env, modules=("sale", "account", "stock"))   # -> results/scale/{coverage,rules}.csv
    PY

Self-contained: no dependency on the benchmark harness (evaluation_script).
"""
import csv
import os
import sys

sys.path.insert(0, "data/erp_authzbench")
from policy_closure import derive_gaps                      # noqa: E402
from domain_ast import parse_domain, governance_fields      # noqa: E402

DEFAULT_MODULES = ("sale", "account", "stock")

# Hand-written POLICY paths the guard ships today (pep_guard.py:47-68): 4 team_path +
# 4 company_path + 1 owner_path = 9 non-null relation paths. The manual-burden baseline.
POLICY_BASELINE_PATHS = 9


def _write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _scope_models(env, modules):
    """(scope:set, model->family:dict): non-abstract/non-transient models whose name is in
    the target module FAMILIES (prefix allowlist).

    Driven straight off ir.model by name prefix — NOT ir.model.data, which attributes a
    model_<x> xmlid to every module that merely REFERENCES a model (uninstall tracking)
    and so leaks res.company/mail.message into scope. `modules` ("sale","account",...) are
    the family roots; a model qualifies iff name == root or name startswith root + ".".
    """
    roots = tuple(modules)
    prefixes = tuple(r + "." for r in roots)
    scope, by_module = set(), {}
    for rec in env["ir.model"].sudo().search([]):
        name = rec.model
        if not (name in roots or name.startswith(prefixes)):
            continue
        try:
            mdl = env[name]
        except KeyError:
            continue
        if getattr(mdl, "_abstract", False) or getattr(mdl, "_transient", False):
            continue
        scope.add(name)
        by_module.setdefault(name, name.split(".", 1)[0])
    return scope, by_module


def _build_edges(env, scope):
    """Stored Many2one CONTAINMENT edges between in-scope models (required + ondelete=cascade).

    Containment = the composing-parent link (order_id/move_id/picking_id); excludes audit/
    reference M2O (create_uid/write_uid/user_id/partner_id) which are never required+cascade,
    so a child has a single containment path -> unambiguous closure. The ir.model.fields
    ondelete column is `on_delete` on some Odoo versions and `ondelete` on others -> introspect.
    """
    imf = env["ir.model.fields"].sudo()
    ondelete_col = "on_delete" if "on_delete" in imf._fields else "ondelete"
    recs = imf.search([("model", "in", list(scope)), ("ttype", "=", "many2one"),
                       ("store", "=", True), ("required", "=", True),
                       (ondelete_col, "=", "cascade")])
    return sorted({(f.model, f.name, f.relation) for f in recs if f.relation in scope})


def _build_ruled(env, scope):
    """ruled[field] -> set(models with an active rule whose leaf binds field to the user/
    company CONTEXT (governance_fields). rule_rows keep parse_domain provenance for rules.csv."""
    ruled, rule_rows = {}, []
    for r in env["ir.rule"].sudo().search([("active", "=", True)]):
        model = r.model_id.model
        if model not in scope:
            continue
        domain = r.domain_force or ""
        gfields = governance_fields(domain)                 # context-bound discriminators
        all_fields, simple, reason = parse_domain(domain)   # provenance only
        rule_rows.append({"model": model, "rule": (r.name or "")[:80],
                          "fields": ",".join(sorted(all_fields)) or "(none)",
                          "governance_fields": ",".join(sorted(gfields)) or "(none)",
                          "pushdownable": simple, "reason": reason})
        for f in gfields:
            ruled.setdefault(f, set()).add(model)
    return ruled, rule_rows


def _build_defines(env, scope, discriminator_fields):
    """defines[field] = in-scope models with the STORED column; mirrors = stored-RELATED
    subset (excluded from hops-0 definers so closures stay relational — correction #1)."""
    defines, mirrors = {}, {}
    if not discriminator_fields:
        return defines, mirrors
    recs = env["ir.model.fields"].sudo().search(
        [("model", "in", list(scope)), ("name", "in", list(discriminator_fields)),
         ("store", "=", True)])
    for f in recs:
        defines.setdefault(f.name, set()).add(f.model)
        if (f.related or "").strip():
            mirrors.setdefault(f.name, set()).add(f.model)
    return defines, mirrors


def _burden_metric(scope, edges, discriminators, records, rule_rows):
    reach_closures = [r for r in records if r["reachable"] and r["hops"] >= 1]
    by_verdict = {}
    for r in records:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
    n_simple = sum(1 for rr in rule_rows if rr["pushdownable"])
    return {
        "n_models": len(scope), "n_edges": len(edges),
        "n_discriminators": len(discriminators),
        "n_reachable_closures": len(reach_closures),
        "n_governed": by_verdict.get("GOVERNED", 0),
        "n_gap": by_verdict.get("GAP", 0),
        "n_root_ungoverned": by_verdict.get("ROOT-UNGOVERNED", 0),
        "n_parent_ungoverned": by_verdict.get("PARENT-UNGOVERNED", 0),
        "n_unreachable": by_verdict.get("UNREACHABLE", 0),
        "n_rules": len(rule_rows), "n_rules_simple": n_simple,
        "n_rules_complex": len(rule_rows) - n_simple,
        "baseline_policy_paths": POLICY_BASELINE_PATHS,
        "burden_reduction_x": round(len(reach_closures) / POLICY_BASELINE_PATHS, 1),
    }


def _print_report(modules, records, metric):
    print(f"\n=== ERP-AuthZBench — policy-closure SCALE scan: {','.join(modules)} ===")
    print("discriminators = context-bound (field bound to user/company in a rule leaf); "
          "edges = containment only (required + ondelete=cascade)")
    print(f"models={metric['n_models']}  m2o-edges={metric['n_edges']}  "
          f"discriminators={metric['n_discriminators']}  "
          f"rules={metric['n_rules']} (simple={metric['n_rules_simple']}/complex={metric['n_rules_complex']})")
    print(f"verdicts: GOVERNED={metric['n_governed']}  GAP={metric['n_gap']}  "
          f"ROOT-UNGOVERNED={metric['n_root_ungoverned']}  "
          f"PARENT-UNGOVERNED={metric['n_parent_ungoverned']}  UNREACHABLE={metric['n_unreachable']}")
    print(f"** manual burden: {metric['n_reachable_closures']} relational closures auto-derived "
          f"vs {metric['baseline_policy_paths']} hand-written POLICY paths "
          f"= {metric['burden_reduction_x']}x **")

    by_field = {}
    for r in records:
        d = by_field.setdefault(r["field"], {"reach": 0, "gov": 0, "gap": 0, "pung": 0, "root": 0})
        if r["reachable"]:
            d["reach"] += 1
            key = {"GOVERNED": "gov", "GAP": "gap", "PARENT-UNGOVERNED": "pung"}.get(r["verdict"])
            if key:
                d[key] += 1
        if r["verdict"] == "ROOT-UNGOVERNED":
            d["root"] += 1
    print("\n-- coverage by discriminator --")
    print(f"{'discriminator':<22}{'reachable':<11}{'GOVERNED':<10}{'GAP':<6}{'P-UNGOV':<9}ROOT")
    for field in sorted(by_field):
        d = by_field[field]
        print(f"{field:<22}{d['reach']:<11}{d['gov']:<10}{d['gap']:<6}{d['pung']:<9}{d['root']}")

    gaps = [r for r in records if r["verdict"] == "GAP"]
    if gaps:
        print(f"\n-- relational-traversal GAPs ({len(gaps)}) --")
        for r in sorted(gaps, key=lambda x: (x["field"], x["model"])):
            print(f"  {r['field']:<18}{r['model']:<36}closure={r['derived_closure']}")


def scan(env, modules=DEFAULT_MODULES, outdir="results/scale"):
    """Static governance scan over `modules`. Prints a report, writes coverage + rules CSVs."""
    scope, by_module = _scope_models(env, modules)
    edges = _build_edges(env, scope)
    ruled, rule_rows = _build_ruled(env, scope)
    discriminators = set(ruled)
    defines, mirrors = _build_defines(env, scope, discriminators)
    records = derive_gaps(edges, defines, ruled, scope, exclude_self_definer=mirrors)
    metric = _burden_metric(scope, edges, discriminators, records, rule_rows)
    _print_report(modules, records, metric)

    os.makedirs(outdir, exist_ok=True)
    cov_cols = ["module", "model", "discriminator", "relation_path", "hops", "definer_model",
                "axis_governed", "native_rule", "parent_governed", "verdict", "derived_closure"]
    cov_rows = sorted(
        ({"module": by_module.get(r["model"], ""), "model": r["model"],
          "discriminator": r["discriminator"], "relation_path": r["relation_path"] or "",
          "hops": r["hops"], "definer_model": r["definer_model"] or "",
          "axis_governed": r["axis_governed"], "native_rule": r["native_rule"],
          "parent_governed": r["parent_governed"], "verdict": r["verdict"],
          "derived_closure": r["derived_closure"] or ""}
         for r in records if r["reachable"]),         # reachable rows only (drop UNREACHABLE noise)
        key=lambda x: (x["module"], x["model"], x["discriminator"]))
    _write_csv(os.path.join(outdir, "coverage.csv"), cov_cols, cov_rows)
    _write_csv(os.path.join(outdir, "rules.csv"),
               ["model", "rule", "fields", "governance_fields", "pushdownable", "reason"],
               sorted(rule_rows, key=lambda x: (x["model"], x["fields"])))
    print(f"\nWrote coverage.csv ({len(cov_rows)} reachable rows), rules.csv ({len(rule_rows)}) -> {outdir}/\n")
    return records, metric


def _parent_rule_by_key(rule_rows):
    """(definer_model, field) -> (pushdownable, reason). A gap's parent rule is pushdownable
    only if EVERY active rule governing that (model, field) is simple; else the first complex
    reason (we refuse to emit when any governing rule is non-pushdownable)."""
    acc = {}
    for rr in rule_rows:
        gfs = [g for g in rr["governance_fields"].split(",") if g and g != "(none)"]
        for f in gfs:
            acc.setdefault((rr["model"], f), []).append((rr["pushdownable"], rr["reason"]))
    out = {}
    for key, lst in acc.items():
        if all(p for p, _ in lst):
            out[key] = (True, "simple")
        else:
            out[key] = next((False, reason) for p, reason in lst if not p)
    return out


def emit_classify(env, modules=DEFAULT_MODULES, outdir="results/scale"):
    """F10 Increment 2 (real Odoo, READ-ONLY): for each discovered GAP, emit the proposed
    native ir.rule domain — gated on the PARENT rule's pushdownability — or flag manual-review.
    Writes <outdir>/emit.csv. Does NOT install anything."""
    from policy_emit import classify_emit

    scope, by_module = _scope_models(env, modules)
    edges = _build_edges(env, scope)
    ruled, rule_rows = _build_ruled(env, scope)
    defines, mirrors = _build_defines(env, scope, set(ruled))
    records = derive_gaps(edges, defines, ruled, scope, exclude_self_definer=mirrors)
    gaps = [r for r in records if r["verdict"] == "GAP"]

    parents = _parent_rule_by_key(rule_rows)
    rows, n_push = classify_emit(gaps, parents)
    for r in rows:                                   # decorate with owning module
        r["module"] = by_module.get(r["model"], "")

    print(f"\n=== F10 Increment 2 — emit-classify (real Odoo: {','.join(modules)}) ===")
    print(f"EMIT: {n_push} pushdownable / {len(gaps)} GAPs ({len(gaps) - n_push} manual-review)")
    for r in sorted(rows, key=lambda x: x["emit_status"] != "pushdownable"):
        print(f"  [{r['emit_status']:<22}] {r['model']:<34} {r['emitted_domain'] or '('+r['parent_reason']+')'}")

    os.makedirs(outdir, exist_ok=True)
    _write_csv(os.path.join(outdir, "emit.csv"),
               ["module", "model", "discriminator", "relation_path", "definer_model",
                "parent_pushdownable", "parent_reason", "emit_status", "emitted_domain"],
               sorted(rows, key=lambda x: (x["module"], x["model"], x["discriminator"])))
    print(f"Wrote emit.csv ({len(rows)} rows) -> {outdir}/\n")
    return rows


def scan_corpus(env, modules, outdir="results/scale/corpus", baseline="results/scale/coverage.csv"):
    """ENDEMICITY scan: run the validated `scan` over a CORPUS of business domains, summarize the
    finding as BREADTH (domains with >=1 gap / domains with an at-risk child) + the per-domain
    distribution (NOT a pooled %), and keyed-diff verdict DRIFT vs the committed 3-module baseline so
    a new rule that closes a gap (or a re-routed closure) is explained, never masked. Writes the
    corpus coverage + endemic + drift CSVs under `outdir`; does NOT overwrite the baseline coverage.csv."""
    from endemic import endemic_summary, diff_baseline, read_coverage_csv

    records, _metric = scan(env, modules, outdir=outdir)        # corpus coverage.csv/rules.csv -> outdir
    s = endemic_summary(records)
    drift = diff_baseline(records, read_coverage_csv(baseline)) if os.path.exists(baseline) else []
    installed = sorted(m.name for m in
                       env["ir.module.module"].sudo().search([("state", "=", "installed")]))

    print("\n=== ERP-AuthZBench — ENDEMICITY across the CE corpus ===")
    print(f"BREADTH: the relational-traversal gap appears in {s['n_domains_with_gap']} of "
          f"{s['n_domains_with_at_risk']} business domains that contain an at-risk child "
          f"({s['n_domains_scanned']} domains scanned).")
    print(f"pooled gap-rate (supporting): {s['gaps_total']}/{s['at_risk_total']} = {s['pooled_gap_rate']}  "
          f"(per-domain rate {s['rate_min']}..{s['rate_max']}); context gaps/reachable = "
          f"{s['gaps_total']}/{s['n_reachable_rows']} = {s['gaps_over_reachable']} (low per-model).")
    print("-- per domain (child x axis: gaps / at-risk) --")
    for dm in sorted(s["per_domain"]):
        d = s["per_domain"][dm]
        print(f"  {dm:<16}{d['gaps']}/{d['at_risk']}  (rate {d['rate']})")
    if drift:
        print(f"-- verdict DRIFT vs 3-module baseline ({len(drift)}) --")
        for r in drift:
            print(f"  {r['model']:<34}{r['discriminator']:<16}{r['before']} -> {r['after']}  [{r['cause']}]")
    else:
        print("-- no verdict drift vs 3-module baseline: the 3 baseline domains reproduce exactly --")

    os.makedirs(outdir, exist_ok=True)
    erows = [{"domain": dm, "gaps": s["per_domain"][dm]["gaps"],
              "at_risk": s["per_domain"][dm]["at_risk"], "rate": s["per_domain"][dm]["rate"]}
             for dm in sorted(s["per_domain"])]
    erows.append({"domain": "TOTAL", "gaps": s["gaps_total"], "at_risk": s["at_risk_total"],
                  "rate": s["pooled_gap_rate"]})
    _write_csv(os.path.join(outdir, "endemic.csv"), ["domain", "gaps", "at_risk", "rate"], erows)
    _write_csv(os.path.join(outdir, "drift.csv"),
               ["model", "discriminator", "before", "after", "cause"], drift)
    with open(os.path.join(outdir, "installed.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(installed) + "\n")
    print(f"\nWrote endemic.csv ({len(erows)} rows), drift.csv ({len(drift)}), coverage.csv, "
          f"installed.txt ({len(installed)} modules) -> {outdir}/\n")
    return s, drift
