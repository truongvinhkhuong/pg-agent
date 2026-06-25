# -*- coding: utf-8 -*-
"""Policy-closure differential linter — Odoo-shell driver (F10 PoC).

Reads the ORM relation graph (ir.model.fields) + existing record rules (ir.rule), feeds
them to the pure core (data/erp_authzbench/policy_closure.derive_closures), then CONFIRMS
each detected gap with a runtime DIFFERENTIAL TEST (child-direct vs closure-allowed rows
as a restricted persona). It also re-derives the hand-written pep_guard.POLICY paths as a
soundness check (matches_policy column).

Run in an Odoo shell AFTER the benchmark harness so its persona/seed helpers are in scope
(POLICY, seed, PERSONAS, make_persona, _persona_env, _write_csv are harness globals):

    odoo shell -c config/odoo.mock.conf -d authzbench --no-http <<'PY'
    exec(open('tests/evaluation_script.py').read())
    exec(open('tests/policy_linter.py').read())
    lint(env)                       # -> results/policy_lint.csv
    lint_gate(env)                  # report-only regression gate
    PY

V-rule variant: install team_security_vrule.xml, then lint(env, outdir="results/vrule").
"""
import os
import re

from policy_closure import derive_closures   # data/erp_authzbench already on sys.path

# Governance axes the linter reasons about. Owner (salesperson_id) is a LOCAL opt-in field,
# not a parent pushdown -> out of scope for relational closure (see policy_closure docstring).
DISCRIMINATORS = {
    "team": ("pco.sale.order", "team_code"),
    "company": ("pco.sale.order", "company_id"),
}

_LINT_COLS = ["model", "axis", "relation_path", "hops", "native_rule", "parent_governed",
              "verdict", "derived_closure", "differential_leak", "matches_policy"]


def _mentions_field(domain_force, field):
    """True iff a record-rule domain string CONSTRAINS `field` (quote-anchored path segment).

    Matches 'team_code' / 'order_id.team_code' (single or double quoted); excludes the
    always-true global rule [(1,'=',1)], the `sale_team_group` decoy, and bare values.
    Heuristic for the PoC; the full compiler would ast.literal_eval the domain and walk
    each leaf's left operand.
    """
    pat = r"""['"](?:[\w.]+\.)?%s['"]""" % re.escape(field)
    return re.search(pat, domain_force or "") is not None


def _build_edges(env):
    """Many2one edges between in-POLICY models, from ir.model.fields (-> the order_id edges)."""
    models = list(POLICY)
    recs = env["ir.model.fields"].sudo().search(
        [("model", "in", models), ("ttype", "=", "many2one")])
    return [(f.model, f.name, f.relation) for f in recs if f.relation in models]


def _build_rules_by_axis(env):
    """Per axis, the set of in-POLICY models carrying a native rule that constrains the axis."""
    by_axis = {axis: set() for axis in DISCRIMINATORS}
    for r in env["ir.rule"].sudo().search([("active", "=", True)]):
        model = r.model_id.model
        if model not in POLICY:
            continue
        for axis, (_dm, field) in DISCRIMINATORS.items():
            if _mentions_field(r.domain_force or "", field):
                by_axis[axis].add(model)
    return by_axis


def _lint_core(env):
    """Static analysis + runtime differential confirmation. Returns the enriched records."""
    edges = _build_edges(env)
    rules_by_axis = _build_rules_by_axis(env)
    records = derive_closures(edges, rules_by_axis, DISCRIMINATORS, list(POLICY))

    companies, _ = seed(env)                       # idempotent (harness global)
    user = make_persona(env, "ttv", companies)
    penv = _persona_env(env, user, PERSONAS["ttv"])

    for r in records:
        model, axis, path = r["model"], r["axis"], r["relation_path"]
        # Soundness: derived path vs the hand-written guard closure (independent oracle).
        pol = POLICY.get(model, {})
        pol_path = pol.get("team_path") if axis == "team" else pol.get("company_path")
        r["matches_policy"] = (path == pol_path)
        # Differential: only meaningful for the team axis (ttv is team-scoped, not company-scoped).
        if axis == "team" and r["reachable"]:
            direct = set(penv[model].search([]).ids)                         # native-rule view
            closure = set(env[model].sudo().search([(path, "=", "ttv")]).ids)  # ground truth
            r["differential_leak"] = "LEAK" if (direct - closure) else "safe"
        else:
            r["differential_leak"] = ""
    return records


def lint(env, outdir="results"):
    """Run the linter, print a table, and write <outdir>/policy_lint.csv."""
    records = _lint_core(env)

    print("\n=== ERP-AuthZBench — policy-closure differential linter (F10 PoC) ===")
    print(f"{'model':<28}{'axis':<9}{'relation_path':<22}{'verdict':<17}{'diff':<6}match-POLICY")
    print("-" * 92)
    for r in records:
        print(f"{r['model']:<28}{r['axis']:<9}{str(r['relation_path']):<22}"
              f"{r['verdict']:<17}{(r['differential_leak'] or '-'):<6}{r['matches_policy']}")
    n_gap = sum(1 for r in records if r["verdict"] == "GAP")
    n_root = sum(1 for r in records if r["verdict"] == "ROOT-UNGOVERNED")
    all_match = all(r["matches_policy"] for r in records if r["reachable"])
    print("-" * 92)
    print(f"POLICY-LINT: {n_gap} GAP(s), {n_root} ROOT-UNGOVERNED, paths reproduce POLICY: {all_match}")

    rows = [{c: ("" if r.get(c) is None else r.get(c)) for c in _LINT_COLS} for r in records]
    os.makedirs(outdir, exist_ok=True)
    _write_csv(os.path.join(outdir, "policy_lint.csv"), _LINT_COLS, rows)
    print(f"Wrote policy_lint.csv -> {outdir}/\n")
    return records


def lint_gate(env):
    """Report-only regression gate. Prints POLICY_LINT_GATE: PASS|FAIL, returns bool.

    GAP existence does NOT fail the gate (GAPs are the expected finding on this mock).
    FAIL only if: (1) a team GAP model is NOT covered by the guard POLICY (a new child both
    unruled natively AND unguarded), (2) no GAP fired (meaningfulness — broken seed/graph),
    or (3) a derived path disagrees with POLICY (the soundness/equivalence invariant).
    """
    records = _lint_core(env)
    team_gaps = [r for r in records if r["verdict"] == "GAP" and r["axis"] == "team"]
    failures = []

    uncovered = sorted({r["model"] for r in team_gaps if r["model"] not in POLICY})
    if uncovered:
        failures.append("team GAP not covered by guard POLICY: " + ", ".join(uncovered))
    if len(team_gaps) < 1:
        failures.append("linter not meaningful: 0 team GAPs (seed/relation graph broken?)")
    mismatched = sorted({r["model"] + "/" + r["axis"]
                         for r in records if r["reachable"] and not r["matches_policy"]})
    if mismatched:
        failures.append("derived path != POLICY: " + ", ".join(mismatched))

    if failures:
        print("POLICY_LINT_GATE: FAIL")
        for f in failures:
            print("  - " + f)
        return False
    print("POLICY_LINT_GATE: PASS")
    return True
