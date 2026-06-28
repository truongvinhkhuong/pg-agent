# -*- coding: utf-8 -*-
"""Offline tests for the performance/overhead plane (§4.8) — no Odoo, no Docker.

CALIBRATION (the policy_model/write_model pattern): the committed results/overhead.csv is produced
by the LIVE guard (`guard._authz_domain` + `sensitivity.partition_fields` — real Odoo group/company/
clearance resolution); the pure `overhead.py` predicts the SAME structural metrics WITHOUT Odoo from
the committed POLICY + SENSITIVITY. We assert pure == committed CSV (so a POLICY/sensitivity drift, or
a guard-resolution change, fails CI on both sides) PLUS the bound invariants the §4.8 claim rests on.

The overhead is a STRUCTURAL BOUND, not a latency: `authz_leaves` indexed conjuncts (<=3), each a
relation-path traversal of depth `closure_hops` (<=1) over the indexed FK, and an O(result_rows *
masked_fields) post-fetch mask scan — no per-row query, no join explosion, no quadratic term. The
wall-clock is printed by the live driver (indicative, not gated) and never enters this test.
Mirrors tests/test_write_model.py.
"""
import csv
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
import overhead as ovh                                  # noqa: E402

_CSV = os.path.join(_D, "..", "results", "overhead.csv")


def _rows():
    with open(_CSV, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ── calibration: the committed CSV must equal the pure prediction, field-for-field ──
def test_live_csv_matches_pure_prediction():
    live, pred = _rows(), ovh.predict_rows()
    assert len(live) == len(pred) == 20             # 5 personas x 4 models
    for r, p in zip(live, pred):
        for k in ovh.FIELDS:
            assert str(r[k]) == str(p[k]), f"{r['persona']}/{r['model']} {k}: {r[k]} != {p[k]}"


# ── the bound invariants the §4.8 claim depends on ──────────────────────────
def test_authz_overhead_is_bounded():
    for r in _rows():
        assert int(r["authz_leaves"]) <= 3          # team + company + owner, at most
        assert int(r["closure_hops"]) <= 1          # one FK hop (child -> header); no deeper traversal
        assert r["mask_cost_class"] == ovh.MASK_COST_CLASS


def test_masking_bounded_by_declared_surface():
    for r in _rows():
        assert 0 <= int(r["masked_fields"]) <= int(r["sensitivity_surface"])


def test_see_all_persona_drops_the_team_leaf():
    # viewer_all is see-all (no team scoping) -> no team leaf, fewer conjuncts, and at its
    # confidential clearance it masks only the single restricted field (line.price_unit).
    va = [r for r in _rows() if r["persona"] == "viewer_all"]
    assert va and all(r["team_scoped"] == "False" for r in va)
    assert all(int(r["authz_leaves"]) == 1 for r in va)          # company leaf only
    line = next(r for r in va if r["model"].endswith(".line"))
    assert int(line["masked_fields"]) == 1                       # price_unit (restricted) only
    assert all(int(r["masked_fields"]) == 0 for r in va if not r["model"].endswith(".line"))


def test_owner_scope_only_when_own_only_and_owner_path():
    # sales_own (own_only) gets the owner leaf ONLY on the line (the only model with an owner_path).
    so = {(r["model"], r["owner_scoped"]) for r in _rows() if r["persona"] == "sales_own"}
    assert ("pco.sale.order.line", "True") in so
    assert ("pco.sale.order.payment", "False") in so
    assert all(r["owner_scoped"] == "False" for r in _rows() if r["persona"] != "sales_own")


# ── structural invariants of the pure module ─────────────────────────────────
def test_prediction_is_deterministic_and_well_shaped():
    a, b = ovh.predict_rows(), ovh.predict_rows()
    assert a == b                                   # pure, no hidden state
    assert len({(r["persona"], r["model"]) for r in a}) == 20
    assert ovh.COMPLEXITY["masking"] == ovh.MASK_COST_CLASS
    assert "indexed" in ovh.COMPLEXITY["authz"]


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} overhead-plane tests passed.")
