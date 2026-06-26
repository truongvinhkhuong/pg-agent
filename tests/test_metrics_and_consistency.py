# -*- coding: utf-8 -*-
"""Offline tests for TB.3 metrics registry + TB.2 self-consistency + the TB.1 blind-spot proofs.

No Odoo. Mirrors test_numeric_verifier. The load-bearing tests prove (deterministically, against
the real numeric_verifier) that the WF-A..D wrong-formula values BIND under TB.1 (genuine blind
spot) while the contrast value does not — the whole premise of TB.2/TB.3.
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
sys.path.insert(0, os.path.join(_D, "..", "addons", "pg_agent_guard", "services"))
sys.path.insert(0, os.path.join(_D, "..", "addons", "pg_agent_guard", "models"))
import metrics                                   # noqa: E402
from consistency import self_consistency         # noqa: E402
from integrity import formula_wrong_value        # noqa: E402
import numeric_verifier as nv                    # noqa: E402
import sensitivity                               # noqa: E402

# Per-group values whose pairwise diffs / shares are NOT also identities (clean blind-spot test).
VALS = [1000.0, 640.0, 410.0, 170.0]
_PERSONA_CLEARANCE = {"viewer_all": "confidential", "ttv": "internal"}


def _t(x):
    return str(int(x)) if float(x) == int(x) else str(x)


# ── TB.3 registry shape ──────────────────────────────────────────────────────
def test_metric_names_unique_nonempty():
    names = metrics.metric_names()
    assert names and len(names) == len(set(names))


def test_each_metric_has_required_keys():
    for name in metrics.metric_names():
        m = metrics.metric_spec(name)
        for k in ("model", "measure", "agg", "dimension", "domain", "sensitivity", "persona"):
            assert k in m, (name, k)
        assert m["agg"] in ("sum", "count", "avg"), (name, m["agg"])


def test_measure_sensitivity_matches_registry():
    # metrics.py must not drift from sensitivity.py for the measure it pins.
    for name in metrics.metric_names():
        m = metrics.metric_spec(name)
        if m["measure"] is None:                 # count metric: no measure -> declared public
            assert m["sensitivity"] == "public", name
            continue
        assert m["sensitivity"] == sensitivity.field_level(m["model"], m["measure"]), name


def test_persona_clearance_covers_measure():
    for name in metrics.metric_names():
        m = metrics.metric_spec(name)
        clr = _PERSONA_CLEARANCE.get(m["persona"], "confidential")
        assert sensitivity.can_see(clr, m["sensitivity"]), (name, m["persona"])
    # ttv (internal) must NOT cover a confidential measure (the persona-clearance trap)
    assert not sensitivity.can_see("internal", "confidential")


# ── TB.2 voting (pure) ───────────────────────────────────────────────────────
def test_majority_outvotes_minority():
    r = self_consistency([10.0, 10.0, 7.0])
    assert r.consensus == 10.0 and r.flagged is False and 7.0 in r.minority


def test_three_distinct_refuses():
    r = self_consistency([10.0, 8.0, 7.0])
    assert r.flagged is True and r.consensus is None


def test_unanimous_passes():
    r = self_consistency([10.0, 10.0, 10.0])
    assert r.agreement == 3 and r.flagged is False and r.minority == []


def test_rounding_tolerance_clusters():
    r = self_consistency([100.0, 100.4, 100.0])   # 100.4 within 0.5% of 100 -> same cluster
    assert r.flagged is False and r.agreement == 3


def test_governed_crosscheck_flags():
    r = self_consistency([10.0, 10.0, 10.0], governed=12.0)
    assert r.flagged is True and r.reason == "consensus!=governed"


def test_voting_never_raises():
    for v in ([], [5.0], [None, "x", True]):
        self_consistency(v)


# ── formula_wrong_value (pure) ───────────────────────────────────────────────
def test_formula_wrong_values():
    assert formula_wrong_value("top_group_instead_of_sum", VALS) == 1000.0
    assert formula_wrong_value("wrong_group_identity", VALS) == 640.0
    assert formula_wrong_value("sum_instead_of_avg", VALS) == sum(VALS)
    assert formula_wrong_value("wrong_pair_diff", VALS) == 1000.0 - 410.0      # a different pair
    assert formula_wrong_value("subtotal_instead_of_total", VALS) == sum(VALS) / 1.1


# ── THE CRUX: TB.1 genuinely MISSES WF-A..D, and CATCHES the contrast ─────────
def test_tb1_misses_wf_a_top_group():
    assert nv.verify_numbers(_t(formula_wrong_value("top_group_instead_of_sum", VALS)), VALS).verified


def test_tb1_misses_wf_b_wrong_group():
    assert nv.verify_numbers(_t(formula_wrong_value("wrong_group_identity", VALS)), VALS).verified


def test_tb1_misses_wf_c_wrong_pair_diff():
    assert nv.verify_numbers(_t(formula_wrong_value("wrong_pair_diff", VALS)), VALS).verified


def test_tb1_misses_wf_d_wrong_share():
    share = formula_wrong_value("wrong_share", VALS)            # 640/2220*100
    assert nv.verify_numbers(f"{share}%", VALS).verified


def test_tb1_misses_sum_instead_of_avg():
    assert nv.verify_numbers(_t(sum(VALS)), VALS).verified      # full-sum is a derivation target


def test_tb1_catches_subtotal_contrast():
    sub = formula_wrong_value("subtotal_instead_of_total", VALS)
    assert nv.verify_numbers(_t(sub), VALS).verified is False   # unbindable -> TB.1 already catches


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
