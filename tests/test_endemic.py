# -*- coding: utf-8 -*-
"""Offline tests for the endemic-gap aggregator (no Odoo, no LLM).

Covers data/erp_authzbench/endemic.endemic_summary (breadth + per-domain distribution + pooled rate)
and diff_baseline (verdict-drift detection). The CALIBRATION ANCHOR reads the committed 3-module
coverage.csv and asserts the known baseline (breadth 3/3, pooled 5/10, per-domain 3/6 / 1/3 / 1/1) so a
scaling regression is caught. Mirrors tests/test_policy_scan.py.
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
import endemic                                          # noqa: E402

_COVERAGE = os.path.join(_D, "..", "results", "scale", "coverage.csv")


def _rec(model, disc, hops, parent_gov, verdict, native=False, path="", definer=""):
    return {"model": model, "discriminator": disc, "hops": hops, "parent_governed": parent_gov,
            "verdict": verdict, "native_rule": native, "relation_path": path, "definer_model": definer}


# A synthetic 3-domain corpus: A has a gap (+1 governed at-risk), B is at-risk-but-fully-governed
# (scanned, no gap), C has a gap; plus hops-0 / parent-ungoverned noise that must NOT count as at-risk.
FIXTURE = [
    _rec("a.order.line", "company_id", 1, True, "GAP", path="order_id.company_id", definer="a.order"),
    _rec("a.order.line", "user_id", 1, True, "GOVERNED", native=True, path="order_id.user_id", definer="a.order"),
    _rec("a.order", "company_id", 0, True, "GOVERNED", native=True),
    _rec("b.move.line", "company_id", 1, True, "GOVERNED", native=True, path="move_id.company_id", definer="b.move"),
    _rec("c.cap", "company_id", 1, True, "GAP", path="cat_id.company_id", definer="c.cat"),
    _rec("c.thing", "partner_id", 0, False, "PARENT-UNGOVERNED"),
    _rec("a.report", "partner_id", 0, False, "PARENT-UNGOVERNED"),
]


# ── endemic_summary: breadth + distribution + pooled ─────────────────────────
def test_breadth_distinguishes_at_risk_from_has_gap():
    s = endemic.endemic_summary(FIXTURE)
    assert s["n_domains_with_at_risk"] == 3            # a, b, c all contain an at-risk child
    assert s["n_domains_with_gap"] == 2                # only a, c have a gap (b is fully governed)
    assert s["domains_with_gap"] == ["a", "c"]


def test_per_domain_and_pooled():
    s = endemic.endemic_summary(FIXTURE)
    assert s["per_domain"]["a"] == {"at_risk": 2, "gaps": 1, "rate": 0.5}
    assert s["per_domain"]["b"] == {"at_risk": 1, "gaps": 0, "rate": 0.0}
    assert s["per_domain"]["c"] == {"at_risk": 1, "gaps": 1, "rate": 1.0}
    assert (s["gaps_total"], s["at_risk_total"], s["pooled_gap_rate"]) == (2, 4, 0.5)


def test_noise_rows_excluded_from_at_risk():
    # hops-0 and parent-ungoverned rows never enter the at-risk denominator
    only_noise = [_rec("x.y", "partner_id", 0, False, "PARENT-UNGOVERNED"),
                  _rec("x.z", "company_id", 0, True, "GOVERNED", native=True)]
    s = endemic.endemic_summary(only_noise)
    assert s["at_risk_total"] == 0 and s["n_domains_with_gap"] == 0


# ── diff_baseline: drift detection + causes ──────────────────────────────────
def test_drift_new_native_rule():
    base = [_rec("a.order.line", "company_id", 1, True, "GAP", path="order_id.company_id", definer="a.order")]
    cur = [_rec("a.order.line", "company_id", 1, True, "GOVERNED", native=True,
                path="order_id.company_id", definer="a.order")]
    drift = endemic.diff_baseline(cur, base)
    assert len(drift) == 1 and "new-native-rule" in drift[0]["cause"]


def test_drift_rerouted_definer():
    base = [_rec("a.order.line", "company_id", 1, True, "GAP", path="order_id.company_id", definer="a.order")]
    cur = [_rec("a.order.line", "company_id", 1, True, "GAP", path="p2_id.company_id", definer="a.p2")]
    drift = endemic.diff_baseline(cur, base)
    assert len(drift) == 1 and "re-routed" in drift[0]["cause"]


def test_no_drift_when_identical():
    base = [_rec("a.order.line", "company_id", 1, True, "GAP", path="order_id.company_id", definer="a.order")]
    assert endemic.diff_baseline(list(base), base) == []


# ── calibration anchor: the committed 3-module baseline must reproduce exactly ─
def test_calibration_against_committed_coverage():
    s = endemic.endemic_summary(endemic.read_coverage_csv(_COVERAGE))
    assert s["n_domains_scanned"] == 3
    assert s["n_domains_with_at_risk"] == 3 and s["n_domains_with_gap"] == 3
    assert (s["gaps_total"], s["at_risk_total"], s["pooled_gap_rate"]) == (5, 10, 0.5)
    assert s["per_domain"]["account"] == {"at_risk": 6, "gaps": 3, "rate": 0.5}
    assert s["per_domain"]["sale"] == {"at_risk": 3, "gaps": 1, "rate": 0.333}
    assert s["per_domain"]["stock"] == {"at_risk": 1, "gaps": 1, "rate": 1.0}


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} endemic-aggregator tests passed.")
