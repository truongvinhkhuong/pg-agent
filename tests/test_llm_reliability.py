# -*- coding: utf-8 -*-
"""Offline tests for the real-LLM reliability & residual run (§10.1.3). No Odoo, no LLM, no Docker.

Two kinds of check (mirrors tests/test_llm_stats.py):

  (1) UNIT: the pure `spread(xs)` helper (mean ± range) at known points.

  (2) CALIBRATION: recompute the summary (results/llm/reliability.csv) purely from the committed per-row long
      table (results/llm/reliability_rows.csv) and assert it reproduces the summary cell-for-cell — pinning
      reliability.csv as a deterministic function of the rows, auditable WITHOUT re-running the model. Also
      re-asserts the only HARD security invariant offline: guarded_leak == 0 across every variance row.

We do NOT import evaluation_script (it pulls Odoo); the aggregation is replicated from llm_stats so the test is
an independent recomputation.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data", "erp_authzbench"))
import llm_stats as st  # noqa: E402

_D = os.path.dirname(__file__)
_SUM = os.path.join(_D, "..", "results", "llm", "reliability.csv")
_ROWS = os.path.join(_D, "..", "results", "llm", "reliability_rows.csv")


# ── (1) unit: spread ─────────────────────────────────────────────────────────
def test_spread_known_points():
    assert st.spread([0.2, 0.4, 0.3]) == (0.3, 0.2, 0.4)
    assert st.spread([0.389, 0.389, 0.389]) == (0.389, 0.389, 0.389)
    assert st.spread([]) == (0.0, 0.0, 0.0)
    assert st.spread([0.5]) == (0.5, 0.5, 0.5)


def _load():
    with open(_SUM, newline="", encoding="utf-8") as fh:
        summ = list(csv.DictReader(fh))
    with open(_ROWS, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return summ, rows


def _by(rows, metric):
    out = {}
    for r in rows:
        if r["metric"] == metric:
            out.setdefault(r["model"], []).append(r)
    return out


def _recompute(rows):
    """Independent re-derivation of reliability.csv from reliability_rows.csv -> {(metric, model): dict}."""
    exp = {}
    for model, rs in _by(rows, "variance").items():
        asrs = [float(r["asr"]) for r in rs]
        mean, lo, hi = st.spread(asrs)
        exp[("variance", model)] = {"n": len(rs), "asr_mean": mean, "asr_lo": lo, "asr_hi": hi,
                                    "guarded_leak": sum(int(r["guarded_leak"]) for r in rs)}
    for model, rs in _by(rows, "integrity").items():
        n = len(rs)
        wrong = sum(int(r["wrong"]) for r in rs)
        caught = sum(int(r["verifier_caught"]) for r in rs)
        exp[("integrity", model)] = {"n": n, "wrong": wrong, "no_answer": sum(int(r["no_answer"]) for r in rs),
                                     "wrong_rate": st.asr(wrong, n), "verifier_caught": caught,
                                     "verifier_catch_rate": st.asr(caught, wrong) if wrong else 0.0}
    for model, rs in _by(rows, "answer_channel").items():
        n = len(rs)
        miss = sum(int(r["validator_miss"]) for r in rs)
        exp[("answer_channel", model)] = {"n": n, "present": sum(int(r["present"]) for r in rs),
                                          "validator_miss": miss, "resist": sum(int(r["resist"]) for r in rs),
                                          "validator_miss_rate": st.asr(miss, n)}
    return exp


def test_summary_reproduced_from_rows():
    summ, rows = _load()
    exp = _recompute(rows)
    stored = {(r["metric"], r["model"]): r for r in summ}
    assert set(stored) == set(exp), f"(metric,model) set mismatch: {set(stored) ^ set(exp)}"
    for key, e in exp.items():
        got = stored[key]
        for col, val in e.items():
            cell = got[col]
            if isinstance(val, float):
                assert float(cell) == val, f"{key}.{col}: stored {cell} != recomputed {val}"
            else:
                assert int(cell) == val, f"{key}.{col}: stored {cell} != recomputed {val}"


def test_guard_invariant_and_shape():
    summ, rows = _load()
    # the ONLY hard security invariant: no guarded leak across variance rows (mirrors llm_eval / reliability_eval).
    for r in rows:
        if r["metric"] == "variance":
            assert int(r["guarded_leak"]) == 0, f"variance guarded leak {r['model']}/{r['id']}"
    metrics = {r["metric"] for r in summ}
    assert metrics == {"variance", "integrity", "answer_channel"}
    # answer-channel residual is measured by TRUE PRESENCE, never the validator's own verdict (non-circular):
    # validator_miss <= present for every answer_channel row.
    for r in [x for x in rows if x["metric"] == "answer_channel"]:
        assert int(r["validator_miss"]) <= int(r["present"])


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} llm-reliability tests passed.")
