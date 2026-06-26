# -*- coding: utf-8 -*-
"""Offline tests for the PCC-ERP pushdown SOUNDNESS THEOREM (no Odoo, no LLM).

These tests are the theorem's regression armor: the proof-by-cases (boolean structure is irrelevant to
soundness; hierarchical/subquery ops + `=?` are withheld), the archived-parent COUNTEREXAMPLE (which must be
unsound without P-ACTIVE-CLEAN), the rewrite's structure preservation + byte-for-byte single-leaf composition
with the committed emit, and the CALIBRATION ANCHOR re-classifying the committed CE reasons to 3/5 sound.
Mirrors tests/test_policy_emit.py.
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
import pushdown_soundness as ps                          # noqa: E402

_EMIT_CSV = os.path.join(_D, "..", "results", "scale", "emit.csv")


# ── proof-by-cases: boolean structure is IRRELEVANT to soundness ─────────────
def test_boolean_structure_is_sound():
    for d in (
        "[('company_id','in',company_ids)]",                                   # single simple leaf
        "['|',('user_id','=',user.id),('company_id','in',company_ids)]",       # OR over different fields
        "['!',('state','=','draft')]",                                         # NOT
        "['&','|',('a','=',1),('b','in',x),('c','!=',2)]",                      # nested &/|/multi-field
        "[('amount','>',100),('date','<=','2026-01-01')]",                     # range value-comparisons
        "[('name','ilike','x')]",                                              # like family
    ):
        ok, why = ps.pushdown_sound(d)
        assert ok, (d, why)


# ── proof-by-cases: hierarchical / subquery / =? are WITHHELD (manual-review) ─
def test_excluded_operators_are_withheld():
    for d, op in (
        ("[('id','child_of',company_ids)]", "child_of"),
        ("[('parent_id','parent_of',x)]", "parent_of"),
        ("[('line_ids','any',[('x','=',1)])]", "any"),
        ("[('line_ids','not any',[('x','=',1)])]", "not any"),
        ("[('company_id','=?',cid)]", "=?"),
    ):
        ok, why = ps.pushdown_sound(d)
        assert not ok and op in why, (d, why)
    # a sound leaf mixed with ONE excluded op -> the whole rule is withheld
    ok, why = ps.pushdown_sound("['|',('company_id','in',cids),('id','child_of',x)]")
    assert not ok and "child_of" in why


def test_not_in_and_not_like_stay_sound():
    # `not in` / `not like` are value-comparisons (NOT the subquery `not any`) -> sound
    for d in ("[('state','not in',['draft','cancel'])]", "[('ref','not like','TMP%')]"):
        assert ps.pushdown_sound(d)[0] is True, d


# ── the archived-parent COUNTEREXAMPLE: unsound without P-ACTIVE-CLEAN ────────
def test_archived_parent_counterexample():
    d = "[('company_id','in',company_ids)]"             # value-comparison, would be sound...
    assert ps.pushdown_sound(d)[0] is True              # ...by ops alone
    # ...but if the parent is active-bearing and the emit does NOT re-impose active, it is UNSOUND
    ok, why = ps.pushdown_sound(d, parent_active_sensitive=True)
    assert not ok and why == "active-sensitive"
    # the emit closes it by re-imposing r.active=True (an explicit value-comparison leaf)
    emitted = ps.pushdown(d, "order_id", parent_has_active=True)
    assert "('order_id.active', '=', True)" in emitted and "order_id.company_id" in emitted


# ── rewrite: structure preserved + byte-for-byte composition with the emit ───
def test_pushdown_rewrites_paths_preserves_boolean_tokens():
    out = ps.pushdown("['|',('user_id','=',user.id),('company_id','in',company_ids)]", "order_id")
    assert out == "['|', ('order_id.user_id', '=', user.id), ('order_id.company_id', 'in', company_ids)]"


def test_single_leaf_pushdown_matches_committed_emit():
    # the one already-emitted CE rule: pushdown must reproduce it byte-for-byte (composition anchor)
    out = ps.pushdown("[('company_id','in',company_ids)]", "storage_category_id")
    assert out == "[('storage_category_id.company_id', 'in', company_ids)]"


def test_pushdown_refuses_unsound():
    try:
        ps.pushdown("[('id','child_of',x)]", "order_id")
    except ValueError as e:
        assert "child_of" in str(e)
    else:
        raise AssertionError("pushdown must refuse an unsound domain")


# ── CALIBRATION ANCHOR: re-classify the committed CE reasons -> 3/5 sound ─────
def test_reclassify_ce_reasons_3_of_5():
    import csv
    rows = list(csv.DictReader(open(_EMIT_CSV, encoding="utf-8")))
    verdicts = {r["model"]: ps.reclassify(r["parent_reason"])[0] for r in rows}
    sound = sorted(m for m, v in verdicts.items() if v)
    manual = sorted(m for m, v in verdicts.items() if not v)
    assert len(sound) == 3 and len(manual) == 2, (sound, manual)
    # the 2 withheld are exactly the parent_of pair (the genuine frontier)
    assert manual == ["account.fiscal.position.account", "account.payment.term.line"]
    assert "sale.order.line" in sound and "account.bank.statement.line" in sound


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} pushdown-soundness (theorem) tests passed.")
