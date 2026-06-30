# -*- coding: utf-8 -*-
"""Offline tests for real-Odoo-schema enforcement (§5.6 / read plane). No Docker, no Odoo, no network.

Two kinds of check (mirrors tests/test_rls_model.py):

  (1) CALIBRATION against the committed results/real_sale.csv — the live `make real-sale` driver regenerates it
      byte-for-byte. We assert the verdict invariants, including the in-band POSITIVE CONTROL (the restricted
      user sees only its own 3 of 6 orders on the GOVERNED parent) — the load-bearing anti-vacuity check: without
      it, a privileged/bypassing run would look identical to a real one. Plus the gap→fix strict improvement on
      the REAL sale.order.line.

  (2) STATIC SAFETY-TOKEN LINT of tools/real_schema.py — the single source of truth — so CI catches drift that
      would make the demo vacuous: the local policy must keep team/company OFF (else the empty-team early-return
      forges a guarded 0), the probe user must not be admin, the oracle must fetch only `id`, and the guard must
      be invoked via the additive `policy=` kwarg (global POLICY untouched).
"""
import csv
import os
import re

_D = os.path.dirname(__file__)
_CSV = os.path.join(_D, "..", "results", "real_sale.csv")
_DRV = os.path.join(_D, "..", "tools", "real_schema.py")

with open(_CSV, newline="", encoding="utf-8") as _fh:
    _ROWS = list(csv.DictReader(_fh))
with open(_DRV, encoding="utf-8") as _fh:
    _SRC = _fh.read()


def _row(variant, probe):
    hits = [r for r in _ROWS if r["variant"] == variant and r["probe"] == probe]
    assert len(hits) == 1, f"expected exactly one {variant}/{probe} row, got {len(hits)}"
    return hits[0]


# ── (1) calibration: verdict invariants on the committed CSV ─────────────────
def test_three_probes_present():
    assert len(_ROWS) == 3
    assert {(r["variant"], r["probe"]) for r in _ROWS} == {
        ("v-native", "parent-control"), ("v-native", "child-direct"), ("v-pep", "child-direct")}
    assert all(r["role"] == "salesperson" and r["own_only"] == "yes" for r in _ROWS)


def test_positive_control_proves_rule_binds():
    # THE load-bearing check: the restricted user sees only its own 3 of 6 orders on the governed parent.
    # If it were 6, the run was privileged/bypassing → CONTROL-FAIL → invalid.
    ctl = _row("v-native", "parent-control")
    assert ctl["verdict"] == "CONTROL-OK"
    assert int(ctl["row_count"]) == 3 and int(ctl["cross_owner_rows"]) == 0


def test_real_child_leaks_undefended():
    # ungoverned child relation on REAL sale.order.line → all 12 lines, 6 belong to the other salesperson.
    leak = _row("v-native", "child-direct")
    assert int(leak["row_count"]) == 12 and int(leak["cross_owner_rows"]) == 6
    assert leak["verdict"] == "LEAK"


def test_pep_closes_real_gap():
    fix = _row("v-pep", "child-direct")
    assert int(fix["row_count"]) == 6 and int(fix["cross_owner_rows"]) == 0
    assert fix["verdict"] == "SAFE"


def test_fix_strictly_improves():
    native = _row("v-native", "child-direct")
    fixed = _row("v-pep", "child-direct")
    assert int(fixed["cross_owner_rows"]) < int(native["cross_owner_rows"])   # 0 < 6
    assert int(fixed["row_count"]) < int(native["row_count"])                 # 6 < 12 (no over-broad read)


# ── (2) static safety-token lint of the single-source-of-truth driver ────────
def test_local_policy_team_company_off():
    # the #1 vacuity trap: a team_path with a restricted non-team user forces [('id','=',0)] (empty set),
    # forging a guarded 0 for the wrong reason. The local policy MUST keep team/company None (owner axis only).
    m = re.search(r"LOCAL_POLICY\s*=\s*\{.*?\n\}", _SRC, re.S)
    assert m, "LOCAL_POLICY block not found"
    block = m.group(0)
    assert '"owner_path": "user_id"' in block and '"owner_path": "order_id.user_id"' in block
    assert '"team_path": None' in block and '"company_path": None' in block
    assert "team_code" not in block and "team_id" not in block


def test_probe_user_is_not_admin():
    # the RLS-superuser trap: the probe user must be asserted non-admin in the driver.
    assert "base.group_system" in _SRC and "base.group_erp_manager" in _SRC
    assert "sales_team.group_sale_salesman" not in _SRC   # must NOT inherit the shipped own/all child rules
    assert "SUPERUSER" not in _SRC.upper() or "must NOT be admin" in _SRC


def test_oracle_fetches_only_id_and_uses_policy_kwarg():
    # leak oracle must read only `id` (never a masked field) and the guard must be called via the additive
    # `policy=` kwarg (so the global POLICY is untouched — protects the exact-equality asserts elsewhere).
    assert 'guarded_search_read("sale.order.line", [], ["id"], policy=LOCAL_POLICY)' in _SRC
    assert '_authz_domain("sale.order.line", LOCAL_POLICY)' in _SRC
    assert "read_group" not in _SRC and "groupby" not in _SRC   # counts only → no group-order nondeterminism


def test_counts_only_no_identifiers_written():
    # byte-stability: the emitted CSV header carries only counts/verdicts, never ids/names/dates/amounts.
    assert '["variant", "probe", "role", "own_only", "row_count", "cross_owner_rows", "verdict"]' in _SRC
    for forbidden in ("date_order", "create_date", "amount_total", "access_token"):
        assert forbidden not in _SRC


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} real-schema tests passed.")
