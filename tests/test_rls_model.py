# -*- coding: utf-8 -*-
"""Offline tests for the cross-system generality plane (§5.5 / RQ9) — PostgreSQL RLS.

No Docker, no Postgres, no Odoo. Two kinds of check:

  (1) CALIBRATION against the committed results/rls.csv — the live `make rls` probe regenerates
      this file byte-for-byte; here we assert the verdict invariants it must satisfy, including the
      in-band POSITIVE CONTROL (parent count < total) that proves RLS actually fired as the
      unprivileged `app_user` and not as a bypassing superuser. This is the load-bearing assertion:
      without it a vacuous run (superuser bypass) would look identical to a real one.

  (2) STATIC SAFETY-TOKEN LINT of tools/rls_demo.sql — the single source of truth — so CI catches
      drift in the SQL (the role losing NOSUPERUSER/NOBYPASSRLS, the parent losing FORCE, the child
      policy starting to read the oracle column, etc.) WITHOUT needing the engine.

We deliberately do NOT re-implement RLS in Python (that would test our model of Postgres, not
Postgres). Mirrors tests/test_endemic.py (calibration-against-committed-CSV pattern).
"""
import csv
import os
import re

_D = os.path.dirname(__file__)
_CSV = os.path.join(_D, "..", "results", "rls.csv")
_SQL = os.path.join(_D, "..", "tools", "rls_demo.sql")

with open(_CSV, newline="", encoding="utf-8") as _fh:
    _ROWS = list(csv.DictReader(_fh))
with open(_SQL, encoding="utf-8") as _fh:
    _SQL_TEXT = _fh.read()
_SQL_CODE = re.sub(r"--[^\n]*", "", _SQL_TEXT)          # executable SQL only (strip `-- ` line comments)


def _row(variant, probe):
    """The single CSV row for a (variant, probe) pair (asserts uniqueness)."""
    hits = [r for r in _ROWS if r["variant"] == variant and r["probe"] == probe]
    assert len(hits) == 1, f"expected exactly one {variant}/{probe} row, got {len(hits)}"
    return hits[0]


def _policy_body(name):
    """Extract the USING(...) text of `CREATE POLICY <name> ... ;` from the SQL."""
    m = re.search(r"CREATE POLICY\s+" + re.escape(name) + r"\b(.*?);", _SQL_TEXT, re.S | re.I)
    assert m, f"policy {name} not found in rls_demo.sql"
    return m.group(1)


# ── (1) calibration: verdict invariants on the committed CSV ─────────────────
def test_schema_and_role_are_unprivileged():
    # exactly the 4 documented probes, every one run as the NON-superuser app_user.
    assert len(_ROWS) == 4
    assert {(r["variant"], r["probe"]) for r in _ROWS} == {
        ("v-native", "parent-control"), ("v-native", "child-direct"),
        ("v-pushdown", "parent-control"), ("v-pushdown", "child-direct")}
    assert all(r["role"] == "app_user" for r in _ROWS)        # never the bypassing superuser `odoo`


def test_positive_control_proves_rls_fired():
    # THE load-bearing check: the parent policy filtered app_user to its own 3 of 6 orders.
    # If RLS had been bypassed (wrong role), this would be 6 -> CONTROL-FAIL and the run is invalid.
    for variant in ("v-native", "v-pushdown"):
        ctl = _row(variant, "parent-control")
        assert ctl["verdict"] == "CONTROL-OK"
        assert int(ctl["row_count"]) < 6 and int(ctl["row_count"]) == 3


def test_v_native_child_direct_leaks():
    # ungoverned child relation, queried directly -> all 12 lines visible, 6 belong to the other tenant.
    leak = _row("v-native", "child-direct")
    assert int(leak["row_count"]) == 12
    assert int(leak["cross_tenant_rows"]) == 6
    assert leak["verdict"] == "LEAK"


def test_v_pushdown_child_direct_safe():
    # forced parent-predicate pushdown closes it -> only the tenant's own 6 lines, 0 cross-tenant.
    fix = _row("v-pushdown", "child-direct")
    assert int(fix["row_count"]) == 6
    assert int(fix["cross_tenant_rows"]) == 0
    assert fix["verdict"] == "SAFE"


def test_fix_strictly_improves_over_native():
    native = _row("v-native", "child-direct")
    fixed = _row("v-pushdown", "child-direct")
    assert int(fixed["cross_tenant_rows"]) < int(native["cross_tenant_rows"])   # 0 < 6
    assert int(fixed["row_count"]) < int(native["row_count"])                   # 6 < 12 (no over-broad read)


# ── (2) static safety-token lint of the single-source-of-truth SQL ───────────
def test_sql_probe_role_cannot_bypass_rls():
    # the #1 trap: the demonstrating role must be NOSUPERUSER and NOBYPASSRLS, or RLS never fires.
    assert re.search(r"CREATE ROLE\s+app_user\s+NOSUPERUSER\s+NOBYPASSRLS", _SQL_TEXT, re.I)


def test_sql_parent_is_force_enabled_and_context_scoped():
    assert "FORCE  ROW LEVEL SECURITY" in _SQL_TEXT or "FORCE ROW LEVEL SECURITY" in _SQL_TEXT
    assert "current_setting('app.tenant'" in _SQL_TEXT           # session-scoped tenant, fail-closed
    assert "tenant = current_setting" in _policy_body("orders_tenant")


def test_sql_child_governed_only_in_pushdown():
    # native = the realistic misconfiguration: NO policy on the child. pushdown adds exactly one.
    child_policies = re.findall(r"CREATE POLICY\s+\w+\s+ON\s+order_lines\b", _SQL_TEXT, re.I)
    assert child_policies == ["CREATE POLICY order_lines_pushdown ON order_lines"] or \
           len(child_policies) == 1                              # exactly one child policy, the pushdown
    assert "order_lines_pushdown" in _SQL_TEXT


def test_sql_child_policy_oracle_is_noncircular():
    # the pushdown policy must key on the PARENT's tenant via the FK, and must NEVER read the
    # child's oracle column (order_lines.tenant) — else the leak measurement would be circular.
    body = _policy_body("order_lines_pushdown")
    assert "o.tenant" in body and "order_lines.order_id" in body
    assert "order_lines.tenant" not in body
    assert "order_lines.tenant" not in _SQL_CODE                 # oracle column never read qualified in any statement


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} RLS cross-system tests passed.")
