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
_WCSV = os.path.join(_D, "..", "results", "real_sale_write.csv")
_MCSV = os.path.join(_D, "..", "results", "real_sale_write_matrix.csv")
_DRV = os.path.join(_D, "..", "tools", "real_schema.py")

with open(_CSV, newline="", encoding="utf-8") as _fh:
    _ROWS = list(csv.DictReader(_fh))
with open(_WCSV, newline="", encoding="utf-8") as _fh:
    _WROWS = list(csv.DictReader(_fh))
with open(_MCSV, newline="", encoding="utf-8") as _fh:
    _MROWS = list(csv.DictReader(_fh))
with open(_DRV, encoding="utf-8") as _fh:
    _SRC = _fh.read()


def _mrow(axis, state, op):
    hits = [r for r in _MROWS if r["axis"] == axis and r["state"] == state and r["op"] == op]
    assert len(hits) == 1, f"expected one matrix row {axis}/{state}/{op}, got {len(hits)}"
    return hits[0]


def _row(variant, probe):
    hits = [r for r in _ROWS if r["variant"] == variant and r["probe"] == probe]
    assert len(hits) == 1, f"expected exactly one {variant}/{probe} row, got {len(hits)}"
    return hits[0]


def _wrow(attack):
    hits = [r for r in _WROWS if r["attack"] == attack]
    assert len(hits) == 1, f"expected exactly one write-attack row {attack}, got {len(hits)}"
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


# ── (1b) write plane (§5.6 extension): confused-deputy create/write/unlink on real sale.order.line ──
def test_write_three_structural_attacks_breach_and_held():
    # The 3 STRUCTURAL confused-deputy writes (unlink/create/reassign) breach native governance undefended,
    # and the PEP write-check (USING + WITH-CHECK) holds every one — the load-bearing write-plane claim.
    for aid in ("unlink-foreign-child", "create-foreign-parent", "cross-owner-reassignment"):
        r = _wrow(aid)
        assert r["undefended"] == "breach", f"{aid}: expected undefended breach (non-vacuity)"
        assert r["pg_agent"] == "denied" and r["outcome"] == "held", f"{aid}: PEP must hold"


def test_write_foreign_field_overwrite_is_natively_blocked():
    # HONEST finding: a foreign FIELD-overwrite is incidentally blocked by Odoo's parent-read coupling (writing a
    # line whose parent order the restricted user cannot read raises AccessError) — it does NOT breach; the PEP
    # also denies it (defense in depth). This is a finding, not a failure.
    r = _wrow("write-foreign-child")
    assert r["undefended"] == "denied" and r["pg_agent"] == "denied" and r["outcome"] == "n/a-native-block"


def test_write_positive_control_in_scope_own_write_succeeds():
    # anti-vacuity: an IN-SCOPE OWN guarded write MUST succeed — proves the guard is permissive in-scope (not
    # blanket-denying) AND that the per-call LOCAL policy threaded through the WITH-CHECK (else own write denies).
    pc = _wrow("positive-control")
    assert pc["outcome"] == "SUCCESS"


def test_write_csv_shape():
    assert len(_WROWS) == 5
    assert {r["attack"] for r in _WROWS} == {
        "write-foreign-child", "unlink-foreign-child", "create-foreign-parent",
        "cross-owner-reassignment", "positive-control"}
    # no guarded write ever breached (the PEP held the whole plane)
    assert all(r["pg_agent"] != "breach" for r in _WROWS)


# ── (1c) write MATRIX: scope of the confused-deputy gap over {owner,company} × {draft,confirmed,locked} ──
def test_matrix_shape():
    assert len(_MROWS) == 9
    assert {(r["axis"], r["state"], r["op"]) for r in _MROWS} == {
        ("owner", "draft", "create"), ("owner", "confirmed", "create"), ("owner", "locked", "create"),
        ("owner", "confirmed", "unlink"), ("owner", "confirmed", "write"),
        ("company", "draft", "create"), ("company", "draft", "write"), ("company", "draft", "unlink"),
        ("-", "-", "positive-control")}


def test_matrix_pep_holds_every_breach_and_never_breaches():
    # the security invariant across the whole matrix: the guard NEVER breaches, and every cell that breaches
    # undefended is HELD by the PEP write-check.
    for r in _MROWS:
        assert r["pg_agent"] != "breach", f"{r['axis']}/{r['state']}/{r['op']}: guarded breach"
        if r["undefended"] == "breach":
            assert r["outcome"] == "held", f"{r['axis']}/{r['state']}/{r['op']}: breach not held"
    assert any(r["undefended"] == "breach" for r in _MROWS), "matrix vacuous: no genuine breach"


def test_matrix_gap_is_owner_draft_create_only():
    # the scope characterization: the ONLY genuine confused-deputy write breach in the matrix is owner/draft/create;
    # confirming/locking the parent (message_post coupling) and the company axis (multi-company rule) close the rest.
    breaches = {(r["axis"], r["state"], r["op"]) for r in _MROWS if r["undefended"] == "breach"}
    assert breaches == {("owner", "draft", "create")}, f"unexpected breach scope: {breaches}"
    assert _mrow("owner", "confirmed", "create")["outcome"] == "native-block:confirmed-msg_post"
    assert _mrow("owner", "confirmed", "unlink")["outcome"] == "native-block:_unlink_except_confirmed"
    assert _mrow("company", "draft", "create")["outcome"] == "native-block:multi-company-rule"
    assert _mrow("-", "-", "positive-control")["outcome"] == "SUCCESS"


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
    # byte-stability: the emitted CSV headers carry only counts/verdicts, never ids/names/dates/amounts.
    assert '["variant", "probe", "role", "own_only", "row_count", "cross_owner_rows", "verdict"]' in _SRC
    assert '["attack", "op", "undefended", "pg_agent", "outcome"]' in _SRC   # write-plane header (counts/verdicts)
    # the exact-header asserts above already pin the columns; this guards against an accidental id/timestamp value.
    code = re.sub(r"#[^\n]*", "", _SRC)   # strip line comments
    for forbidden in ("date_order", "create_date", "access_token"):
        assert forbidden not in code


def test_write_driver_uses_policy_kwarg_and_isolation():
    # every guarded WRITE call must pass the per-call LOCAL policy (else the WITH-CHECK falls back to the global
    # POLICY → vacuous deny); the right-reason owner-leaf assertion must be present.
    for call in ("guarded_write(_SOL,", "guarded_unlink(_SOL,", "guarded_create(_SOL,"):
        assert call in _SRC, f"missing guarded write call {call}"
    assert _SRC.count("policy=LOCAL_POLICY") >= 5            # 3 attacks + reassign + positive control
    assert 'guard._authz_domain(_SOL, LOCAL_POLICY)' in _SRC  # right-reason guard (catches a missed thread)
    # savepoint isolation + the load-bearing env.clear() (not invalidate_all) + residue snapshot
    assert "SAVEPOINT" in _SRC and 'getattr(env, name, None)' in _SRC and '"clear"' in _SRC
    assert "residue" in _SRC and "_safe_mutate" in _SRC


def test_write_driver_crud_acl_on_line_only_not_header():
    # the ACL-vacuity fix: the bespoke role gets full CRUD on the LINE (so undefended writes fire) but the header
    # stays read-only (the gap is the missing line RULE, not the ACL). The probe user is NOT in a sales_team group.
    assert '"sale.order": (True, False, False, False)' in _SRC      # header read-only
    assert '"sale.order.line": (True, True, True, True)' in _SRC    # line full CRUD


def test_matrix_driver_isolation_and_company_user():
    # confirm/lock must be in-savepoint with a state-propagation flush+assert; the company axis must use a DISTINCT
    # company-scoped user (allowed_company_ids) + a DISTINCT partner so the §5.6 frozen CSVs stay byte-identical; the
    # residue snapshot must assert state/lock fully rolled back.
    assert 'flush_recordset(["state"])' in _SRC and 'ln.state == "sale"' in _SRC   # propagation check
    assert "allowed_company_ids" in _SRC and "RS-Partner-B" in _SRC                # company isolation, distinct partner
    assert '("state", "=", "sale")' in _SRC and '("locked", "=", True)' in _SRC    # residue: state/lock rolled back
    assert "_unlink_except_confirmed" in _SRC                                       # the native-block reason labels
    # the misattributed owner×locked×write cell was DROPPED (locked guard never runs for a foreign line)
    assert '("owner", "locked", "write"' not in _SRC


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} real-schema tests passed.")
